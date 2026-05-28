package connect

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	_AuthMessageSize   = 8 + ed25519.SignatureSize // 8-byte timestamp + 64-byte signature
	_MaxBodySize       = 4 << 10                   // 4 KiB — enough for a base64-encoded 3 KiB payload, which is more than enough for typical signaling messages
	_InvalidCharacters = "\n\r"
)

var (
	// sseAuthDomain is the domain separation tag for SSE subscription signatures.
	// Must match the tag used by all client implementations.
	sseAuthDomain = []byte("connect.sse.v1\x00")

	ssePrefix    = []byte("data: ")
	sseSuffix    = []byte("\n\n")
	sseKeepalive = []byte(": ka\n\n")

	// sseResponse is written to the hijacked connection immediately after auth.
	sseResponse = []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/event-stream\r\n" +
		"Cache-Control: no-cache\r\n" +
		"Connection: keep-alive\r\n" +
		"Access-Control-Allow-Origin: *\r\n" +
		"X-Accel-Buffering: no\r\n" +
		"\r\n")

	errMissingSignature       = errors.New("missing ?sig= query param")
	errInvalidEncoding        = errors.New("invalid encoding")
	errInvalidSignatureLength = errors.New("invalid signature length")
)

// PeerFinder returns the current set of peer node base URLs for pubkey routing.
// Implementations must be safe for concurrent use.
//
// Peers should include this node's own URL. The server uses the sorted list and
// a hash of the pubkey to select the canonical node for each channel; if the
// selected node is not this node, the request is redirected.
type PeerFinder interface {
	Peers() []string
}

// Config holds optional server configuration.
type Config struct {
	// PeerFinder provides the current peer set. If nil or returns an empty
	// slice, all requests are served locally (single-node / dev mode).
	PeerFinder PeerFinder
	// NodeURL is this node's own base URL (e.g. "https://node-abc123.example.com").
	// Must be set for routing to be active; leave empty to serve all requests locally.
	NodeURL string
}

type server struct {
	hub      *hub
	peers    PeerFinder
	nodeURL  string
	bodyPool sync.Pool
}

func NewServer(ctx context.Context, cfg Config) *server {
	return &server{
		hub:     newHub(ctx),
		peers:   cfg.PeerFinder,
		nodeURL: cfg.NodeURL,
		bodyPool: sync.Pool{
			New: func() any {
				b := make([]byte, _MaxBodySize)
				return &b
			},
		},
	}
}

// targetPeer returns the peer URL that should handle pubkey using rendezvous
// (HRW) hashing, or "" if this node is the target or no peers are configured.
//
// For each peer, score = fnv64a(pubkey + "\x00" + peerURL). The peer with the
// highest score wins. This minimises churn on topology changes: adding or
// removing a node only rerouteskeys that were assigned to that node.
func (s *server) targetPeer(pubkeyStr string) string {
	if s.peers == nil || s.nodeURL == "" {
		return ""
	}
	peers := s.peers.Peers()
	if len(peers) == 0 {
		return ""
	}

	h := fnv.New64a()
	var best string
	var bestScore uint64
	for _, peer := range peers {
		h.Reset()
		io.WriteString(h, pubkeyStr)
		h.Write([]byte{0})
		io.WriteString(h, peer)
		if score := h.Sum64(); score > bestScore {
			bestScore = score
			best = peer
		}
	}

	if best == s.nodeURL {
		return ""
	}
	return best
}

// ServeHTTP routes:
//
//	GET  /{pubkey}  — open SSE stream (client proves ownership)
//	POST /{pubkey}  — deliver an opaque payload to that pubkey
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "X-Signature, Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	pubKey := strings.Trim(r.URL.Path, "/")
	if len(pubKey) != 43 {
		http.NotFound(w, r)
		return
	}

	// if target := s.targetPeer(pubkeyStr); target != "" {
	// 	http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	// 	return
	// }

	switch r.Method {
	case http.MethodGet:
		s.listenForMessages(w, r, pubKey)
	case http.MethodPost:
		s.postMessage(w, r, pubKey)
	default:
		http.NotFound(w, r)
	}
}

// decodePubKey parses a base64url (no-padding) encoded ed25519 public key.
func decodePubKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// verifyAuth checks that the request carries a valid ed25519 signature from
// pubkey.
//
// The signature may be provided as:
//   - X-Signature header: base64(sig || ts)
//   - ?sig= query param: same encoding (survives cross-origin redirects where
//     browsers may strip custom headers before forwarding)
//
// sig = ed25519_sign(privkey, sseAuthDomain || ts), ts is an 8-byte
// big-endian uint64 unix timestamp, must be within ±60 s of server time.
func verifyAuth(rawSignature string, pubkey ed25519.PublicKey) error {
	raw, err := base64.RawURLEncoding.DecodeString(rawSignature)
	if err != nil {
		return errInvalidEncoding
	}
	if len(raw) != _AuthMessageSize {
		return errInvalidSignatureLength
	}

	sig := raw[:ed25519.SignatureSize]
	tsBytes := raw[ed25519.SignatureSize:]
	ts := int64(binary.BigEndian.Uint64(tsBytes))

	delta := time.Now().Unix() - ts
	if delta < -60 || delta > 2 {
		return fmt.Errorf("timestamp outside window")
	}

	if !ed25519.Verify(pubkey, append([]byte(sseAuthDomain), tsBytes...), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// --- SSE -----------------------------------------------------------------

// listenForMessages hijacks the connection after auth, writes the SSE response
// headers, registers with the hub, and returns — freeing the handler goroutine.
func (s *server) listenForMessages(w http.ResponseWriter, r *http.Request, pubkeyStr string) {
	pubkey, err := decodePubKey(pubkeyStr)
	if err != nil {
		http.Error(w, "invalid public key", http.StatusBadRequest)
		return
	}

	sigStr := r.URL.Query().Get("sig")
	if sigStr == "" {
		http.Error(w, "missing signature", http.StatusUnauthorized)
		return
	}

	if err := verifyAuth(sigStr, pubkey); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	nc, brw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "failed to acquire connection", http.StatusInternalServerError)
		return
	}

	if _, err := brw.Write(sseResponse); err != nil || brw.Flush() != nil {
		nc.Close()
		return
	}

	s.hub.register(pubkeyStr, nc)
}

// --- Message -------------------------------------------------------------

// postMessage delivers an opaque payload to the target's SSE stream.
// The server is a pure relay — it does not inspect or wrap the body.
// Clients are responsible for encoding their own identity into the payload.
//
//	POST /{target_pubkey}
//	Body: <base64-encoded data, no newlines>
//
// Returns 404 if the target pubkey has no active SSE connection.
func (s *server) postMessage(w http.ResponseWriter, r *http.Request, targetStr string) {
	bufp := s.bodyPool.Get().(*[]byte)
	defer s.bodyPool.Put(bufp)

	n, err := io.ReadFull(r.Body, *bufp)
	if err == io.EOF {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	if err != nil && err != io.ErrUnexpectedEOF {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	body := (*bufp)[:n]

	if bytes.ContainsAny(body, _InvalidCharacters) {
		http.Error(w, "body must not contain newlines; send base64-encoded data", http.StatusBadRequest)
		return
	}

	if !s.hub.deliver(targetStr, body) {
		http.Error(w, "recipient not connected", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}
