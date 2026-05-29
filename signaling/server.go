package connect

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	_AuthMessageSize   = 8 + ed25519.SignatureSize // 8-byte timestamp + 64-byte signature
	_MaxBodySize       = 4 << 10                   // 4 KiB
	_InvalidCharacters = "\n\r"

	// SSE frame layout: "data: " <body> "\n\n"
	// The prefix is pre-filled in the pool New func so it is never copied at runtime.
	_SSEPrefixLen = 6 // len("data: ")
	_SSESuffixLen = 2 // len("\n\n")
	_FrameSize    = _SSEPrefixLen + _MaxBodySize + _SSESuffixLen
)

var (
	// sseAuthDomain is the domain separation tag for SSE subscription signatures.
	// Must match the tag used by all client implementations.
	sseAuthDomain = []byte("connect.sse.v1\x00")

	// Auth pools — eliminate per-request heap allocations on the SSE connect path.

	// pubkeyDecodePool holds 32-byte buffers for base64-decoding ed25519 public keys.
	// Callers must not retain a reference after returning the buffer to the pool.
	pubkeyDecodePool = sync.Pool{New: func() any { b := make([]byte, ed25519.PublicKeySize); return &b }}

	// authDecodePool holds _AuthMessageSize-byte buffers for base64-decoding the
	// sig query parameter (sig[64] || ts[8]).
	authDecodePool = sync.Pool{New: func() any { b := make([]byte, _AuthMessageSize); return &b }}

	// authMsgPool holds the ed25519 message buffer pre-filled with sseAuthDomain.
	// Only the trailing 8 timestamp bytes are overwritten per request.
	authMsgPool = sync.Pool{New: func() any {
		b := make([]byte, len(sseAuthDomain)+8)
		copy(b, sseAuthDomain)
		return &b
	}}

	ssePrefix    = []byte("data: ")
	sseSuffix    = []byte("\n\n")
	sseKeepalive = []byte(": ka\n\n")

	// corsOriginAny is pre-allocated to avoid a []string alloc on every POST response.
	// Safe to share: net/http reads header values but never mutates them after WriteHeader.
	corsOriginAny = []string{"*"}

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
	hub       *hub
	peers     PeerFinder
	nodeURL   string
	framePool sync.Pool
}

func NewServer(ctx context.Context, cfg Config) *server {
	return &server{
		hub:     newHub(ctx),
		peers:   cfg.PeerFinder,
		nodeURL: cfg.NodeURL,
		framePool: sync.Pool{
			New: func() any {
				b := make([]byte, _FrameSize)
				copy(b, ssePrefix) // pre-fill prefix — valid for pool lifetime
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
	if r.Method == http.MethodOptions {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST")
		h.Set("Access-Control-Allow-Headers", "Content-Type")
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
		// POST responses require Access-Control-Allow-Origin for cross-origin clients.
		// Allow-Methods and Allow-Headers are only checked by browsers on OPTIONS preflight.
		w.Header()["Access-Control-Allow-Origin"] = corsOriginAny
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

// decodePubKeyInto decodes a base64url-encoded ed25519 public key into dst.
// dst must be at least ed25519.PublicKeySize bytes. The returned PublicKey
// aliases dst — the caller must not return dst to a pool while the key is live.
func decodePubKeyInto(src, dst []byte) (ed25519.PublicKey, error) {
	n, err := base64.RawURLEncoding.Decode(dst, src)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if n != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, n)
	}
	return ed25519.PublicKey(dst[:n]), nil
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
//
// rawSig is the raw base64url bytes — callers pass the query param or header
// value directly without converting to string, avoiding an allocation.
func verifyAuth(rawSig []byte, pubkey ed25519.PublicKey) error {
	rawp := authDecodePool.Get().(*[]byte)
	n, err := base64.RawURLEncoding.Decode(*rawp, rawSig)
	if err != nil {
		authDecodePool.Put(rawp)
		return errInvalidEncoding
	}
	if n != _AuthMessageSize {
		authDecodePool.Put(rawp)
		return errInvalidSignatureLength
	}

	sig := (*rawp)[:ed25519.SignatureSize]
	tsBytes := (*rawp)[ed25519.SignatureSize:n]
	ts := int64(binary.BigEndian.Uint64(tsBytes))

	delta := time.Now().Unix() - ts
	if delta < -60 || delta > 2 {
		authDecodePool.Put(rawp)
		return fmt.Errorf("timestamp outside window")
	}

	// authMsgPool buffers are pre-filled with sseAuthDomain; only write tsBytes.
	msgp := authMsgPool.Get().(*[]byte)
	copy((*msgp)[len(sseAuthDomain):], tsBytes)
	ok := ed25519.Verify(pubkey, *msgp, sig)
	authMsgPool.Put(msgp)
	authDecodePool.Put(rawp)

	if !ok {
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

	if err := verifyAuth([]byte(sigStr), pubkey); err != nil {
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

	tuneSSEBuffers(nc)

	if _, err := brw.Write(sseResponse); err != nil || brw.Flush() != nil {
		nc.Close()
		return
	}

	s.hub.register(pubkeyStr, nc)
}

// tuneConnBuffers sets SO_RCVBUF and SO_SNDBUF on a connection, unwrapping
// TLS if necessary. Best-effort: errors are silently ignored.
func tuneConnBuffers(nc net.Conn, rcvbuf, sndbuf int) {
	inner := nc
	if tlsConn, ok := nc.(*tls.Conn); ok {
		inner = tlsConn.NetConn()
	}
	tc, ok := inner.(*net.TCPConn)
	if !ok {
		return
	}
	tc.SetReadBuffer(rcvbuf)  //nolint:errcheck
	tc.SetWriteBuffer(sndbuf) //nolint:errcheck
}

// tuneSSEBuffers shrinks buffers on a hijacked SSE connection to the minimum
// viable sizes for a write-only long-lived stream:
//
//   - rcvbuf=1: kernel floors to its minimum (~2304 B); the connection is
//     receive-idle after the handshake so no receive capacity is needed.
//   - sndbuf=_FrameSize: one max SSE frame fits without blocking; the hub
//     writes frames sequentially so no larger buffer is needed.
func tuneSSEBuffers(nc net.Conn) {
	tuneConnBuffers(nc, 1, _FrameSize)
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
	framep := s.framePool.Get().(*[]byte)
	defer s.framePool.Put(framep)

	// Read body directly into the frame buffer after the pre-filled prefix.
	body := (*framep)[_SSEPrefixLen : _SSEPrefixLen+_MaxBodySize]
	n, err := io.ReadFull(r.Body, body)
	if err == io.EOF {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	if err != nil && err != io.ErrUnexpectedEOF {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	if bytes.ContainsAny(body[:n], _InvalidCharacters) {
		http.Error(w, "body must not contain newlines; send base64-encoded data", http.StatusBadRequest)
		return
	}

	// Append suffix and deliver the complete frame in one write.
	copy((*framep)[_SSEPrefixLen+n:], sseSuffix)
	if !s.hub.deliver(targetStr, (*framep)[:_SSEPrefixLen+n+_SSESuffixLen]) {
		http.Error(w, "recipient not connected", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}
