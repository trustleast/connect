package connect

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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

	errNodeUnavailable        = errors.New("recipient not connected")
	errInvalidPubKey          = errors.New("invalid public key")
	errMissingSignature       = errors.New("missing ?sig= query param")
	errInvalidEncoding        = errors.New("invalid encoding")
	errInvalidSignatureLength = errors.New("invalid signature length")
)

// PeerFinder returns the current set of peer node base URLs for pubkey routing.
// Implementations must be safe for concurrent use.
//
// Peers should include this node's own URL. The server uses HRW hashing over the
// peer set to select the canonical node for each pubkey; requests for keys not
// owned by this node are redirected to the owner.
type PeerFinder interface {
	// Peers returns the current peer set including this node's own URL.
	Peers() []*url.URL
	// OnChange returns a channel that receives an empty signal whenever the peer
	// set changes. The channel is never closed. Callers should re-read Peers()
	// after receiving a signal. Static implementations allocate the channel but
	// never send on it.
	OnChange() <-chan struct{}

	Secret() [32]byte
}

// Config holds optional server configuration.
type Config struct {
	// PeerFinder provides the current peer set. If nil or returns an empty
	// slice, all requests are served locally (single-node / dev mode).
	PeerFinder PeerFinder
	// NodeURL is this node's own base URL (e.g. "http://localhost:8081").
	// Must be set for routing to be active; leave empty to serve all requests locally.
	NodeURL *url.URL
	// ClusterSecret is the shared HMAC key for HRW scoring. All nodes in the
	// cluster must use the same value. When empty, a zero key is used (dev only).
	ClusterSecret [32]byte
}

type server struct {
	hub       *hub
	cfg       Config
	hashKey   [32]byte
	framePool sync.Pool
	// Auth pools — eliminate per-request heap allocations on the SSE connect path.
	authDecodePool sync.Pool // _AuthMessageSize-byte buffers for base64-decoding ?sig=
	authMsgPool    sync.Pool // ed25519 message buffer pre-filled with sseAuthDomain
}

func NewHTTPServer(ctx context.Context, cfg Config) *http.Server {
	server := newServer(ctx, cfg)
	return &http.Server{
		Handler: server,
		// Disable HTTP/2: ServeTLS enables it automatically via ALPN, but
		// hijacking (required for SSE) is not available on HTTP/2 streams.
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 10, // 1 KiB
	}
}

func newServer(ctx context.Context, cfg Config) *server {
	return &server{
		hub: newHub(ctx, cfg.PeerFinder),
		cfg: cfg,
		framePool: sync.Pool{
			New: func() any {
				b := make([]byte, _FrameSize)
				copy(b, ssePrefix) // pre-fill prefix — valid for pool lifetime
				return &b
			},
		},
		authDecodePool: sync.Pool{
			New: func() any { b := make([]byte, _AuthMessageSize); return &b },
		},
		authMsgPool: sync.Pool{
			New: func() any {
				b := make([]byte, len(sseAuthDomain)+8)
				copy(b, sseAuthDomain)
				return &b
			},
		},
	}

}

// targetPeer returns the parsed URL of the peer that should handle pubkey using
// rendezvous (HRW) hashing, or nil if this node is the target or no peers are
// configured.
//
// For each peer, score = HMAC-SHA256(clusterSecret, pubkey || "\x00" || peerURL)[0:8]
// interpreted as a big-endian uint64. The peer with the highest score wins.
// Using a keyed hash prevents clients from generating pubkeys that target a
// specific node. HRW minimises churn: only keys assigned to an added/removed
// node are reassigned.
func targetPeer(pf PeerFinder, pubkeyStr string) *url.URL {
	peers := pf.Peers()
	if len(peers) == 0 {
		return nil
	}

	secret := pf.Secret()

	best := peers[0]
	var bestScore uint64
	var sum [sha256.Size]byte
	mac := hmac.New(sha256.New, secret[:])
	for _, peer := range peers {
		io.WriteString(mac, pubkeyStr)
		mac.Write([]byte{0})
		io.WriteString(mac, peer.Host)
		mac.Sum(sum[:0])
		mac.Reset()
		if score := binary.BigEndian.Uint64(sum[:8]); score > bestScore {
			bestScore = score
			best = peer
		}
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
		h["Access-Control-Allow-Origin"] = corsOriginAny
		h.Set("Access-Control-Allow-Methods", "GET, POST")
		h.Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	pubKey := strings.Trim(r.URL.Path, "/")
	if len(pubKey) != 43 {
		http.Error(w, errInvalidPubKey.Error(), http.StatusBadRequest)
		return
	}

	// Check if cluster routing is enabled
	if s.cfg.clusterRoutingEnabled() {
		if target := targetPeer(s.cfg.PeerFinder, pubKey); target == nil {
			// Cluster routing enabled but no peers found
			http.Error(w, errNodeUnavailable.Error(), http.StatusServiceUnavailable)
			return
		} else {
			// Another node is the HRW owner. Before redirecting, check whether the
			// request already arrived with the target's hostname — this means the
			// client followed a previous redirect to that node but DNS fell through
			// to us (e.g. CNAME drain). We can't find the good node yet; return 503 so
			// the client backs off until the routing table converges.
			if r.Host == target.Host && r.Host != s.cfg.NodeURL.Host {
				http.Error(w, errNodeUnavailable.Error(), http.StatusServiceUnavailable)
				return
			} else if r.Host != target.Host {
				u := *target
				u.Path = r.URL.Path
				u.RawQuery = r.URL.RawQuery
				http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
				return
			}
		}
	}

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
func (s *server) verifyAuth(rawSig []byte, pubkey ed25519.PublicKey) error {
	rawp := s.authDecodePool.Get().(*[]byte)
	n, err := base64.RawURLEncoding.Decode(*rawp, rawSig)
	if err != nil {
		s.authDecodePool.Put(rawp)
		return errInvalidEncoding
	}
	if n != _AuthMessageSize {
		s.authDecodePool.Put(rawp)
		return errInvalidSignatureLength
	}

	sig := (*rawp)[:ed25519.SignatureSize]
	tsBytes := (*rawp)[ed25519.SignatureSize:n]
	ts := int64(binary.BigEndian.Uint64(tsBytes))

	delta := time.Now().Unix() - ts
	if delta < -60 || delta > 2 {
		s.authDecodePool.Put(rawp)
		return fmt.Errorf("timestamp outside window")
	}

	// authMsgPool buffers are pre-filled with sseAuthDomain; only write tsBytes.
	msgp := s.authMsgPool.Get().(*[]byte)
	copy((*msgp)[len(sseAuthDomain):], tsBytes)
	ok := ed25519.Verify(pubkey, *msgp, sig)
	s.authMsgPool.Put(msgp)
	s.authDecodePool.Put(rawp)

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

	if err := s.verifyAuth([]byte(sigStr), pubkey); err != nil {
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

func (c Config) clusterRoutingEnabled() bool {
	return c.NodeURL != nil && c.PeerFinder != nil
}
