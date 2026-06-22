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
	"hash"
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

	errNodeUnavailable             = errors.New("recipient not connected")
	errInvalidPubKey               = errors.New("invalid public key")
	errMissingSignature            = errors.New("missing ?sig= query param")
	errInvalidEncoding             = errors.New("invalid encoding")
	errInvalidSignatureLength      = errors.New("invalid signature length")
	errTimestampOutsideWindow      = errors.New("timestamp outside window")
	errSignatureVerificationFailed = errors.New("signature verification failed")
)

// PeerFinder returns the current set of peer node base URLs for pubkey routing.
// Implementations must be safe for concurrent use.
//
// Peers should include this node's own URL. The server uses HRW hashing over the
// peer set to select the canonical node for each pubkey; requests for keys not
// owned by this node are redirected to the owner.
type PeerFinder interface {
	// Node returns this node's own base URL.
	Node() *url.URL
	// Peers returns the current peer set including this node's own URL.
	Peers() []*url.URL
	// OnChange returns a channel that receives an empty signal whenever the peer
	// set changes. The channel is never closed. Callers should re-read Peers()
	// after receiving a signal. Static implementations allocate the channel but
	// never send on it.
	OnChange() <-chan struct{}

	Secret() [32]byte
}

type server struct {
	hub *hub
	// PeerFinder provides the current peer set. If nil or returns an empty
	// slice, all requests are served locally (single-node / dev mode).
	peerFinder PeerFinder
	hashKey    [32]byte
	framePool  sync.Pool
	// hmacPool holds pre-keyed HMAC-SHA256 instances for the HRW routing path.
	// Each item is a hash.Hash already keyed with the cluster secret; callers
	// must Reset() after use before returning it to the pool. Populated only
	// when peerFinder != nil.
	hmacPool sync.Pool
	// Auth pools — eliminate per-request heap allocations on the SSE connect path.
	authDecodePool sync.Pool // _AuthMessageSize-byte buffers for base64-decoding ?sig=
	authMsgPool    sync.Pool // ed25519 message buffer pre-filled with sseAuthDomain
}

func NewHTTPServer(ctx context.Context, peerFinder PeerFinder) *http.Server {
	server := newServer(ctx, peerFinder)
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

func newServer(ctx context.Context, peerFinder PeerFinder) *server {
	s := &server{
		hub:        newHub(ctx, peerFinder),
		peerFinder: peerFinder,
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
	if peerFinder != nil {
		secret := peerFinder.Secret()
		s.hmacPool = sync.Pool{
			New: func() any {
				return hmac.New(sha256.New, secret[:])
			},
		}
	}
	return s
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
	return targetPeerWith(peers, pubkeyStr, hmac.New(sha256.New, secret[:]))
}

// targetPeerWith scores peers using the provided pre-keyed hash h and returns
// the HRW winner. h is Reset() after each peer's score so it is in the initial
// keyed state when this function returns — callers that obtained h from a pool
// can return it directly without an additional Reset().
func targetPeerWith(peers []*url.URL, pubkeyStr string, h hash.Hash) *url.URL {
	best := peers[0]
	var bestScore uint64
	var sum [sha256.Size]byte
	for _, peer := range peers {
		io.WriteString(h, pubkeyStr)
		h.Write([]byte{0})
		io.WriteString(h, peer.Host)
		h.Sum(sum[:0])
		h.Reset()
		if score := binary.BigEndian.Uint64(sum[:8]); score > bestScore {
			bestScore = score
			best = peer
		}
	}
	return best
}

// targetPeer is the hot-path method called from ServeHTTP. It uses the server's
// pre-keyed HMAC pool so hmac.New is not called on every request.
func (s *server) targetPeer(pubkeyStr string) *url.URL {
	peers := s.peerFinder.Peers()
	if len(peers) == 0 {
		return nil
	}
	h := s.hmacPool.Get().(hash.Hash)
	result := targetPeerWith(peers, pubkeyStr, h)
	s.hmacPool.Put(h) // targetPeerWith leaves h Reset()-ed; ready for reuse
	return result
}

// ServeHTTP routes:
//
//	GET  /{pubkey}  — open SSE stream (client proves ownership)
//	POST /{pubkey}  — deliver an opaque payload to that pubkey
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	if r.Method == http.MethodOptions {
		h.Set("Access-Control-Allow-Methods", "GET, POST")
		h.Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	h["Access-Control-Allow-Origin"] = corsOriginAny
	pubKey := strings.Trim(r.URL.Path, "/")
	if len(pubKey) != 43 {
		http.Error(w, errInvalidPubKey.Error(), http.StatusBadRequest)
		return
	}

	// Check if cluster routing is enabled
	if s.peerFinder != nil {
		if target := s.targetPeer(pubKey); target == nil {
			fmt.Printf("No peers found for %s\n", r.Host)
			// Cluster routing enabled but no peers found
			respondAndDrain(r, w, http.StatusServiceUnavailable)
			return
		} else {
			me := s.peerFinder.Node().Host
			fmt.Printf("%s %s: for %s got %s, I am: %s\n", r.Method, pubKey, r.Host, target.Host, me)
			// Another node is the HRW owner. Before redirecting, check whether the
			// request already arrived with the target's hostname — this means the
			// client followed a previous redirect to that node but DNS fell through
			// to us (e.g. CNAME drain). We can't find the good node yet; return 503 so
			// the client backs off until the routing table converges.
			if r.Host == target.Host && r.Host != me {
				respondAndDrain(r, w, http.StatusServiceUnavailable)
				return
			} else if r.Host != target.Host {
				u := *target
				u.Path = r.URL.Path
				u.RawQuery = r.URL.RawQuery
				redirectAndDrain(r, w, u.String())
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
		h["Access-Control-Allow-Origin"] = corsOriginAny
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
		return errTimestampOutsideWindow
	}

	// authMsgPool buffers are pre-filled with sseAuthDomain; only write tsBytes.
	msgp := s.authMsgPool.Get().(*[]byte)
	copy((*msgp)[len(sseAuthDomain):], tsBytes)
	ok := ed25519.Verify(pubkey, *msgp, sig)
	s.authMsgPool.Put(msgp)
	s.authDecodePool.Put(rawp)

	if !ok {
		return errSignatureVerificationFailed
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

func respondAndDrain(r *http.Request, w http.ResponseWriter, status int) {
	if r.Method == http.MethodPost {
		// Read and discard the body to avoid leaking resources on the client side.
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	w.WriteHeader(status)
}

func redirectAndDrain(r *http.Request, w http.ResponseWriter, target string) {
	if r.Method == http.MethodPost {
		// Read and discard the body to avoid leaking resources on the client side.
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	w.Header().Set("Cache-Control", "public, max-age=20")
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}
