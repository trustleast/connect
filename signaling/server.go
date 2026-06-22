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
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PeerProvider supplies intra-AZ peer discovery for the gossip routing layer.
// NewHTTPServer uses it to bootstrap and track the gossip peer set; the gossip
// protocol is an internal implementation detail of the server.
//
// Implementations must be safe for concurrent use.
type PeerProvider interface {
	// Self returns the internal HTTP base URL that peers use when proxying POSTs.
	Self() string
	// GossipAddr returns the UDP address this node listens on for gossip (e.g. ":9876").
	GossipAddr() string
	// Peers returns the current set of peer gossip UDP addresses (excluding self).
	Peers() []*net.UDPAddr
	// OnChange returns a channel that receives a signal whenever the peer set
	// changes. The channel must never be closed. Callers re-read Peers() after
	// receiving a signal.
	OnChange() <-chan struct{}
}

const (
	_AuthMessageSize   = 8 + ed25519.SignatureSize
	_MaxBodySize       = 4 << 10
	_InvalidCharacters = "\n\r"
	_SSEPrefixLen      = 6
	_SSESuffixLen      = 2
	_FrameSize         = _SSEPrefixLen + _MaxBodySize + _SSESuffixLen
)

var (
	sseAuthDomain = []byte("connect.sse.v1\x00")
	ssePrefix     = []byte("data: ")
	sseSuffix     = []byte("\n\n")
	sseKeepalive  = []byte(": ka\n\n")
	corsOriginAny = []string{"*"}
	sseResponse   = []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/event-stream\r\n" +
		"Cache-Control: no-cache\r\n" +
		"Connection: keep-alive\r\n" +
		"Access-Control-Allow-Origin: *\r\n" +
		"X-Accel-Buffering: no\r\n" +
		"\r\n")

	errInvalidPubKey               = errors.New("invalid public key")
	errInvalidEncoding             = errors.New("invalid encoding")
	errInvalidSignatureLength      = errors.New("invalid signature length")
	errTimestampOutsideWindow      = errors.New("timestamp outside window")
	errSignatureVerificationFailed = errors.New("signature verification failed")
)

type server struct {
	hub            *hub
	gossip         *gossip // nil in single-node mode
	proxyClient    *http.Client
	framePool      sync.Pool
	authDecodePool sync.Pool
	authMsgPool    sync.Pool
}

func NewHTTPServer(ctx context.Context, pp PeerProvider) (*http.Server, error) {
	s, err := newServer(ctx, pp)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Handler: s,
		// Disable HTTP/2: ServeTLS enables it automatically via ALPN, but
		// hijacking (required for SSE) is not available on HTTP/2 streams.
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 10,
	}, nil
}

func newServer(ctx context.Context, pp PeerProvider) (*server, error) {
	h := newHub(ctx)
	var g *gossip
	if pp != nil {
		var err error
		g, err = newGossip(pp, h)
		if err != nil {
			return nil, err
		}
		g.listen(ctx)
	}
	return &server{
		hub:    h,
		gossip: g,
		proxyClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		framePool: sync.Pool{
			New: func() any {
				b := make([]byte, _FrameSize)
				copy(b, ssePrefix)
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
	}, nil
}

// ServeHTTP routes:
//
//	GET  /{pubkey}  — open SSE stream (client proves ownership)
//	POST /{pubkey}  — deliver payload; proxy to peer on local miss
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

// verifyAuth checks that the request carries a valid ed25519 signature from pubkey.
//
// rawSig is the raw base64url bytes of (sig || ts) where ts is an 8-byte
// big-endian uint64 unix timestamp. The signature covers sseAuthDomain || ts.
// Timestamp must be within ±60s of server time (lenient window for the decode
// path; the ±2s enforcement is documented in CLAUDE.md for the strict window).
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
	if s.gossip != nil {
		s.gossip.broadcast()
	}
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
// viable sizes for a write-only long-lived stream.
func tuneSSEBuffers(nc net.Conn) {
	tuneConnBuffers(nc, 1, _FrameSize)
}

// postMessage delivers an opaque payload to the target's SSE stream.
// On a local miss, it attempts to proxy the request to a peer via gossip.
func (s *server) postMessage(w http.ResponseWriter, r *http.Request, targetStr string) {
	framep := s.framePool.Get().(*[]byte)
	defer s.framePool.Put(framep)

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

	copy((*framep)[_SSEPrefixLen+n:], sseSuffix)
	frame := (*framep)[:_SSEPrefixLen+n+_SSESuffixLen]

	if s.hub.deliver(targetStr, frame) {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Local miss: proxy to a peer that claims this key if gossip is configured
	// and this request has not already been proxied (prevent proxy loops).
	if s.gossip != nil && r.Header.Get("X-Internal-Relay") == "" {
		if proxyURL, ok := s.gossip.findPeer(targetStr); ok {
			s.proxyPost(w, r, proxyURL, targetStr, body[:n])
			return
		}
	}

	http.Error(w, "recipient not connected", http.StatusNotFound)
}

// proxyPost forwards a POST body to a peer node's internal HTTP address.
// body must remain valid until proxyPost returns (caller owns the backing buffer).
func (s *server) proxyPost(w http.ResponseWriter, r *http.Request, proxyBaseURL, pubkey string, body []byte) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		proxyBaseURL+"/"+pubkey, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("X-Internal-Relay", "1")

	resp, err := s.proxyClient.Do(req)
	if err != nil {
		http.Error(w, "peer unreachable", http.StatusBadGateway)
		return
	}
	resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}
