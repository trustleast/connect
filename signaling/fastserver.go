package connect

import (
	"bytes"
	"context"
	"net"
	"sync"
	"unsafe"

	"github.com/valyala/fasthttp"
)

// FastServer is a fasthttp-based alternative to server that eliminates the
// net/http header parsing allocations (readMIMEHeader was 34.5% of allocs).
// The API surface is identical: GET /{pubkey} opens SSE, POST /{pubkey} relays.
type FastServer struct {
	hub       *hub
	peers     PeerFinder
	nodeURL   string
	framePool sync.Pool
}

func NewFastServer(ctx context.Context, cfg Config) *FastServer {
	return &FastServer{
		hub:     newHub(ctx),
		peers:   cfg.PeerFinder,
		nodeURL: cfg.NodeURL,
		framePool: sync.Pool{
			New: func() any {
				b := make([]byte, _FrameSize)
				copy(b, ssePrefix)
				return &b
			},
		},
	}
}

// Handler is the fasthttp request handler — pass to fasthttp.Server.Handler.
func (s *FastServer) Handler(ctx *fasthttp.RequestCtx) {
	method := string(ctx.Method())

	if method == fasthttp.MethodOptions {
		ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
		ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST")
		ctx.Response.Header.Set("Access-Control-Allow-Headers", "Content-Type")
		ctx.SetStatusCode(fasthttp.StatusNoContent)
		return
	}

	pubKeyB := bytes.Trim(ctx.Path(), "/")
	if len(pubKeyB) != 43 {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		return
	}
	// Zero-copy reinterpret: safe because ctx.Path() is owned by fasthttp for
	// the duration of this handler call and is never mutated. The string must
	// not outlive the handler — callers that need to store it (hub.register)
	// must make an explicit copy first.
	pubKey := unsafe.String(&pubKeyB[0], len(pubKeyB))

	switch method {
	case fasthttp.MethodGet:
		s.listenForMessages(ctx, pubKey)
	case fasthttp.MethodPost:
		ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
		s.postMessage(ctx, pubKey)
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
	}
}

func (s *FastServer) listenForMessages(ctx *fasthttp.RequestCtx, pubkeyStr string) {
	// Decode the pubkey into a pooled buffer. The returned key aliases the buffer,
	// so we must not return it to the pool until after verifyAuth (which calls
	// ed25519.Verify) has returned.
	pubkeyBufp := pubkeyDecodePool.Get().(*[]byte)
	pubkey, err := decodePubKeyInto([]byte(pubkeyStr), *pubkeyBufp)
	if err != nil {
		pubkeyDecodePool.Put(pubkeyBufp)
		ctx.Error("invalid public key", fasthttp.StatusBadRequest)
		return
	}

	// ctx.QueryArgs().Peek returns a []byte slice into fasthttp's buffer —
	// no string conversion needed, passing it directly to verifyAuth saves 1 alloc.
	sig := ctx.QueryArgs().Peek("sig")
	if len(sig) == 0 {
		pubkeyDecodePool.Put(pubkeyBufp)
		ctx.Error("missing signature", fasthttp.StatusUnauthorized)
		return
	}

	err = verifyAuth(sig, pubkey)
	pubkeyDecodePool.Put(pubkeyBufp) // safe: verifyAuth has returned, pubkey no longer live
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusUnauthorized)
		return
	}

	// Tell fasthttp not to send any response — we write sseResponse ourselves
	// directly on the raw connection inside the hijack callback.
	// Copy the key before the hijack closure captures it: pubkeyStr is a
	// zero-copy view into fasthttp's path buffer which may be reused after the
	// handler returns. The hub map key must outlive the request.
	storedKey := string([]byte(pubkeyStr))

	ctx.HijackSetNoResponse(true)
	ctx.Hijack(func(nc net.Conn) {
		// nc is fasthttp's pooled hijackConn wrapper; extract the real TCP
		// connection so we can hold it after the hijack handler returns (fasthttp
		// zeroes hijackConn.Conn on release, which would panic on later writes).
		type unsafer interface{ UnsafeConn() net.Conn }
		raw := nc
		if u, ok := nc.(unsafer); ok {
			raw = u.UnsafeConn()
		}
		tuneSSEBuffers(raw)
		if _, err := raw.Write(sseResponse); err != nil {
			raw.Close()
			return
		}
		s.hub.register(storedKey, raw)
	})
}

func (s *FastServer) postMessage(ctx *fasthttp.RequestCtx, targetStr string) {
	body := ctx.PostBody() // zero-copy slice into fasthttp's read buffer
	if len(body) == 0 {
		ctx.Error("empty body", fasthttp.StatusBadRequest)
		return
	}
	if len(body) > _MaxBodySize {
		ctx.Error("body too large", fasthttp.StatusRequestEntityTooLarge)
		return
	}

	if bytes.ContainsAny(body, _InvalidCharacters) {
		ctx.Error("body must not contain newlines; send base64-encoded data", fasthttp.StatusBadRequest)
		return
	}

	framep := s.framePool.Get().(*[]byte)
	defer s.framePool.Put(framep)

	n := copy((*framep)[_SSEPrefixLen:_SSEPrefixLen+_MaxBodySize], body)
	copy((*framep)[_SSEPrefixLen+n:], sseSuffix)

	if !s.hub.deliver(targetStr, (*framep)[:_SSEPrefixLen+n+_SSESuffixLen]) {
		ctx.Error("recipient not connected", fasthttp.StatusNotFound)
		return
	}

	ctx.SetStatusCode(fasthttp.StatusAccepted)
}
