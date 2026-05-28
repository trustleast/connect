package connect

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// hub manages live SSE connections keyed by base32 public key.
// At most one connection per key is kept; registering a second closes the first.
//
// sync.Map is used because the access pattern is write-once-per-connection,
// read-many-per-message — exactly the case sync.Map's lock-free read path
// is optimised for.
type hub struct {
	clients sync.Map // map[string]*conn
}

// conn holds the live SSE writer for a single pubkey.
type conn struct {
	mu        sync.Mutex
	w         http.ResponseWriter
	flush     func()
	displaced chan struct{} // closed when a newer registration takes over
}

// newHub creates a hub and starts a single shared keepalive ticker that sends
// SSE keep-alive comments to all active connections. The ticker runs until ctx
// is cancelled.
func newHub(ctx context.Context) *hub {
	h := &hub{}
	go h.keepalive(ctx)
	return h
}

func (h *hub) keepalive(ctx context.Context) {
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			h.clients.Range(func(_, val any) bool {
				c := val.(*conn)
				c.mu.Lock()
				c.w.Write(sseKeepalive)
				c.flush()
				c.mu.Unlock()
				return true
			})
		}
	}
}

// register stores conn for pubkey, displacing any existing connection, then
// blocks until ctx is done or the connection is displaced by a newer one. On
// return the conn is removed from the hub. Callers should not use w or fl
// after register returns.
func (h *hub) register(ctx context.Context, pubkey string, w http.ResponseWriter, flush func()) {
	c := &conn{w: w, flush: flush, displaced: make(chan struct{})}
	if old, ok := h.clients.Swap(pubkey, c); ok {
		close(old.(*conn).displaced)
	}

	select {
	case <-ctx.Done():
		h.clients.CompareAndDelete(pubkey, c)
	case <-c.displaced:
		// already replaced in the map by the new registration
	}
}

// deliver writes data directly into the SSE stream registered under pubkey.
// Returns false if pubkey has no active connection.
func (h *hub) deliver(pubkey string, data []byte) bool {
	val, ok := h.clients.Load(pubkey)
	if !ok {
		return false
	}
	c := val.(*conn)
	c.mu.Lock()
	c.w.Write(ssePrefix)
	c.w.Write(data)
	c.w.Write(sseSuffix)
	c.flush()
	c.mu.Unlock()
	return true
}
