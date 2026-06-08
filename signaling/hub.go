package connect

import (
	"context"
	"net"
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

// conn holds the hijacked TCP connection for a single pubkey.
type conn struct {
	mu sync.Mutex
	nc net.Conn
}

// newHub creates a hub and starts a single shared keepalive ticker that sends
// SSE keep-alive comments to all active connections. The ticker runs until ctx
// is cancelled, at which point all connections are closed.
func newHub(ctx context.Context, peerFinder PeerFinder) *hub {
	h := &hub{}
	go h.cleanUnownedConnections(ctx, peerFinder)
	go h.keepalive(ctx)
	return h
}

func (h *hub) cleanUnownedConnections(ctx context.Context, peerFinder PeerFinder) {
	if peerFinder == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-peerFinder.OnChange():
			if !ok {
				return
			}

			h.clients.Range(func(k, val any) bool {
				pubkey := k.(string)
				if target := targetPeer(peerFinder, pubkey); target == nil {
					c := val.(*conn)
					if h.clients.CompareAndDelete(k, c) {
						c.nc.Close()
					}
				}
				return true
			})
		}
	}
}
func (h *hub) keepalive(ctx context.Context) {
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			h.clients.Range(func(k, val any) bool {
				c := val.(*conn)
				if h.clients.CompareAndDelete(k, c) {
					c.nc.Close()
				}
				return true
			})
			return
		case <-tick.C:
			h.clients.Range(func(k, val any) bool {
				c := val.(*conn)
				c.mu.Lock()
				_, err := c.nc.Write(sseKeepalive)
				c.mu.Unlock()
				if err != nil {
					if h.clients.CompareAndDelete(k, c) {
						c.nc.Close()
					}
				}
				return true
			})
		}
	}
}

// register stores nc for pubkey and closes any displaced connection.
// It returns immediately; the caller's goroutine is freed.
func (h *hub) register(pubkey string, nc net.Conn) {
	c := &conn{nc: nc}
	if old, ok := h.clients.Swap(pubkey, c); ok {
		old.(*conn).nc.Close()
	}
}

// deliver writes a pre-framed SSE payload to the stream registered under
// pubkey. The caller is responsible for framing (prefix + body + suffix).
// Returns false if pubkey has no active connection or the write fails.
func (h *hub) deliver(pubkey string, frame []byte) bool {
	val, ok := h.clients.Load(pubkey)
	if !ok {
		return false
	}
	c := val.(*conn)
	c.mu.Lock()
	_, err := c.nc.Write(frame)
	c.mu.Unlock()
	if err != nil {
		if h.clients.CompareAndDelete(pubkey, c) {
			c.nc.Close()
		}
		return false
	}
	return true
}
