package connect

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/FastFilter/xorfilter"
)

// hub manages live SSE connections keyed by base64url public key.
// At most one connection per key; registering a second closes the first.
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

// newHub creates a hub and starts the shared keepalive goroutine.
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

// buildFilter constructs a BinaryFuse[uint8] over all currently registered
// pubkeys, suitable for gossip broadcast. Returns nil when no clients are
// connected. Duplicate hashes (astronomically rare) are silently deduplicated
// as required by xorfilter.
func (h *hub) buildFilter() *xorfilter.BinaryFuse[uint8] {
	seen := make(map[uint64]struct{})
	h.clients.Range(func(k, _ any) bool {
		seen[pubkeyToUint64(k.(string))] = struct{}{}
		return true
	})
	if len(seen) == 0 {
		return nil
	}
	keys := make([]uint64, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	f, err := xorfilter.NewBinaryFuse[uint8](keys)
	if err != nil {
		return nil
	}
	return f
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

// pubkeyToUint64 maps a base64url-encoded ed25519 public key to a uint64 for
// the BinaryFuse filter. Inlined FNV-1a avoids allocating a hash.Hash object.
func pubkeyToUint64(b64key string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(b64key); i++ {
		h ^= uint64(b64key[i])
		h *= prime64
	}
	return h
}
