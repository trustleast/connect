package connect

import "sync"

// hub manages live SSE connections keyed by base32 public key.
// At most one connection per key is kept; registering a second closes the first.
//
// sync.Map is used because the access pattern is write-once-per-connection,
// read-many-per-message — exactly the case sync.Map's lock-free read path
// is optimised for.
type hub struct {
	clients sync.Map // map[string]chan []byte
}

// register creates a channel for pubkey, atomically replaces any existing
// entry, closes the displaced channel if present, and returns the new channel.
func (h *hub) register(pubkey string) chan []byte {
	ch := make(chan []byte, 16)
	if old, ok := h.clients.Swap(pubkey, ch); ok {
		close(old.(chan []byte))
	}
	return ch
}

// unregister removes pubkey only if ch is still the current channel, then
// closes it. If a newer registration displaced ch, the close already happened
// inside register — this becomes a no-op.
func (h *hub) unregister(pubkey string, ch chan []byte) {
	if h.clients.CompareAndDelete(pubkey, ch) {
		close(ch)
	}
}

// deliver sends data to the channel registered under pubkey.
// Returns false if pubkey has no active connection or its buffer is full.
func (h *hub) deliver(pubkey string, data []byte) bool {
	val, ok := h.clients.Load(pubkey)
	if !ok {
		return false
	}
	ch := val.(chan []byte)
	select {
	case ch <- data:
		return true
	default:
		return false
	}
}
