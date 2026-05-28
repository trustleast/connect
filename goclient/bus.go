package connect

import "sync"

// bus routes wireMessages to per-connection subscribers by connKey.
// The SSE loop dispatches; Dial and handleIncoming goroutines subscribe.
//
// Subscribe before sending any message that could generate a reply — the
// channel must exist before the reply can arrive.
type bus struct {
	mu   sync.Mutex
	subs map[connKey]chan wireMessage
}

func newBus() *bus {
	return &bus{subs: make(map[connKey]chan wireMessage)}
}

// subscribe registers a buffered channel for key. The returned unsubscribe
// function must be called exactly once (typically via defer) to remove the
// entry. It is safe to call from any goroutine.
func (b *bus) subscribe(key connKey) (<-chan wireMessage, func()) {
	ch := make(chan wireMessage, 32)
	b.mu.Lock()
	b.subs[key] = ch
	b.mu.Unlock()
	return ch, sync.OnceFunc(func() {
		b.mu.Lock()
		if b.subs[key] == ch { // guard against a newer subscription for the same key
			delete(b.subs, key)
		}
		b.mu.Unlock()
	})
}

// dispatch sends msg to the subscriber for key if one exists.
// Non-blocking: drops the message if the channel buffer is full rather than
// stalling the SSE loop. Returns false when no subscriber is registered.
func (b *bus) dispatch(key connKey, msg wireMessage) bool {
	b.mu.Lock()
	ch := b.subs[key]
	b.mu.Unlock()
	if ch == nil {
		return false
	}
	select {
	case ch <- msg:
	default:
	}
	return true
}

// clear removes all subscribers, leaving the bus empty.
func (b *bus) clear() {
	b.mu.Lock()
	b.subs = make(map[connKey]chan wireMessage)
	b.mu.Unlock()
}
