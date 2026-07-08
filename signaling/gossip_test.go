package connect

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/FastFilter/xorfilter"
)

// testPeerProvider is a no-op PeerProvider for unit tests.
// The peer list is always empty; use injectPeer on the resulting gossip
// to simulate peer state without actual HTTP traffic.
type testPeerProvider struct {
	self string
}

func newTestPeerProvider() *testPeerProvider {
	return &testPeerProvider{self: "http://self"}
}

func (p *testPeerProvider) Self() string    { return p.self }
func (p *testPeerProvider) Peers() []string { return nil }

// newTestGossip creates a gossip with no active peers or background goroutines.
// Useful for unit tests that only call injectPeer + findPeer directly.
func newTestGossip() *gossip {
	return &gossip{
		pp:  newTestPeerProvider(),
		hub: newHub(context.Background()),
	}
}

// injectPeer adds a fake peer entry directly (without HTTP), keyed by proxyURL.
func (g *gossip) injectPeer(pubkey string, proxyURL string) {
	f, err := xorfilter.NewBinaryFuse[uint8]([]uint64{pubkeyToUint64(pubkey)})
	if err != nil {
		panic("injectPeer: filter build failed: " + err.Error())
	}
	g.peers.Store(proxyURL, &peerSnapshot{ts: time.Now(), filter: f})
}

// injectStaleFilter adds a peer entry whose filter was built before the target
// client connected — the filter contains a different key, not the one being
// looked up. This exercises the missingMatchURL fallback in findPeer.
func (g *gossip) injectStaleFilter(proxyURL string) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic("injectStaleFilter: " + err.Error())
	}
	f, err := xorfilter.NewBinaryFuse[uint8]([]uint64{pubkeyToUint64(pubKeyStr(priv))})
	if err != nil {
		panic("injectStaleFilter: " + err.Error())
	}
	g.peers.Store(proxyURL, &peerSnapshot{ts: time.Now(), filter: f})
}

// pubKeyStr encodes an ed25519 private key's public part as base64url.
func pubKeyStr(priv ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// TestXorFilter verifies that BinaryFuse[uint8] contains keys after construction
// and that pubkeyToUint64 is deterministic over base64url strings.
func TestXorFilter(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(nil)
	_, priv2, _ := ed25519.GenerateKey(nil)
	s1, s2 := pubKeyStr(priv1), pubKeyStr(priv2)
	k1, k2 := pubkeyToUint64(s1), pubkeyToUint64(s2)

	f, err := xorfilter.NewBinaryFuse[uint8]([]uint64{k1, k2})
	if err != nil {
		t.Fatal(err)
	}
	if !f.Contains(k1) {
		t.Fatal("filter should contain k1")
	}
	if !f.Contains(k2) {
		t.Fatal("filter should contain k2")
	}
	if pubkeyToUint64(s1) != k1 {
		t.Fatal("pubkeyToUint64 is not deterministic")
	}
}

// TestGossipFindPeer verifies that findPeer returns the injected peer URL.
func TestGossipFindPeer(t *testing.T) {
	g := newTestGossip()

	_, priv, err := ed25519.GenerateKey(nil)
	assertEqual(t, err, nil)
	pub := pubKeyStr(priv)

	_, ok := g.findPeer(pub, "")
	assertEqual(t, ok, false)

	g.injectPeer(pub, "http://peer1:8080")
	url, ok := g.findPeer(pub, "")
	assertEqual(t, ok, true)
	assertEqual(t, url, "http://peer1:8080")
}

// TestNodeToken_deterministic verifies that nodeToken returns the same value for
// identical inputs.
func TestNodeToken_deterministic(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := pubKeyStr(priv)
	tok1 := nodeToken(pub, "http://node1:8080")
	tok2 := nodeToken(pub, "http://node1:8080")
	assertEqual(t, tok1, tok2)
}

// TestNodeToken_differentPubkey verifies that different pubkeys produce different tokens.
func TestNodeToken_differentPubkey(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(nil)
	_, priv2, _ := ed25519.GenerateKey(nil)
	proxyURL := "http://node1:8080"
	tok1 := nodeToken(pubKeyStr(priv1), proxyURL)
	tok2 := nodeToken(pubKeyStr(priv2), proxyURL)
	if tok1 == tok2 {
		t.Fatal("different pubkeys should produce different tokens")
	}
}

// TestNodeToken_differentNode verifies that the same pubkey on different nodes
// produces different tokens.
func TestNodeToken_differentNode(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := pubKeyStr(priv)
	tok1 := nodeToken(pub, "http://node1:8080")
	tok2 := nodeToken(pub, "http://node2:8080")
	if tok1 == tok2 {
		t.Fatal("different nodes should produce different tokens")
	}
}

// TestFindPeer_tokenTiebreaker verifies that when multiple peers' filters claim
// a key, the peer whose token matches wins over the most-recent-timestamp heuristic.
func TestFindPeer_tokenTiebreaker(t *testing.T) {
	g := newTestGossip()
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := pubKeyStr(priv)

	// Both peers share the same filter to simulate a false positive on peer2.
	f, err := xorfilter.NewBinaryFuse[uint8]([]uint64{pubkeyToUint64(pub)})
	assertEqual(t, err, nil)

	now := time.Now()
	// peer2 is more recent — it would win without a token.
	g.peers.Store("http://peer1:8080", &peerSnapshot{ts: now.Add(-time.Millisecond), filter: f})
	g.peers.Store("http://peer2:8080", &peerSnapshot{ts: now, filter: f})

	// Token identifies peer1; it should win despite being less recent.
	token := nodeToken(pub, "http://peer1:8080")
	url, ok := g.findPeer(pub, token)
	assertEqual(t, ok, true)
	assertEqual(t, url, "http://peer1:8080")

	// Without a token, peer2 wins (most recent).
	url, ok = g.findPeer(pub, "")
	assertEqual(t, ok, true)
	assertEqual(t, url, "http://peer2:8080")
}

// TestFindPeer_tokenMissingMatchFallback verifies that when a token identifies a
// peer but that peer's filter predates the client's connection (key not in filter),
// findPeer still routes to that peer rather than returning not-found.
// This covers the window between a client connecting and the next gossip broadcast.
func TestFindPeer_tokenMissingMatchFallback(t *testing.T) {
	g := newTestGossip()
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := pubKeyStr(priv)

	// Inject a stale filter — built before the client connected, so it contains
	// some other key but not pub.
	g.injectStaleFilter("http://peer1:8080")

	// Without a token, filter says "no" — peer not found.
	_, ok := g.findPeer(pub, "")
	assertEqual(t, ok, false)

	// With the correct token, the peer is returned as a best-effort fallback.
	token := nodeToken(pub, "http://peer1:8080")
	url, ok := g.findPeer(pub, token)
	assertEqual(t, ok, true)
	assertEqual(t, url, "http://peer1:8080")
}
