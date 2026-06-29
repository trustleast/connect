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
// It uses an ephemeral UDP port (":0") so tests don't conflict.
// The peer list is always empty; use injectPeer on the resulting gossip
// to simulate peer state without actual UDP traffic.
type testPeerProvider struct {
	onChange chan struct{}
}

func newTestPeerProvider() *testPeerProvider {
	return &testPeerProvider{onChange: make(chan struct{}, 1)}
}

func (p *testPeerProvider) Self() string              { return "http://self" }
func (p *testPeerProvider) GossipAddr() string        { return ":0" }
func (p *testPeerProvider) Peers() []string           { return nil }
func (p *testPeerProvider) OnChange() <-chan struct{} { return p.onChange }

// newTestGossip creates a gossip with no active peers or background goroutines.
// Useful for unit tests that only call injectPeer + findPeer directly.
func newTestGossip() *gossip {
	return &gossip{
		proxyURL:    "http://self",
		hub:         newHub(context.Background()),
		peerByProxy: make(map[string]*peerSnapshot),
	}
}

// injectPeer adds a fake peer entry directly (without HTTP), keyed by proxyURL.
func (g *gossip) injectPeer(pubkey string, proxyURL string) {
	f, err := xorfilter.NewBinaryFuse[uint8]([]uint64{pubkeyToUint64(pubkey)})
	if err != nil {
		panic("injectPeer: filter build failed: " + err.Error())
	}
	g.mu.Lock()
	g.peerByProxy[proxyURL] = &peerSnapshot{
		ts:     time.Now().UnixNano(),
		filter: f,
	}
	g.mu.Unlock()
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

	_, ok := g.findPeer(pub)
	assertEqual(t, ok, false)

	g.injectPeer(pub, "http://peer1:8080")
	url, ok := g.findPeer(pub)
	assertEqual(t, ok, true)
	assertEqual(t, url, "http://peer1:8080")
}
