package connect

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
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
func (p *testPeerProvider) GossipAddr() string        { return "127.0.0.1:0" }
func (p *testPeerProvider) Peers() []*net.UDPAddr     { return nil }
func (p *testPeerProvider) OnChange() <-chan struct{}  { return p.onChange }

// newTestGossip creates a gossip with no active peers or UDP goroutines.
// Useful for unit tests that only call injectPeer + findPeer directly.
func newTestGossip() *gossip {
	return &gossip{
		proxyURL:   "http://self",
		hub:        newHub(context.Background()),
		peerByAddr: make(map[string]*peerSnapshot),
	}
}

// injectPeer adds a fake peer entry directly (for tests, without UDP).
// Each call uses a unique synthetic addr to avoid collisions.
func (g *gossip) injectPeer(pubkey string, proxyURL string) {
	raw, err := base64.RawURLEncoding.DecodeString(pubkey)
	if err != nil {
		panic("injectPeer: invalid pubkey: " + err.Error())
	}
	f, err := xorfilter.NewBinaryFuse[uint8]([]uint64{pubkeyToUint64(raw)})
	if err != nil {
		panic("injectPeer: filter build failed: " + err.Error())
	}
	g.mu.Lock()
	addrKey := proxyURL // unique per injected peer
	g.peerByAddr[addrKey] = &peerSnapshot{
		seq:      1,
		ts:       time.Now().UnixNano(),
		proxyURL: proxyURL,
		filter:   f,
	}
	g.mu.Unlock()
}

// pubKeyStr encodes an ed25519 private key's public part as base64url.
func pubKeyStr(priv ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// TestXorFilter verifies that BinaryFuse[uint8] contains keys after construction
// and that the pubkeyToUint64 mapping is stable.
func TestXorFilter(t *testing.T) {
	raw1 := make([]byte, 32)
	raw2 := make([]byte, 32)
	for i := range raw1 {
		raw1[i] = byte(i + 1)
		raw2[i] = byte(i + 100)
	}
	k1, k2 := pubkeyToUint64(raw1), pubkeyToUint64(raw2)

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
	// Verify pubkeyToUint64 is deterministic.
	if pubkeyToUint64(raw1) != k1 {
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
