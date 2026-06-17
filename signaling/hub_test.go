package connect

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"
)

// mutablePeerFinder is a PeerFinder whose peer list can be updated at runtime.
// Node() always returns the fixed node URL passed at construction.
type mutablePeerFinder struct {
	node     *url.URL
	mu       sync.Mutex
	peers    []*url.URL
	onChange chan struct{}
}

func newMutablePeerFinder(node *url.URL, peers ...*url.URL) *mutablePeerFinder {
	return &mutablePeerFinder{
		node:     node,
		peers:    peers,
		onChange: make(chan struct{}, 1),
	}
}

func (m *mutablePeerFinder) Node() *url.URL { return m.node }
func (m *mutablePeerFinder) Peers() []*url.URL {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.peers
}
func (m *mutablePeerFinder) OnChange() <-chan struct{} { return m.onChange }
func (m *mutablePeerFinder) Secret() [32]byte {
	return sha256.Sum256([]byte("hub-test-secret"))
}
func (m *mutablePeerFinder) setPeers(peers []*url.URL) {
	m.mu.Lock()
	m.peers = peers
	m.mu.Unlock()
	m.onChange <- struct{}{}
}

// TestHubClosesConnectionsForUnownedKeys verifies that after a peer-set change, the
// hub closes SSE connections for pubkeys that are no longer owned by this node,
// while leaving connections for keys that remain on this node open.
func TestHubClosesConnectionsForUnownedKeys(t *testing.T) {
	nodeA := mustParseURL(t, "http://hub-test-node-a.test")
	nodeB := mustParseURL(t, "http://hub-test-node-b.test")
	nodeC := mustParseURL(t, "http://hub-test-node-c.test")

	initialPeers := []*url.URL{nodeA, nodeB}
	newPeers := []*url.URL{nodeA, nodeC}

	pf := newMutablePeerFinder(nodeA, initialPeers...)
	secret := pf.Secret()

	// Find two keys both initially owned by nodeA.
	// movedKey: moves to nodeC after the peer-set change.
	// stableKey: stays on nodeA after the peer-set change.
	var movedKey, stableKey string
	for movedKey == "" || stableKey == "" {
		pub, _, err := ed25519.GenerateKey(nil)
		assertEqual(t, err, nil)
		encoded := base64.RawURLEncoding.EncodeToString(pub)

		h := hmac.New(sha256.New, secret[:])
		if targetPeerWith(initialPeers, encoded, h).Host != nodeA.Host {
			continue // not owned by nodeA in the current peer set
		}
		// targetPeerWith leaves h Reset(); reuse it for the new peer set.
		if targetPeerWith(newPeers, encoded, h).Host != nodeA.Host {
			if movedKey == "" {
				movedKey = encoded
			}
		} else {
			if stableKey == "" {
				stableKey = encoded
			}
		}
	}

	hub := newHub(t.Context(), pf)

	// net.Pipe gives us two connected net.Conn ends. Closing the hub-side end
	// causes the client-side Read to return immediately with an error.
	movedHubSide, movedClientSide := net.Pipe()
	stableHubSide, stableClientSide := net.Pipe()
	defer movedClientSide.Close()
	defer stableClientSide.Close()

	hub.register(movedKey, movedHubSide)
	hub.register(stableKey, stableHubSide)

	// Trigger the peer-set change: nodeB is replaced by nodeC.
	pf.setPeers(newPeers)

	buf := make([]byte, 1)

	// The hub must close movedHubSide; reads from movedClientSide must error.
	movedClientSide.SetDeadline(time.Now().Add(2 * time.Second))
	_, err := movedClientSide.Read(buf)
	if err == nil {
		t.Fatal("expected connection for moved key to be closed, but Read succeeded")
	}

	// The hub must leave stableHubSide open; reads from stableClientSide must time out.
	stableClientSide.SetDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = stableClientSide.Read(buf)
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("expected stable connection to remain open (timeout), got: %v", err)
	}
}
