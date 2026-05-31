package connect

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// routingPeerFinder is a static PeerFinder for routing tests.
type routingPeerFinder struct {
	peers    []*url.URL
	onChange chan struct{}
}

func newRoutingPeerFinder(peers ...*url.URL) *routingPeerFinder {
	return &routingPeerFinder{peers: peers, onChange: make(chan struct{})}
}

func (f *routingPeerFinder) Peers() []*url.URL        { return f.peers }
func (f *routingPeerFinder) OnChange() <-chan struct{} { return f.onChange }

// hrwTarget replicates targetPeer's scoring. Must stay in sync with server.targetPeer.
func hrwTarget(pubkeyStr, secret string, peers []*url.URL) *url.URL {
	key := sha256.Sum256([]byte(secret))
	best := peers[0]
	var bestScore uint64
	var sum [sha256.Size]byte
	for _, peer := range peers {
		mac := hmac.New(sha256.New, key[:])
		io.WriteString(mac, pubkeyStr)
		mac.Write([]byte{0})
		io.WriteString(mac, peer.Host)
		mac.Sum(sum[:0])
		if score := binary.BigEndian.Uint64(sum[:8]); score > bestScore {
			bestScore = score
			best = peer
		}
	}
	return best
}

// pubkeyOwnedBy generates ed25519 pubkeys until one's HRW owner matches wantHost.
func pubkeyOwnedBy(t *testing.T, secret string, peers []*url.URL, wantHost string) string {
	t.Helper()
	for {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		s := base64.RawURLEncoding.EncodeToString(pub)
		if hrwTarget(s, secret, peers).Host == wantHost {
			return s
		}
	}
}

// noRedirect is an HTTP client that returns redirect responses without following them.
var noRedirect = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

const routingSecret = "test-cluster-secret"

// mustParseURL parses a URL and fatals on error.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// TestSingleNode verifies that a server with no PeerFinder serves all requests
// locally without redirecting.
func TestSingleNode(t *testing.T) {
	srv := httptest.NewServer(NewServer(t.Context(), Config{}))
	defer srv.Close()

	pub, _, _ := ed25519.GenerateKey(nil)
	pubStr := base64.RawURLEncoding.EncodeToString(pub)

	t.Run("GET_reaches_handler", func(t *testing.T) {
		resp, _ := noRedirect.Get(srv.URL + "/" + pubStr)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTemporaryRedirect {
			t.Fatalf("single-node GET: got unexpected redirect")
		}
		// Should reach auth handler and reject the unauthenticated request.
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("single-node GET: want 401, got %d", resp.StatusCode)
		}
	})

	t.Run("POST_reaches_handler", func(t *testing.T) {
		resp := postSDP(noRedirect, srv.URL, pubStr, testSDP)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTemporaryRedirect {
			t.Fatalf("single-node POST: got unexpected redirect")
		}
		// Should reach delivery handler and return 404 (no SSE listener).
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("single-node POST: want 404, got %d", resp.StatusCode)
		}
	})
}

// TestSinglePeerIsSelf verifies that when the peer list contains only this node,
// no keys are redirected.
func TestSinglePeerIsSelf(t *testing.T) {
	nodeA := mustParseURL(t, "http://node-a.test")
	cfg := Config{
		PeerFinder:    newRoutingPeerFinder(nodeA),
		NodeURL:       nodeA,
		ClusterSecret: routingSecret,
	}
	srv := httptest.NewServer(NewServer(t.Context(), cfg))
	defer srv.Close()

	pub, _, _ := ed25519.GenerateKey(nil)
	pubStr := base64.RawURLEncoding.EncodeToString(pub)

	resp := postSDP(noRedirect, srv.URL, pubStr, testSDP)
	resp.Body.Close()
	if resp.StatusCode == http.StatusTemporaryRedirect {
		t.Errorf("single-peer-self POST: unexpected redirect")
	}
}

// TestTwoNodeRouting verifies HRW-based routing in a two-node cluster.
func TestTwoNodeRouting(t *testing.T) {
	nodeA := mustParseURL(t, "http://node-a.test")
	nodeB := mustParseURL(t, "http://node-b.test")
	peers := []*url.URL{nodeA, nodeB}

	// Server under test acts as nodeA.
	cfg := Config{
		PeerFinder:    newRoutingPeerFinder(peers...),
		NodeURL:       nodeA,
		ClusterSecret: routingSecret,
	}
	srv := httptest.NewServer(NewServer(t.Context(), cfg))
	defer srv.Close()

	selfKey := pubkeyOwnedBy(t, routingSecret, peers, nodeA.Host)
	otherKey := pubkeyOwnedBy(t, routingSecret, peers, nodeB.Host)

	t.Run("GET_self_owned_reaches_handler", func(t *testing.T) {
		resp, _ := noRedirect.Get(srv.URL + "/" + selfKey)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTemporaryRedirect {
			t.Fatalf("self-owned GET: unexpected redirect")
		}
		// Routing passed through; auth handler rejects unauthenticated request.
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("self-owned GET: want 401, got %d", resp.StatusCode)
		}
	})

	t.Run("GET_other_owned_redirects_to_owner", func(t *testing.T) {
		resp, _ := noRedirect.Get(srv.URL + "/" + otherKey)
		resp.Body.Close()
		if resp.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("other-owned GET: want 307, got %d", resp.StatusCode)
		}
		want := nodeB.String() + "/" + otherKey
		if got := resp.Header.Get("Location"); got != want {
			t.Errorf("other-owned GET Location: want %s, got %s", want, got)
		}
	})

	t.Run("GET_other_owned_preserves_query_string", func(t *testing.T) {
		resp, _ := noRedirect.Get(srv.URL + "/" + otherKey + "?sig=abc123")
		resp.Body.Close()
		if resp.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("other-owned GET with query: want 307, got %d", resp.StatusCode)
		}
		want := nodeB.String() + "/" + otherKey + "?sig=abc123"
		if got := resp.Header.Get("Location"); got != want {
			t.Errorf("other-owned GET Location with query: want %s, got %s", want, got)
		}
	})

	t.Run("POST_self_owned_reaches_handler", func(t *testing.T) {
		resp := postSDP(noRedirect, srv.URL, selfKey, testSDP)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTemporaryRedirect {
			t.Fatalf("self-owned POST: unexpected redirect")
		}
		// Routing passed through; delivery returns 404 (no SSE listener).
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("self-owned POST: want 404, got %d", resp.StatusCode)
		}
	})

	t.Run("POST_other_owned_redirects_to_owner", func(t *testing.T) {
		resp := postSDP(noRedirect, srv.URL, otherKey, testSDP)
		resp.Body.Close()
		if resp.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("other-owned POST: want 307, got %d", resp.StatusCode)
		}
		want := nodeB.String() + "/" + otherKey
		if got := resp.Header.Get("Location"); got != want {
			t.Errorf("other-owned POST Location: want %s, got %s", want, got)
		}
	})
}

// TestLoopDetection verifies that a request arriving with the HRW winner's
// hostname returns 503 instead of looping.
func TestLoopDetection(t *testing.T) {
	nodeA := mustParseURL(t, "http://node-a.test")
	nodeB := mustParseURL(t, "http://node-b.test")
	peers := []*url.URL{nodeA, nodeB}

	cfg := Config{
		PeerFinder:    newRoutingPeerFinder(peers...),
		NodeURL:       nodeA,
		ClusterSecret: routingSecret,
	}
	srv := httptest.NewServer(NewServer(t.Context(), cfg))
	defer srv.Close()

	// Use a key owned by nodeB so that nodeA would normally redirect there.
	otherKey := pubkeyOwnedBy(t, routingSecret, peers, nodeB.Host)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			req, _ := http.NewRequest(method, srv.URL+"/"+otherKey, nil)
			// Simulate arriving with nodeB's hostname — as if the client followed
			// a redirect to node-b.test but DNS fell through to us.
			req.Host = nodeB.Host
			resp, _ := noRedirect.Do(req)
			resp.Body.Close()

			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Errorf("loop detection %s: want 503, got %d", method, resp.StatusCode)
			}
		})
	}
}

// TestClusterRedirect verifies that a GET arriving via the cluster hostname is
// redirected to the stable node URL even when this node is the HRW owner.
func TestClusterRedirect(t *testing.T) {
	nodeA := mustParseURL(t, "http://node-a.test")
	nodeB := mustParseURL(t, "http://node-b.test")
	cluster := mustParseURL(t, "http://cluster.test")
	peers := []*url.URL{nodeA, nodeB}

	cfg := Config{
		PeerFinder:    newRoutingPeerFinder(peers...),
		NodeURL:       nodeA,
		ClusterURL:    cluster,
		ClusterSecret: routingSecret,
	}
	srv := httptest.NewServer(NewServer(t.Context(), cfg))
	defer srv.Close()

	selfKey := pubkeyOwnedBy(t, routingSecret, peers, nodeA.Host)

	t.Run("GET_via_cluster_redirects_to_node_URL", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/"+selfKey, nil)
		req.Host = cluster.Host
		resp, _ := noRedirect.Do(req)
		resp.Body.Close()

		if resp.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("cluster GET: want 307, got %d", resp.StatusCode)
		}
		want := nodeA.String() + "/" + selfKey
		if got := resp.Header.Get("Location"); got != want {
			t.Errorf("cluster GET Location: want %s, got %s", want, got)
		}
	})

	t.Run("GET_via_cluster_preserves_query_string", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/"+selfKey+"?sig=xyz", nil)
		req.Host = cluster.Host
		resp, _ := noRedirect.Do(req)
		resp.Body.Close()

		if resp.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("cluster GET with query: want 307, got %d", resp.StatusCode)
		}
		want := nodeA.String() + "/" + selfKey + "?sig=xyz"
		if got := resp.Header.Get("Location"); got != want {
			t.Errorf("cluster GET Location with query: want %s, got %s", want, got)
		}
	})

	t.Run("POST_via_cluster_serves_locally", func(t *testing.T) {
		// POST via the cluster hostname is not redirected to the node URL —
		// only GET (SSE) needs the stable address for reconnection.
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/"+selfKey, nil)
		req.Host = cluster.Host
		resp, _ := noRedirect.Do(req)
		resp.Body.Close()

		if resp.StatusCode == http.StatusTemporaryRedirect {
			t.Errorf("cluster POST for self-owned key: unexpected redirect")
		}
	})
}
