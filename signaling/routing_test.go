package connect

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"
)

// routingPeerFinder is a static PeerFinder for routing tests.
type routingPeerFinder struct {
	peers    []*url.URL
	onChange chan struct{}
}

func newRoutingPeerFinder(peers ...*url.URL) *routingPeerFinder {
	return &routingPeerFinder{
		peers:    peers,
		onChange: make(chan struct{}),
	}
}

func (f *routingPeerFinder) Node() *url.URL            { return f.peers[0] }
func (f *routingPeerFinder) Peers() []*url.URL         { return f.peers }
func (f *routingPeerFinder) OnChange() <-chan struct{} { return f.onChange }
func (f *routingPeerFinder) Secret() [32]byte {
	return sha256.Sum256([]byte(routingSecret))
}

// keyOwnedBy generates ed25519 pubkeys until one's HRW owner matches wantHost.
func keyOwnedBy(t testing.TB, pf *routingPeerFinder, wantHost string) (string, ed25519.PrivateKey) {
	t.Helper()
	for {
		pub, priv, err := ed25519.GenerateKey(nil)
		assertEqual(t, err, nil)
		encoded := base64.RawURLEncoding.EncodeToString(pub)
		target := targetPeer(pf, encoded)
		assertEqual(t, target != nil, true)
		if target.Host == wantHost {
			return encoded, priv
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
func mustParseURL(t testing.TB, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	assertEqual(t, err, nil)
	return u
}

func postSDPHost(t *testing.T, client *http.Client, serverURL, host, targetPubStr string, body []byte) *http.Response {
	req, err := http.NewRequest(http.MethodPost, serverURL+"/"+targetPubStr, bytes.NewReader(body))
	assertEqual(t, err, nil)
	req.Host = host
	resp, err := client.Do(req)
	assertEqual(t, err, nil)
	return resp
}

func getStreamHost(t *testing.T, client *http.Client, serverURL, host string, priv ed25519.PrivateKey) *http.Response {
	pubRaw := priv.Public()
	pub, ok := pubRaw.(ed25519.PublicKey)
	assertEqual(t, ok, true)

	pubStr := base64.RawURLEncoding.EncodeToString(pub)

	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(time.Now().Unix()))
	sig := ed25519.Sign(priv, append([]byte(sseAuthDomain), tsBytes...))
	combined := append(sig, tsBytes...)

	sigParam := url.QueryEscape(base64.RawURLEncoding.EncodeToString(combined))
	req, err := http.NewRequest(http.MethodGet, serverURL+"/"+pubStr+"?sig="+sigParam, nil)
	assertEqual(t, err, nil)
	req.Host = host

	resp, err := client.Do(req)
	assertEqual(t, err, nil)

	return resp
}

// TestSingleNode verifies that a server with no PeerFinder serves all requests
// locally without redirecting.
func TestSingleNode(t *testing.T) {
	srv := httptest.NewServer(newServer(t.Context(), nil))
	defer srv.Close()

	pub, _, err := ed25519.GenerateKey(nil)
	assertEqual(t, err, nil)
	pubStr := base64.RawURLEncoding.EncodeToString(pub)

	t.Run("GET_reaches_handler", func(t *testing.T) {
		resp, err := noRedirect.Get(srv.URL + "/" + pubStr)
		assertEqual(t, err, nil)
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusUnauthorized)
	})

	t.Run("POST_reaches_handler", func(t *testing.T) {
		resp := postSDP(noRedirect, srv.URL, pubStr, testSDP)
		resp.Body.Close()
		// Should reach delivery handler and return 404 (no SSE listener).
		assertEqual(t, resp.StatusCode, http.StatusNotFound)
	})
}

// TestSinglePeerIsSelf verifies that when the peer list contains only this node,
// no keys are redirected.
func TestSinglePeerRedirectsToSingleNode(t *testing.T) {
	nodeA := mustParseURL(t, "http://node-singlepeer.test")
	pf := newRoutingPeerFinder(nodeA)
	srv := httptest.NewServer(newServer(t.Context(), pf))
	defer srv.Close()

	pub, priv, err := ed25519.GenerateKey(nil)
	assertEqual(t, err, nil)
	pubStr := base64.RawURLEncoding.EncodeToString(pub)

	t.Run("no_listener", func(t *testing.T) {
		resp := postSDPHost(t, noRedirect, srv.URL, "node.test", pubStr, testSDP)
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusTemporaryRedirect)
		loc, err := resp.Location()
		assertEqual(t, err, nil)
		assertEqual(t, loc.String(), fmt.Sprintf("http://node-singlepeer.test/%s", pubStr))

		resp = postSDPHost(t, noRedirect, srv.URL, nodeA.Host, pubStr, testSDP)
		resp.Body.Close()
		loc, err = resp.Location()
		t.Log(loc)
		assertEqual(t, resp.StatusCode, http.StatusNotFound)
	})

	t.Run("listener", func(t *testing.T) {
		listenerResp := getStreamHost(t, noRedirect, srv.URL, "", priv)
		assertEqual(t, listenerResp.StatusCode, http.StatusTemporaryRedirect)
		loc, err := listenerResp.Location()
		assertEqual(t, err, nil)
		sig := listenerResp.Request.URL.Query().Get("sig")
		assertEqual(t, loc.String(), fmt.Sprintf("http://node-singlepeer.test/%s?sig=%s", pubStr, sig))

		listenerResp = getStreamHost(t, noRedirect, srv.URL, "node-singlepeer.test", priv)
		assertEqual(t, listenerResp.StatusCode, http.StatusOK)

		resp := postSDPHost(t, noRedirect, srv.URL, "node.test", pubStr, testSDP)
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusTemporaryRedirect)
		loc, err = resp.Location()
		assertEqual(t, err, nil)
		assertEqual(t, loc.String(), fmt.Sprintf("http://node-singlepeer.test/%s", pubStr))

		resp = postSDPHost(t, noRedirect, srv.URL, nodeA.Host, pubStr, testSDP)
		resp.Body.Close()
		loc, err = resp.Location()
		t.Log(loc)
		assertEqual(t, resp.StatusCode, http.StatusAccepted)

		listenerResp.Body.Close()
	})
}

func assertEqual[T comparable](t testing.TB, got T, expected T) {
	if expected != got {
		_, file, line, ok := runtime.Caller(1)
		var preamble string
		if ok {
			tokens := strings.Split(file, "/")
			preamble = fmt.Sprintf("\n%s:%d: ", tokens[len(tokens)-1], line)
		}

		t.Fatalf("%sexpected: %v, got %v", preamble, expected, got)
	}
}

// TestTwoNodeRouting verifies HRW-based routing in a two-node cluster.
func TestTwoNodeRouting(t *testing.T) {
	nodeA := mustParseURL(t, "http://node-twonode-a.test")
	nodeB := mustParseURL(t, "http://node-twonode-b.test")
	// clusterURL := mustParseURL(t, "http://node.test")
	peers := []*url.URL{nodeA, nodeB}

	// Server under test acts as nodeA.
	pf := newRoutingPeerFinder(peers...)
	s := newServer(t.Context(), pf)
	srv := httptest.NewServer(s)
	defer srv.Close()

	aPub, aPriv := keyOwnedBy(t, pf, nodeA.Host)
	bPub, _ := keyOwnedBy(t, pf, nodeB.Host)

	t.Run("GET_a_owned_redirects_to_owner", func(t *testing.T) {
		resp := getStreamHost(t, noRedirect, srv.URL, "", aPriv)
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusTemporaryRedirect)
		sig := resp.Request.URL.Query().Get("sig")
		want := fmt.Sprintf("%s/%s?sig=%s", nodeA.String(), aPub, sig)
		got, err := resp.Location()
		assertEqual(t, err, nil)
		assertEqual(t, got.String(), want)

		listenerResp := getStreamHost(t, noRedirect, srv.URL, nodeA.Host, aPriv)
		assertEqual(t, listenerResp.StatusCode, http.StatusOK)

		resp = postSDPHost(t, noRedirect, srv.URL, nodeA.Host, aPub, []byte("foo"))
		assertEqual(t, resp.StatusCode, http.StatusAccepted)

		listenerResp.Body.Close()
	})

	t.Run("GET_b_owned_sent_to_a_fails", func(t *testing.T) {
		resp := postSDPHost(t, noRedirect, srv.URL, nodeB.Host, bPub, []byte("foo"))
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusServiceUnavailable)
	})

	t.Run("GET_other_owned_preserves_query_string", func(t *testing.T) {
		resp, err := noRedirect.Get(srv.URL + "/" + bPub + "?sig=abc123")
		assertEqual(t, err, nil)
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusTemporaryRedirect)
		want := nodeB.String() + "/" + bPub + "?sig=abc123"
		got, err := resp.Location()
		assertEqual(t, err, nil)
		assertEqual(t, got.String(), want)
	})

	t.Run("POST_other_owned_redirects_to_owner", func(t *testing.T) {
		resp := postSDP(noRedirect, srv.URL, bPub, testSDP)
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusTemporaryRedirect)
		want := nodeB.String() + "/" + bPub
		got, err := resp.Location()
		assertEqual(t, err, nil)
		assertEqual(t, got.String(), want)
	})
}

// TestLoopDetection verifies that a request arriving with the HRW winner's
// hostname returns 503 instead of looping.
func TestLoopDetection(t *testing.T) {
	nodeA := mustParseURL(t, "http://node-a.test")
	nodeB := mustParseURL(t, "http://node-b.test")
	peers := []*url.URL{nodeA, nodeB}

	pf := newRoutingPeerFinder(peers...)
	s := newServer(t.Context(), pf)
	srv := httptest.NewServer(s)
	defer srv.Close()

	// Use a key owned by nodeB so that nodeA would normally redirect there.
	otherKey, _ := keyOwnedBy(t, pf, nodeB.Host)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			req, err := http.NewRequest(method, srv.URL+"/"+otherKey, nil)
			assertEqual(t, err, nil)
			// Simulate arriving with nodeB's hostname — as if the client followed
			// a redirect to node-b.test but DNS fell through to us.
			req.Host = nodeB.Host
			resp, err := noRedirect.Do(req)
			assertEqual(t, err, nil)
			resp.Body.Close()
			assertEqual(t, resp.StatusCode, http.StatusServiceUnavailable)
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

	pf := newRoutingPeerFinder(peers...)
	s := newServer(t.Context(), pf)
	srv := httptest.NewServer(s)
	defer srv.Close()

	selfKey, _ := keyOwnedBy(t, pf, nodeA.Host)

	t.Run("GET_via_cluster_redirects_to_node_URL", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/"+selfKey, nil)
		assertEqual(t, err, nil)
		req.Host = cluster.Host
		resp, err := noRedirect.Do(req)
		assertEqual(t, err, nil)
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusTemporaryRedirect)
		loc, err := resp.Location()
		assertEqual(t, err, nil)
		assertEqual(t, loc.String(), nodeA.String()+"/"+selfKey)
	})

	t.Run("GET_via_cluster_preserves_query_string", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/"+selfKey+"?sig=xyz", nil)
		assertEqual(t, err, nil)
		req.Host = cluster.Host
		resp, err := noRedirect.Do(req)
		assertEqual(t, err, nil)
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusTemporaryRedirect)
		loc, err := resp.Location()
		assertEqual(t, err, nil)
		assertEqual(t, loc.String(), nodeA.String()+"/"+selfKey+"?sig=xyz")
	})

	t.Run("POST_via_cluster_redirects", func(t *testing.T) {
		// POST via the cluster hostname is not redirected to the node URL —
		// only GET (SSE) needs the stable address for reconnection.
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/"+selfKey, nil)
		assertEqual(t, err, nil)
		req.Host = cluster.Host
		resp, err := noRedirect.Do(req)
		assertEqual(t, err, nil)
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusTemporaryRedirect)
	})
}
