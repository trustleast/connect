package connect

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func assertEqual[T comparable](t testing.TB, got T, expected T) {
	t.Helper()
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

// TestSingleNode verifies that a server with no Gossip serves all requests locally.
func TestSingleNode(t *testing.T) {
	srv := httptest.NewServer(newServer(t.Context(), nil))
	defer srv.Close()

	pub, _, err := ed25519.GenerateKey(nil)
	assertEqual(t, err, nil)
	pubStr := base64.RawURLEncoding.EncodeToString(pub)

	t.Run("GET_reaches_handler", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/" + pubStr)
		assertEqual(t, err, nil)
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusUnauthorized)
	})

	t.Run("POST_reaches_handler", func(t *testing.T) {
		resp := postSDP(&http.Client{}, srv.URL, pubStr, testSDP)
		resp.Body.Close()
		assertEqual(t, resp.StatusCode, http.StatusNotFound)
	})
}

// TestProxyOnMiss verifies that a POST to a pubkey not held locally is proxied
// to the peer node that holds the SSE stream.
func TestProxyOnMiss(t *testing.T) {
	// Node B holds the SSE stream.
	nodeB := httptest.NewServer(newServer(t.Context(), nil))
	defer nodeB.Close()

	// Node A is started with a PeerProvider; gossip is created internally.
	pp := newTestPeerProvider()
	sA := newServer(t.Context(), pp)
	nodeA := httptest.NewServer(sA)
	defer nodeA.Close()

	// Open an SSE stream on nodeB.
	_, priv, err := ed25519.GenerateKey(nil)
	assertEqual(t, err, nil)
	sse := connectSSE(t, nodeB.URL, priv)
	defer sse.Body.Close()

	pub := priv.Public().(ed25519.PublicKey)
	pubStr := base64.RawURLEncoding.EncodeToString(pub)

	// Inject peer state into nodeA's gossip so it knows nodeB claims this key.
	sA.gossip.injectPeer(pubStr, nodeB.URL)

	// POST to nodeA — it should proxy to nodeB and deliver.
	// Skip the first data line (node routing token); the second is the message.
	got := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(sse.Body)
		tokenSkipped := false
		for s.Scan() {
			data, ok := strings.CutPrefix(s.Text(), "data: ")
			if !ok {
				continue
			}
			if !tokenSkipped {
				tokenSkipped = true
				continue
			}
			got <- data
			return
		}
	}()

	resp := postSDP(&http.Client{}, nodeA.URL, pubStr, testSDP)
	resp.Body.Close()
	assertEqual(t, resp.StatusCode, http.StatusAccepted)

	data := <-got
	assertEqual(t, data, string(testSDP))
}

// TestProxyLoopPrevention verifies that a proxied POST (X-Internal-Relay: 1)
// is never re-proxied on a miss, and returns 404 instead.
func TestProxyLoopPrevention(t *testing.T) {
	pp := newTestPeerProvider()
	s := newServer(t.Context(), pp)
	srv := httptest.NewServer(s)
	defer srv.Close()

	_, priv, err := ed25519.GenerateKey(nil)
	assertEqual(t, err, nil)
	pub := priv.Public().(ed25519.PublicKey)
	pubStr := base64.RawURLEncoding.EncodeToString(pub)
	s.gossip.injectPeer(pubStr, "http://127.0.0.1:19999") // unreachable

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/"+pubStr, bytes.NewReader(testSDP))
	req.Header.Set("X-Internal-Relay", "1")
	resp, err := (&http.Client{}).Do(req)
	assertEqual(t, err, nil)
	resp.Body.Close()
	assertEqual(t, resp.StatusCode, http.StatusNotFound)
}

// TestTokenBypassGossip verifies that a POST with ?t=<token> routes directly
// to the correct peer without requiring a gossip filter entry. This covers the
// window immediately after a client connects, before gossip has propagated.
func TestTokenBypassGossip(t *testing.T) {
	// Pre-allocate a listener so we know node B's URL before constructing the server.
	// gossip.proxyURL is captured at newGossip time, so the URL must be known first.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assertEqual(t, err, nil)
	t.Cleanup(func() { ln.Close() })
	bURL := "http://" + ln.Addr().String()

	ppB := newTestPeerProvider()
	ppB.self = bURL
	sB := newServer(t.Context(), ppB)
	go http.Serve(ln, sB) //nolint:errcheck

	ppA := newTestPeerProvider()
	sA := newServer(t.Context(), ppA)
	nodeA := httptest.NewServer(sA)
	defer nodeA.Close()

	_, priv, err := ed25519.GenerateKey(nil)
	assertEqual(t, err, nil)
	pub := priv.Public().(ed25519.PublicKey)
	pubStr := base64.RawURLEncoding.EncodeToString(pub)

	// Open SSE on node B — the node token is emitted as the first SSE event.
	sse := connectSSE(t, bURL, priv)
	defer sse.Body.Close()

	// Inject node B with a stale filter (built before the client connected, so
	// it doesn't contain this pubkey). Token routing must succeed via the
	// missingMatchURL fallback in findPeer even when the filter says "no".
	sA.gossip.injectStaleFilter(bURL)

	// Read SSE data lines: the first is the raw node token; subsequent lines
	// are wire messages.
	tokenCh := make(chan string, 1)
	dataCh := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(sse.Body)
		tokenSent := false
		for s.Scan() {
			data, ok := strings.CutPrefix(s.Text(), "data: ")
			if !ok {
				continue
			}
			if !tokenSent {
				tokenCh <- data
				tokenSent = true
				continue
			}
			dataCh <- data
			return
		}
	}()

	token := <-tokenCh

	// POST to node A with the token — should route to node B without a filter.
	req, _ := http.NewRequest(http.MethodPost, nodeA.URL+"/"+pubStr+"?t="+token, bytes.NewReader(testSDP))
	resp, err := (&http.Client{}).Do(req)
	assertEqual(t, err, nil)
	resp.Body.Close()
	assertEqual(t, resp.StatusCode, http.StatusAccepted)

	assertEqual(t, <-dataCh, string(testSDP))
}

// TestStaleTokenFallsBackToGossip verifies that a POST with an unrecognised
// wrong ?t= token still delivers via the gossip filter path.
func TestStaleTokenFallsBackToGossip(t *testing.T) {
	// Node B is single-node (no gossip) — only needs an SSE connection.
	nodeB := httptest.NewServer(newServer(t.Context(), nil))
	defer nodeB.Close()

	ppA := newTestPeerProvider()
	sA := newServer(t.Context(), ppA)
	nodeA := httptest.NewServer(sA)
	defer nodeA.Close()

	_, priv, err := ed25519.GenerateKey(nil)
	assertEqual(t, err, nil)
	pub := priv.Public().(ed25519.PublicKey)
	pubStr := base64.RawURLEncoding.EncodeToString(pub)

	sse := connectSSE(t, nodeB.URL, priv)
	defer sse.Body.Close()

	// Inject gossip filter (regular path) but use a wrong token.
	sA.gossip.injectPeer(pubStr, nodeB.URL)
	wrongToken := nodeToken(pubStr, "http://some-other-node:8080")

	// Skip the first data line (node routing token); the second is the message.
	got := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(sse.Body)
		tokenSkipped := false
		for s.Scan() {
			data, ok := strings.CutPrefix(s.Text(), "data: ")
			if !ok {
				continue
			}
			if !tokenSkipped {
				tokenSkipped = true
				continue
			}
			got <- data
			return
		}
	}()

	req, _ := http.NewRequest(http.MethodPost, nodeA.URL+"/"+pubStr+"?t="+wrongToken, bytes.NewReader(testSDP))
	resp, err := (&http.Client{}).Do(req)
	assertEqual(t, err, nil)
	resp.Body.Close()
	assertEqual(t, resp.StatusCode, http.StatusAccepted)

	assertEqual(t, <-got, string(testSDP))
}
