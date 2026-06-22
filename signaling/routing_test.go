package connect

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
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
	if sA.gossip == nil {
		t.Skip("gossip not available (UDP bind failed)")
	}
	sA.gossip.injectPeer(pubStr, nodeB.URL)

	// POST to nodeA — it should proxy to nodeB and deliver.
	got := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(sse.Body)
		for s.Scan() {
			if data, ok := strings.CutPrefix(s.Text(), "data: "); ok {
				got <- data
				return
			}
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

	if s.gossip == nil {
		t.Skip("gossip not available (UDP bind failed)")
	}

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
