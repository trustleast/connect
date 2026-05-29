package connect

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

var testSDP = []byte(base64.StdEncoding.EncodeToString([]byte("v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:test\r\na=ice-pwd:testpassword\r\na=fingerprint:sha-256 AA:BB:CC\r\na=setup:actpass\r\na=mid:0\r\n")))

func connectSSE(tb testing.TB, serverURL string, pub ed25519.PublicKey, priv ed25519.PrivateKey) *http.Response {
	tb.Helper()
	pubStr := base64.RawURLEncoding.EncodeToString(pub)

	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(time.Now().Unix()))
	sig := ed25519.Sign(priv, append([]byte(sseAuthDomain), tsBytes...))
	combined := append(sig, tsBytes...)

	sigParam := url.QueryEscape(base64.RawURLEncoding.EncodeToString(combined))
	req, err := http.NewRequest(http.MethodGet, serverURL+"/"+pubStr+"?sig="+sigParam, nil)
	if err != nil {
		tb.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("SSE connect: unexpected status %d", resp.StatusCode)
	}
	return resp
}

func postSDP(client *http.Client, serverURL, targetPubStr string, body []byte) *http.Response {
	req, _ := http.NewRequest(http.MethodPost, serverURL+"/"+targetPubStr, bytes.NewReader(body))
	resp, _ := client.Do(req)
	return resp
}

// BenchmarkSSERoundtrip measures end-to-end delivery: POST entering the server
// to the message appearing on the receiver's SSE stream.
func BenchmarkSSERoundtrip(b *testing.B) {
	srv := httptest.NewServer(NewServer(b.Context(), Config{}))
	defer srv.Close()

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverStr := base64.RawURLEncoding.EncodeToString(receiverPub)

	sse := connectSSE(b, srv.URL, receiverPub, receiverPriv)
	defer sse.Body.Close()

	delivered := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(sse.Body)
		for s.Scan() {
			if data, ok := strings.CutPrefix(s.Text(), "data: "); ok {
				delivered <- data
			}
		}

		// Connection closed error is expected because we don't synchronize with teardown
		if err := s.Err(); err != nil && !strings.HasSuffix(err.Error(), "use of closed network connection") {
			b.Errorf("SSE read error: %v", err)
		}
	}()

	expected := string(testSDP)

	client := &http.Client{}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp := postSDP(client, srv.URL, receiverStr, testSDP)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			b.Fatalf("unexpected status %d", resp.StatusCode)
		}
		data := <-delivered
		if data != expected {
			b.Fatalf("unexpected SSE data:\ngot  %q\nwant %q", data, expected)
		}
	}
}

// BenchmarkSSEConnect measures the cost of opening a single SSE connection:
// auth verification, hijack, sseResponse write, and hub registration.
//
// Keypairs are pre-generated to exclude ed25519.GenerateKey from the measured
// path. A pool of 256 pubkeys is reused in rotation — each new connection
// evicts its predecessor, keeping the hub size bounded at 256 entries.
func BenchmarkSSEConnect(b *testing.B) {
	srv := httptest.NewServer(NewServer(b.Context(), Config{}))
	defer srv.Close()

	const poolSize = 256
	type kp struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}
	pool := make([]kp, poolSize)
	for i := range pool {
		pool[i].pub, pool[i].priv, _ = ed25519.GenerateKey(nil)
	}

	var open [poolSize]*http.Response

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		k := pool[i%poolSize]
		resp := connectSSE(b, srv.URL, k.pub, k.priv)
		if old := open[i%poolSize]; old != nil {
			old.Body.Close()
		}
		open[i%poolSize] = resp
	}

	b.StopTimer()
	for _, resp := range open {
		if resp != nil {
			resp.Body.Close()
		}
	}
}

/*
Reference benchmarks below — not testing our API, but establishing baselines.
These are theoretical things we can't avoid paying on every request.
BenchmarkHTTPRoundtrip and BenchmarkFastHTTPRoundtrip are the net/http and
fasthttp floors respectively — the minimum overhead a request can ever cost.
*/

// BenchmarkED25519 measures a single ed25519 Sign + Verify pair — the minimum
// crypto cost paid on every POST (sender signs, server verifies).
func BenchmarkED25519(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	msg := []byte("ts\nPOST\n/path\nbody")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sig := ed25519.Sign(priv, msg)
		ed25519.Verify(pub, msg, sig)
	}
}

// BenchmarkHTTPRoundtrip measures a plain net/http POST round-trip to a no-op
// handler — the minimum net/http overhead paid on every request.
func BenchmarkHTTPRoundtrip(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client := &http.Client{}
	body := strings.NewReader("hello")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		body.Reset("hello")
		resp, _ := client.Post(srv.URL, "text/plain", body)
		resp.Body.Close()
	}
}

// BenchmarkFastHTTPRoundtrip measures a plain fasthttp POST round-trip to a
// no-op handler — the minimum fasthttp overhead paid on every request.
// Compare to BenchmarkHTTPRoundtrip to see the net/http vs fasthttp baseline gap,
// and to BenchmarkFastSSERoundtrip to see how much our own code adds on top.
//
// Two variants:
//   - NetHTTPClient: net/http client → fasthttp server (what our real clients do)
//   - FastHTTPClient: fasthttp client → fasthttp server (true fasthttp floor)
//
// The gap between the two variants is the net/http client's allocation cost.
func BenchmarkFastHTTPRoundtrip(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	fhSrv := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			ctx.SetStatusCode(fasthttp.StatusAccepted)
		},
	}
	go fhSrv.Serve(ln) //nolint:errcheck
	b.Cleanup(func() { fhSrv.Shutdown() })

	addr := ln.Addr().String()

	b.Run("NetHTTPClient", func(b *testing.B) {
		client := &http.Client{}
		body := strings.NewReader("hello")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			body.Reset("hello")
			resp, _ := client.Post("http://"+addr, "text/plain", body)
			resp.Body.Close()
		}
	})

	b.Run("FastHTTPClient", func(b *testing.B) {
		client := &fasthttp.Client{}
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(resp)

		req.Header.SetMethod(fasthttp.MethodPost)
		req.SetRequestURI("http://" + addr)
		req.SetBodyString("hello")

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			req.SetBodyString("hello")
			resp.Reset()
			client.Do(req, resp) //nolint:errcheck
		}
	})
}

// startFastServer starts a FastServer on a random local port and returns the
// base URL. The server stops when the test completes.
func startFastServer(tb testing.TB) string {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	fs := NewFastServer(tb.Context(), Config{})
	fhSrv := &fasthttp.Server{
		Handler:            fs.Handler,
		MaxRequestBodySize: _MaxBodySize,
		KeepHijackedConns:  true,
	}
	go fhSrv.Serve(ln) //nolint:errcheck
	tb.Cleanup(func() { fhSrv.Shutdown() })
	return "http://" + ln.Addr().String()
}

// BenchmarkFastSSERoundtrip is the fasthttp equivalent of BenchmarkSSERoundtrip.
// The POST (hot path) uses a fasthttp.Client to eliminate client-side allocs and
// measure server overhead in isolation. The SSE subscription uses net/http since
// fasthttp's client doesn't support streaming reads.
func BenchmarkFastSSERoundtrip(b *testing.B) {
	srvURL := startFastServer(b)

	receiverPub, receiverPriv, _ := ed25519.GenerateKey(nil)
	receiverStr := base64.RawURLEncoding.EncodeToString(receiverPub)

	sse := connectSSE(b, srvURL, receiverPub, receiverPriv)
	defer sse.Body.Close()

	delivered := make(chan string, 1)
	go func() {
		s := bufio.NewScanner(sse.Body)
		for s.Scan() {
			if data, ok := strings.CutPrefix(s.Text(), "data: "); ok {
				delivered <- data
			}
		}
		if err := s.Err(); err != nil && !strings.HasSuffix(err.Error(), "use of closed network connection") {
			b.Errorf("SSE read error: %v", err)
		}
	}()

	expected := string(testSDP)

	client := &fasthttp.Client{}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod(fasthttp.MethodPost)
	req.SetRequestURI(srvURL + "/" + receiverStr)
	req.SetBody(testSDP)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		resp.Reset()
		if err := client.Do(req, resp); err != nil {
			b.Fatalf("post: %v", err)
		}
		if resp.StatusCode() != fasthttp.StatusAccepted {
			b.Fatalf("unexpected status %d", resp.StatusCode())
		}
		data := <-delivered
		if data != expected {
			b.Fatalf("unexpected SSE data:\ngot  %q\nwant %q", data, expected)
		}
	}
}

// BenchmarkFastSSEConnect is the fasthttp equivalent of BenchmarkSSEConnect.
func BenchmarkFastSSEConnect(b *testing.B) {
	srvURL := startFastServer(b)

	const poolSize = 256
	type kp struct {
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}
	pool := make([]kp, poolSize)
	for i := range pool {
		pool[i].pub, pool[i].priv, _ = ed25519.GenerateKey(nil)
	}

	var open [poolSize]*http.Response

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		k := pool[i%poolSize]
		resp := connectSSE(b, srvURL, k.pub, k.priv)
		if old := open[i%poolSize]; old != nil {
			old.Body.Close()
		}
		open[i%poolSize] = resp
	}

	b.StopTimer()
	for _, resp := range open {
		if resp != nil {
			resp.Body.Close()
		}
	}
}
