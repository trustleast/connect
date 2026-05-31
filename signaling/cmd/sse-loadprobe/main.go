package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var sseAuthDomain = []byte("connect.sse.v1\x00")

type connHold struct {
	pubkey     string
	body       io.ReadCloser
	deliveries chan string
	postMu     *sync.Mutex
}

type connSet struct {
	mu    sync.RWMutex
	conns []connHold
	next  uint64
}

func (s *connSet) add(c connHold) {
	s.mu.Lock()
	s.conns = append(s.conns, c)
	s.mu.Unlock()
}

func (s *connSet) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.conns)
}

func (s *connSet) getRoundRobin() (connHold, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.conns) == 0 {
		return connHold{}, false
	}
	idx := atomic.AddUint64(&s.next, 1) - 1
	return s.conns[int(idx%uint64(len(s.conns)))], true
}

func (s *connSet) closeAll() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.conns {
		_ = c.body.Close()
	}
}

type postStats struct {
	attempted int64
	ok        int64
	errors    int64
	latencies []time.Duration
}

func (s postStats) avg() time.Duration {
	if s.ok == 0 {
		return 0
	}
	var total time.Duration
	for _, lat := range s.latencies {
		total += lat
	}
	return total / time.Duration(s.ok)
}

func (s postStats) percentile(p float64) time.Duration {
	if len(s.latencies) == 0 {
		return 0
	}
	idx := int(float64(len(s.latencies)-1) * p)
	return s.latencies[idx]
}

func durationMillis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

type postRecorder struct {
	attempted atomic.Int64
	ok        atomic.Int64
	errors    atomic.Int64
	mu        sync.Mutex
	latencies []time.Duration
}

func (r *postRecorder) snapshotAndReset() postStats {
	r.mu.Lock()
	latencies := append([]time.Duration(nil), r.latencies...)
	r.latencies = r.latencies[:0]
	r.mu.Unlock()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	return postStats{
		attempted: r.attempted.Swap(0),
		ok:        r.ok.Swap(0),
		errors:    r.errors.Swap(0),
		latencies: latencies,
	}
}

func (r *postRecorder) record(latency time.Duration, err error) {
	r.attempted.Add(1)
	if err != nil {
		r.errors.Add(1)
		return
	}
	r.ok.Add(1)
	r.mu.Lock()
	r.latencies = append(r.latencies, latency)
	r.mu.Unlock()
}

type csvWriter struct {
	w io.Writer
}

func (c csvWriter) header() {
	fmt.Fprintln(c.w, "event,mode,sse_conns,target_sse_rate,target_post_rate,sse_attempted,sse_failed,post_attempted,post_ok,post_errors,post_avg_ms,post_p50_ms,post_p95_ms,post_p99_ms,elapsed_ms,reason")
}

func (c csvWriter) row(event, mode string, sseConns int, sseRate, postRate float64, sseAttempted, sseFailed int64, posts postStats, elapsed time.Duration, reason string) {
	fmt.Fprintf(c.w, "%s,%s,%d,%.2f,%.2f,%d,%d,%d,%d,%d,%.3f,%.3f,%.3f,%.3f,%d,%s\n",
		event,
		mode,
		sseConns,
		sseRate,
		postRate,
		sseAttempted,
		sseFailed,
		posts.attempted,
		posts.ok,
		posts.errors,
		durationMillis(posts.avg()),
		durationMillis(posts.percentile(0.50)),
		durationMillis(posts.percentile(0.95)),
		durationMillis(posts.percentile(0.99)),
		elapsed.Milliseconds(),
		reason,
	)
}

func main() {
	var (
		mode         = flag.String("mode", "conn-ramp", "conn-ramp or post-ramp")
		target       = flag.String("target", "http://127.0.0.1:8080", "server base URL")
		openTimeout  = flag.Duration("open-timeout", 10*time.Second, "timeout for each SSE open")
		openParallel = flag.Int("open-parallel", 500, "max concurrent SSE open attempts")
		postSize     = flag.Int("post-size", 512, "POST body size in bytes")
		postTimeout  = flag.Duration("post-timeout", 10*time.Second, "max time for POST to appear on SSE")
		postParallel = flag.Int("post-parallel", 500, "max concurrent POST attempts")

		sseRate      = flag.Float64("sse-rate", 250, "conn-ramp: SSE opens per second")
		sseMax       = flag.Int("sse-max", 50000, "conn-ramp: max SSE connections")
		sampleEvery  = flag.Duration("sample", 5*time.Second, "sample interval")
		stopFailures = flag.Int("stop-failures", 25, "conn-ramp: stop after this many consecutive open failures")
		postRate     = flag.Float64("post-rate", 0, "conn-ramp: constant POST/s during SSE ramp")

		sseCount        = flag.Int("sse-count", 1000, "post-ramp: established SSE count")
		postRateStart   = flag.Float64("post-rate-start", 1000, "post-ramp: first POST/s rate")
		postRateStep    = flag.Float64("post-rate-step", 1000, "post-ramp: POST/s increment")
		postRateMax     = flag.Float64("post-rate-max", 10000, "post-ramp: max POST/s rate")
		postStepDur     = flag.Duration("post-step-duration", 15*time.Second, "post-ramp: duration per POST rate")
		postMaxErrRatio = flag.Float64("post-stop-error-ratio", 0.05, "post-ramp: stop rate ramp above this error ratio")
	)
	flag.Parse()

	if *mode != "conn-ramp" && *mode != "post-ramp" {
		fatalf("-mode must be conn-ramp or post-ramp")
	}
	if *openParallel <= 0 || *postParallel <= 0 {
		fatalf("parallelism must be positive")
	}
	if *postSize <= 0 || *sseMax <= 0 {
		fatalf("sizes and limits must be positive")
	}

	targetURL := strings.TrimRight(*target, "/")
	csv := csvWriter{w: io.Writer(os.Stdout)}
	csv.header()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			ForceAttemptHTTP2:   false,
			DisableCompression:  true,
			MaxIdleConnsPerHost: max(*sseMax+*postParallel+100, *openParallel),
			IdleConnTimeout:     24 * time.Hour,
			DialContext: (&net.Dialer{
				Timeout:   *openTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var conns connSet
	var readers sync.WaitGroup
	var readFailures atomic.Int64

	switch *mode {
	case "conn-ramp":
		runConnRamp(ctx, csv, client, targetURL, &conns, &readers, &readFailures, *sseRate, *sseMax, *openParallel, *sampleEvery, *stopFailures, *postRate, *postSize, *postTimeout, *postParallel)
	case "post-ramp":
		runPostRamp(ctx, csv, client, targetURL, &conns, &readers, &readFailures, *sseCount, *openParallel, *postRateStart, *postRateStep, *postRateMax, *postStepDur, *postMaxErrRatio, *postSize, *postTimeout, *postParallel)
	}

	conns.closeAll()
	readers.Wait()
	if readFailures.Load() > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d SSE readers ended with errors\n", readFailures.Load())
	}
}

func runConnRamp(ctx context.Context, csv csvWriter, client *http.Client, targetURL string, conns *connSet, readers *sync.WaitGroup, readFailures *atomic.Int64, sseRate float64, sseMax, openParallel int, sampleEvery time.Duration, stopFailures int, postRate float64, postSize int, postTimeout time.Duration, postParallel int) {
	start := time.Now()
	recorder := &postRecorder{}
	postCancel := func() {}
	if postRate > 0 {
		postCtx, cancel := context.WithCancel(ctx)
		postCancel = cancel
		go runPostGenerator(postCtx, client, targetURL, conns, postRate, postSize, postTimeout, postParallel, recorder)
	}
	defer postCancel()

	openInterval := time.Duration(float64(time.Second) / sseRate)
	if openInterval <= 0 {
		openInterval = time.Nanosecond
	}
	openTick := time.NewTicker(openInterval)
	defer openTick.Stop()
	sampleTick := time.NewTicker(sampleEvery)
	defer sampleTick.Stop()

	sem := make(chan struct{}, openParallel)
	results := make(chan error, openParallel*2)
	var wg sync.WaitGroup
	var attempted int64
	var failed int64
	consecutiveFailures := 0
	reason := "max"

	drain := func() {
		for {
			select {
			case err := <-results:
				if err != nil {
					failed++
					consecutiveFailures++
				} else {
					consecutiveFailures = 0
				}
			default:
				return
			}
		}
	}

	for conns.len() < sseMax {
		drain()
		if consecutiveFailures >= stopFailures {
			reason = "failures"
			break
		}
		select {
		case <-ctx.Done():
			reason = "context"
			goto done
		case <-sampleTick.C:
			drain()
			csv.row("sample", "conn-ramp", conns.len(), sseRate, postRate, attempted, failed, recorder.snapshotAndReset(), time.Since(start), "")
		case <-openTick.C:
			select {
			case sem <- struct{}{}:
				attempted++
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					c, err := openSSE(ctx, client, targetURL)
					if err == nil {
						conns.add(c)
						readers.Add(1)
						go func() {
							defer readers.Done()
							if err := readSSE(c); err != nil {
								readFailures.Add(1)
							}
						}()
					}
					results <- err
				}()
			default:
				failed++
				consecutiveFailures++
			}
		}
	}

done:
	wg.Wait()
	drain()
	csv.row("final", "conn-ramp", conns.len(), sseRate, postRate, attempted, failed, recorder.snapshotAndReset(), time.Since(start), reason)
}

func runPostRamp(ctx context.Context, csv csvWriter, client *http.Client, targetURL string, conns *connSet, readers *sync.WaitGroup, readFailures *atomic.Int64, sseCount int, openParallel int, rateStart, rateStep, rateMax float64, stepDuration time.Duration, stopErrorRatio float64, postSize int, postTimeout time.Duration, postParallel int) {
	start := time.Now()
	need := sseCount - conns.len()
	if need > 0 {
		fmt.Fprintf(os.Stderr, "opening %d SSE connections to reach %d\n", need, sseCount)
		if err := openN(ctx, client, targetURL, conns, readers, readFailures, need, openParallel); err != nil {
			fatalf("open SSE: %v", err)
		}
	}
	csv.row("sse_ready", "post-ramp", conns.len(), 0, 0, int64(conns.len()), 0, postStats{}, time.Since(start), "")

	for rate := rateStart; rate <= rateMax; rate += rateStep {
		recorder := &postRecorder{}
		postCtx, cancel := context.WithCancel(ctx)
		go runPostGenerator(postCtx, client, targetURL, conns, rate, postSize, postTimeout, postParallel, recorder)
		time.Sleep(stepDuration)
		cancel()
		time.Sleep(100 * time.Millisecond)
		stats := recorder.snapshotAndReset()
		reason := ""
		if stats.attempted > 0 && float64(stats.errors)/float64(stats.attempted) > stopErrorRatio {
			reason = "error_ratio"
		}
		csv.row("post_step", "post-ramp", conns.len(), 0, rate, int64(conns.len()), 0, stats, time.Since(start), reason)
		if reason != "" {
			break
		}
	}
}

func runPostGenerator(ctx context.Context, client *http.Client, targetURL string, conns *connSet, rate float64, postSize int, timeout time.Duration, parallel int, recorder *postRecorder) {
	interval := time.Duration(float64(time.Second) / rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	sem := make(chan struct{}, parallel)
	var seq atomic.Uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			c, ok := conns.getRoundRobin()
			if !ok {
				continue
			}
			select {
			case sem <- struct{}{}:
				n := seq.Add(1)
				go func(conn connHold, seq uint64) {
					defer func() { <-sem }()
					body := makePostBody(postSize, int(seq))
					t0 := time.Now()
					err := postOnceAndWait(client, targetURL, conn, body, timeout)
					recorder.record(time.Since(t0), err)
				}(c, n)
			default:
				recorder.record(0, fmt.Errorf("post backlog saturated"))
			}
		}
	}
}

func openN(ctx context.Context, client *http.Client, targetURL string, conns *connSet, readers *sync.WaitGroup, readFailures *atomic.Int64, count, parallel int) error {
	sem := make(chan struct{}, parallel)
	results := make(chan openResult, parallel)
	var wg sync.WaitGroup

	for i := 0; i < count; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := openSSE(ctx, client, targetURL)
			results <- openResult{conn: c, err: err}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		if res.err != nil {
			return res.err
		}
		conns.add(res.conn)
		readers.Add(1)
		go func(c connHold) {
			defer readers.Done()
			if err := readSSE(c); err != nil {
				readFailures.Add(1)
			}
		}(res.conn)
	}
	return nil
}

type openResult struct {
	conn connHold
	err  error
}

func openSSE(ctx context.Context, client *http.Client, targetURL string) (connHold, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return connHold{}, err
	}
	pubStr := base64.RawURLEncoding.EncodeToString(pub)

	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(time.Now().Unix()))
	sig := ed25519.Sign(priv, append([]byte(sseAuthDomain), tsBytes...))
	combined := append(sig, tsBytes...)
	sigParam := url.QueryEscape(base64.RawURLEncoding.EncodeToString(combined))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL+"/"+pubStr+"?sig="+sigParam, nil)
	if err != nil {
		return connHold{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return connHold{}, err
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		return connHold{}, fmt.Errorf("SSE status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return connHold{pubkey: pubStr, body: resp.Body, deliveries: make(chan string, 1024), postMu: &sync.Mutex{}}, nil
}

func readSSE(c connHold) error {
	defer close(c.deliveries)
	sc := bufio.NewScanner(c.body)
	for sc.Scan() {
		if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			c.deliveries <- data
		}
	}
	return sc.Err()
}

func makePostBody(size int, seq int) []byte {
	prefix := fmt.Sprintf("loadprobe.%d.", seq)
	if len(prefix) >= size {
		return []byte(prefix[:size])
	}
	body := make([]byte, size)
	copy(body, prefix)
	for i := len(prefix); i < len(body); i++ {
		body[i] = 'A'
	}
	return body
}

func postOnceAndWait(client *http.Client, targetURL string, conn connHold, body []byte, timeout time.Duration) error {
	conn.postMu.Lock()
	defer conn.postMu.Unlock()

	expected := string(body)
	req, err := http.NewRequest(http.MethodPost, targetURL+"/"+conn.pubkey, bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("POST status %d", resp.StatusCode)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case got, ok := <-conn.deliveries:
			if !ok {
				return fmt.Errorf("SSE stream closed before delivery")
			}
			if got == expected {
				return nil
			}
		case <-timer.C:
			return fmt.Errorf("timed out waiting for SSE delivery")
		}
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
