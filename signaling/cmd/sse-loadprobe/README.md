# SSE Load Probe

Focused load harness for two questions:

1. How many SSE connections can one host absorb while connections open at a
   steady rate, with optional steady POST traffic?
2. How much end-to-end POST throughput can the server sustain with different
   numbers of already-open SSE connections?

All POST latency is end-to-end: before the HTTP POST starts until the target SSE
reader receives the exact payload.

## Connection Ramp

```bash
env GOCACHE="$PWD/.gocache" GOTMPDIR="$PWD/.gotmp" \
go run ./signaling/cmd/sse-loadprobe \
  -mode conn-ramp \
  -target https://connect.example.com \
  -sse-rate 250 \
  -sse-max 50000 \
  -post-rate 1000 \
  -sample 5s \
  -stop-failures 25 \
  -open-parallel 500 \
  -post-parallel 500 \
  -out load-conn-ramp.csv
```

Run this repeatedly with different `-sse-rate` and `-post-rate` values to map
max connections under different SSE:POST load ratios.

## POST Ramp

```bash
env GOCACHE="$PWD/.gocache" GOTMPDIR="$PWD/.gotmp" \
go run ./signaling/cmd/sse-loadprobe \
  -mode post-ramp \
  -target https://connect.example.com \
  -sse-counts 100,1000,5000 \
  -post-rate-start 1000 \
  -post-rate-step 1000 \
  -post-rate-max 20000 \
  -post-step-duration 15s \
  -post-stop-error-ratio 0.01 \
  -post-parallel 1000 \
  -out load-post-ramp.csv
```

The CSV schema is shared between modes:

```text
event,mode,sse_conns,target_sse_rate,target_post_rate,sse_attempted,sse_failed,post_attempted,post_ok,post_errors,post_avg_ms,post_p50_ms,post_p95_ms,post_p99_ms,elapsed_ms,reason
```
