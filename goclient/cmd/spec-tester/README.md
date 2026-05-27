# Spec Tester

`spec-tester` is the protocol judge for client implementations. It starts a
known Go client, runs a candidate program, and passes the candidate two
positional arguments:

```text
serverURL testerPubkey
```

The candidate dials the tester first. After that succeeds, the tester dials the
candidate back. The tester validates both directions.

Before running it, start a local signaling server:

```bash
go run ./cmd/server
```

Then, from `goclient`, run the Go candidate:

```bash
go run ./cmd/spec-tester -- go run cmd/spec-candidate/main.go
```

Or run the browser JS candidate:

```bash
go run ./cmd/spec-tester/main.go  -- node "../jsclient/spec-candidate/browser-spec-candidate.mjs"
```

The tester checks that signaling follows the connection-flow spec:

- offers, answers, and ICE candidates are signed correctly
- answers are sent before ICE candidates
- answer signatures cover the exact offer SDP received over signaling
- ICE candidates use the expected session challenge
- the final WebRTC connection can open a data channel and echo a challenge pong

Failures include a bracketed invariant name, such as `[answer.before-ice]` or
`[offer.signature]`, followed by details about what failed.
