# Connect

> [!WARNING]
> This project includes an experimental authentication flow for WebRTC signaling messages. It has not been professionally audited, formally verified, or battle-tested against real adversaries. Do not treat it as a security product. Review the design, read the code, run your own tests, and use it at your own risk.

Connect is a small WebRTC signaling relay and matching client libraries. The server is intentionally a dumb pipe: clients POST opaque bytes to `/{pubkey}`, and the server forwards those bytes to the active Server-Sent Events stream for that pubkey. The server does not parse SDP, does not inspect ICE candidates, does not build envelopes, and does not own application semantics.

The goal is to keep the relay simple enough that protocol changes live in clients, not in the server. Client libraries are responsible for signing, verifying, session binding, authorization policy, and deciding what an incoming message means.

## What This Is

- A Go signaling server for relaying small opaque WebRTC signaling payloads.
- A TypeScript client library in `jsclient/`.
- A Go client library in `goclient/`.
- An example browser chat app in `jsclient/example/`.
- Terraform modules under `terraform/` showing one way to run the relay on AWS with Cloudflare DNS registration.

## What This Is Not

- Not a TURN server.
- Not a WebRTC media or data relay.
- Not a user registry, identity provider, or key directory.
- Not an audited authentication system.
- Not a general message broker. Payloads are capped at 8 KB and are meant only for signaling.

## Design Intent

The server owns only transport mechanics:

- `GET /{pubkey}` opens an authenticated SSE stream for that pubkey.
- `POST /{pubkey}` relays the request body to that stream.
- Only one active listener is allowed per pubkey.
- POST bodies are rejected if they contain `\n` or `\r`, because payloads are written directly into SSE frames.
- POST bodies are size-limited to keep this as a signaling channel, not a data channel.

Authentication is asymmetric by design. Subscribing to a pubkey requires an Ed25519 signature so callers cannot squat on someone else's receive channel. Sending to a pubkey has no server-side authentication because the server does not know which senders a recipient expects. Sender authentication is a client-layer responsibility.

## Authentication Model

The client libraries treat the signaling relay as untrusted. Offers, answers, and ICE candidates are carried in client-owned JSON envelopes encoded as `base64url(JSON)`. The envelopes include the sender pubkey, payload data, a session challenge, timestamps where needed, and Ed25519 signatures.

At a high level:

1. The dialer signs an offer with a fresh random challenge, timestamp, intended recipient pubkey, and offer SDP.
2. The answerer verifies the offer before applying the remote description.
3. The answerer signs the answer over the same challenge, a fresh timestamp, the exact offer SDP it received, and the answer SDP.
4. The dialer verifies the answer before applying it.
5. ICE candidates are signed and bound to the session challenge.

Any verification failure closes the relevant `RTCPeerConnection`.

Read [connection-flow.md](connection-flow.md) for the full sequence and security rationale. That document is design documentation, not an audit.

## Creating New Clients

New client libraries should preserve the server's dumb-pipe model: keep SDP,
ICE, signing, session state, authorization, and cleanup semantics in the client,
not the relay.

Use [connection-flow.md](connection-flow.md) as the protocol spec, and run the
[spec tester](goclient/cmd/spec-tester/README.md) against new implementations.
The tester exercises both dialer and answerer behavior, checks signing and
message ordering invariants, and verifies that an authenticated WebRTC
connection can answer a challenge over a data channel.
