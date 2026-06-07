// Package connect implements a WebRTC signaling client that works with the
// connect relay server. It handles:
//   - Authenticated SSE subscription (ed25519 signed timestamp)
//   - Offer/answer/ICE exchange via signed relay messages
//
// The server is treated as an untrusted pipe. All message authenticity is
// verified client-side via ed25519 signatures before any SDP is applied.
// Auth is proven during the SDP exchange: the dialer generates a random
// challenge included in the offer, and all subsequent messages are signed over
// the challenge. Any verification failure closes the PeerConnection.
package connect

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	mathrand "math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/pion/webrtc/v4"
)

const (
	reconnectBaseMS = 1_000
	reconnectMaxMS  = 30_000
)

var defaultConfiguration = webrtc.Configuration{
	ICEServers: []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
	},
}

// options configures a Client.
type options struct {
	ServerURL     string
	Configuration webrtc.Configuration // defaults to Google STUN if empty
	SettingEngine *webrtc.SettingEngine
	PrivateKey    ed25519.PrivateKey // generated if nil
	// AcceptConnection is called after offer signature and timestamp verification,
	// before a PeerConnection is created or an answer sent. Return false to silently
	// drop the offer — no response is sent to the dialer, to avoid leaking whether
	// the key is active. If nil, all offers are denied.
	AcceptConnection func(remotePubkey string) bool
	// OnIncoming is called when an incoming offer has been verified and accepted,
	// before the answer is sent. Wire OnDataChannel and media track handlers here.
	// The PC may still be closed if a subsequent ICE candidate fails auth.
	OnIncoming func(pc *webrtc.PeerConnection, remotePubkey string)
	// OnSignal observes every raw signaling payload sent or received by this
	// client. It is informational only; callbacks cannot mutate or drop messages.
	OnSignal func(SignalEvent)
}

// Option is a functional option for configuring a Client.
type Option func(*options)

// WithServerURL sets the relay server URL.
func WithServerURL(url string) Option {
	return func(o *options) { o.ServerURL = url }
}

// WithConfiguration sets the WebRTC configuration (ICE servers, etc.).
func WithConfiguration(cfg webrtc.Configuration) Option {
	return func(o *options) { o.Configuration = cfg }
}

// WithSettingEngine sets the pion SettingEngine for advanced WebRTC tuning.
func WithSettingEngine(se *webrtc.SettingEngine) Option {
	return func(o *options) { o.SettingEngine = se }
}

// WithPrivateKey sets the ed25519 private key used for signing. If not set, a
// key is generated automatically.
func WithPrivateKey(key ed25519.PrivateKey) Option {
	return func(o *options) { o.PrivateKey = key }
}

// WithAcceptConnection sets the callback that decides whether to accept an
// incoming offer. Return false to silently drop the offer. If not set, all
// offers are denied.
func WithAcceptConnection(fn func(remotePubkey string) bool) Option {
	return func(o *options) { o.AcceptConnection = fn }
}

// WithOnIncoming sets the callback invoked when an incoming offer has been
// verified and accepted, before the answer is sent.
func WithOnIncoming(fn func(pc *webrtc.PeerConnection, remotePubkey string)) Option {
	return func(o *options) { o.OnIncoming = fn }
}

// WithOnSignal sets a callback that observes every raw signaling payload sent
// or received. It is informational only; the callback cannot mutate or drop
// messages.
func WithOnSignal(fn func(SignalEvent)) Option {
	return func(o *options) { o.OnSignal = fn }
}

// SignalDirection identifies where a signaling payload was observed.
type SignalDirection string

const (
	SignalInboundSSE   SignalDirection = "inbound-sse"
	SignalOutboundPOST SignalDirection = "outbound-post"
	_DefaultServerURL                  = "https://connect.peerwave.ai"
)

// SignalEvent is a passive observation of one wire payload.
type SignalEvent struct {
	Direction    SignalDirection
	RemotePubkey string
	Payload      string
}

// wireMessage is the signed envelope relayed through the server.
// base64url(JSON) keeps the payload newline-free for SSE framing.
type wireMessage struct {
	From      string `json:"from"`
	Data      string `json:"data"`
	Challenge string `json:"challenge"`
	Ts        string `json:"ts,omitempty"`
	Sig       string `json:"sig"`
}

// connKey is the composite key for the bus. Including the challenge
// allows a single remote pubkey to have multiple simultaneous connections.
type connKey struct {
	pubkey    string
	challenge [32]byte
}

func makeConnKey(pubkey string, challenge []byte) connKey {
	var k connKey
	k.pubkey = pubkey
	copy(k.challenge[:], challenge)
	return k
}

// Client connects to the relay server and manages WebRTC peer connections.
// The SSE loop dispatches incoming messages to per-connection goroutines via
// the bus; each connection runs its own sequential auth and ICE loop.
type Client struct {
	api  *webrtc.API
	opts options
	bus  *bus
	ctx  context.Context    // cancelled by Close
	stop context.CancelFunc // cancels ctx
}

// New creates a Client. Call Listen to start receiving incoming connections.
func New(opts ...Option) (*Client, error) {
	o := options{
		ServerURL:     _DefaultServerURL,
		Configuration: defaultConfiguration,
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.PrivateKey == nil {
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating key pair: %w", err)
		}
		o.PrivateKey = privKey
	}
	o.ServerURL = strings.TrimRight(o.ServerURL, "/")

	api := webrtc.NewAPI()
	if o.SettingEngine != nil {
		api = webrtc.NewAPI(webrtc.WithSettingEngine(*o.SettingEngine))
	}
	ctx, stop := context.WithCancel(context.Background())
	return &Client{api: api, opts: o, bus: newBus(), ctx: ctx, stop: stop}, nil
}

func (c *Client) pubKeyRaw() ed25519.PublicKey {
	return c.opts.PrivateKey.Public().(ed25519.PublicKey)
}

// Pubkey returns the base64url-encoded Ed25519 public key identifying this
// client on the relay. Share this so others can reach you via Dial.
func (c *Client) Pubkey() string {
	return base64.RawURLEncoding.EncodeToString(c.pubKeyRaw())
}

// Close stops all active connections and shuts down the client.
// Cancel the context passed to Listen to stop the SSE loop.
func (c *Client) Close() {
	c.stop()
	c.bus.clear()
}

// Dial opens a connection to the peer identified by remotePubkey (base64url).
// setup is called before the offer is created; add data channels, media tracks,
// and event handlers there. Dial returns after a verified answer is applied;
// the returned PC may still be ICE/DTLS connecting. Use context.WithTimeout
// to limit how long Dial waits for an authenticated answer.
func (c *Client) Dial(ctx context.Context, remotePubkey string, setup func(*webrtc.PeerConnection)) (*webrtc.PeerConnection, error) {
	if setup == nil {
		return nil, fmt.Errorf("a data channel or media track must be set up")
	}

	// 1. Generate session challenge.
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}
	key := makeConnKey(remotePubkey, challenge)

	// 2. Subscribe before sending so the answer can't arrive before we're ready.
	msgs, unsub := c.bus.subscribe(key)
	defer unsub()

	// 3. Create PeerConnection. iceCh receives local candidates as gathered;
	//    closing signals gathering complete. Candidates buffer here until the
	//    offer is posted (step 6), so none are sent before the remote knows the session.
	iceCh := make(chan string, 32)
	pc, err := c.makePC(iceCh)
	if err != nil {
		return nil, err
	}

	// 4. Let caller configure data channels/tracks (triggers SDP negotiation).
	setup(pc)

	// 5. Create and apply local offer.
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		pc.Close()
		return nil, err
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		pc.Close()
		return nil, err
	}
	desc := pc.LocalDescription()
	if desc == nil {
		pc.Close()
		return nil, fmt.Errorf("no local description after creating offer")
	}
	offerSdp := desc.SDP

	// 6. Send signed offer. Any candidates gathered so far are buffered in iceCh.
	if err := c.postOffer(ctx, remotePubkey, offerSdp, challenge, currentTsBytes()); err != nil {
		pc.Close()
		return nil, err
	}

	// 7. Wait for the authenticated answer.
	select {
	case msg := <-msgs:
		// 8. Verify answer timestamp.
		tsBytes, err := base64.RawURLEncoding.DecodeString(msg.Ts)
		if err != nil || parseTsBytes(tsBytes) == nil {
			pc.Close()
			return nil, fmt.Errorf("answer timestamp invalid or out of window")
		}
		// 9. Verify answer signature (covers challenge + ts + offerSdp + answerSdp).
		sender, sigBytes, err := parseSenderAndSig(msg.From, msg.Sig)
		if err != nil {
			pc.Close()
			return nil, err
		}
		if !ed25519.Verify(sender, answerPayload(challenge, tsBytes, offerSdp, msg.Data), sigBytes) {
			pc.Close()
			return nil, fmt.Errorf("invalid answer signature from %s", msg.From)
		}
		// 10. Apply the authenticated answer.
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: msg.Data}); err != nil {
			pc.Close()
			return nil, err
		}
	case <-ctx.Done():
		pc.Close()
		return nil, ctx.Err()
	case <-c.ctx.Done():
		pc.Close()
		return nil, fmt.Errorf("client closed")
	}

	// 11. Send local ICE candidates and apply remote ones until gathering is done.
	//     iceCh close signals gathering complete; return the ready PC.
	for {
		select {
		case candidate, ok := <-iceCh:
			if !ok {
				return pc, nil
			}
			_ = c.postICE(remotePubkey, candidate, challenge)
		case msg := <-msgs:
			if err := c.handleICE(pc, msg, challenge); err != nil {
				pc.Close()
				return nil, err
			}
		case <-ctx.Done():
			pc.Close()
			return nil, ctx.Err()
		case <-c.ctx.Done():
			pc.Close()
			return nil, fmt.Errorf("client closed")
		}
	}
}

// handleIncoming processes a new incoming offer. It runs in a goroutine
// spawned by routeSSEMessage, which subscribes to the bus first to ensure
// ICE candidates cannot arrive before this goroutine is ready to receive them.
//
// Protocol steps:
//  1. Validate offer timestamp (±30 s).
//  2. Verify offer signature (covers challenge + ts + our pubkey + offer SDP).
//  3. Call AcceptConnection — after sig check so untrusted keys can't drive policy.
//  4. Call OnIncoming so the caller can wire data channels before the answer.
//  5. Apply offer as remote description; create and apply answer as local description.
//  6. Send signed answer (covers challenge + ts + offerSdp + answerSdp).
//  7. Receive and apply ICE candidates until the client is closed.
func (c *Client) handleIncoming(msg wireMessage, challenge []byte, msgs <-chan wireMessage, unsub func()) {
	defer unsub()

	// 1. Validate offer timestamp.
	tsBytes, err := base64.RawURLEncoding.DecodeString(msg.Ts)
	if err != nil || parseTsBytes(tsBytes) == nil {
		return
	}

	// 2. Verify offer signature.
	sender, sigBytes, err := parseSenderAndSig(msg.From, msg.Sig)
	if err != nil {
		return
	}
	if !ed25519.Verify(sender, offerPayload(challenge, tsBytes, c.pubKeyRaw(), msg.Data), sigBytes) {
		return
	}

	// 3. AcceptConnection is called after signature verification.
	if c.opts.AcceptConnection == nil || !c.opts.AcceptConnection(msg.From) {
		return
	}

	// 4. Create PeerConnection. iceCh receives local candidates as gathered;
	//    closing signals gathering complete. Candidates buffer here until the
	//    answer is posted (step 6), so none are sent before the remote knows the session.
	iceCh := make(chan string, 32)
	pc, err := c.makePC(iceCh)
	if err != nil {
		return
	}

	// 5. OnIncoming: caller wires data channel and media handlers.
	if c.opts.OnIncoming != nil {
		c.opts.OnIncoming(pc, msg.From)
	}

	// 5. Apply offer and create answer.
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: msg.Data}); err != nil {
		pc.Close()
		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		pc.Close()
		return
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		pc.Close()
		return
	}
	desc := pc.LocalDescription()
	if desc == nil {
		pc.Close()
		return
	}

	// 6. Send signed answer. Any candidates gathered so far are buffered in iceCh.
	if err := c.postAnswer(msg.From, desc.SDP, challenge, msg.Data); err != nil {
		pc.Close()
		return
	}

	// 7. Send local ICE candidates and apply remote ones until gathering is done.
	//    iceCh close signals gathering complete.
	for {
		select {
		case candidate, ok := <-iceCh:
			if !ok {
				return
			}
			_ = c.postICE(msg.From, candidate, challenge)
		case iceMsg, ok := <-msgs:
			if !ok {
				return
			}
			if err := c.handleICE(pc, iceMsg, challenge); err != nil {
				pc.Close()
				return
			}
		case <-c.ctx.Done():
			return
		}
	}
}

// handleICE verifies the ICE candidate signature and adds the candidate.
func (c *Client) handleICE(pc *webrtc.PeerConnection, msg wireMessage, challenge []byte) error {
	sender, sigBytes, err := parseSenderAndSig(msg.From, msg.Sig)
	if err != nil {
		return err
	}
	if !ed25519.Verify(sender, icePayload(challenge, msg.Data), sigBytes) {
		return fmt.Errorf("invalid ICE signature from %s", msg.From)
	}
	var init webrtc.ICECandidateInit
	if err := json.Unmarshal([]byte(msg.Data), &init); err != nil {
		return fmt.Errorf("parsing ICE candidate: %w", err)
	}
	return pc.AddICECandidate(init)
}

// makePC creates a new PeerConnection wired to iceCh. ICE candidates are sent
// to iceCh as they are gathered; when gathering completes (OnICECandidate fires
// with nil), iceCh is closed. The caller controls when to start draining iceCh
// — candidates buffer there until the offer or answer has been posted.
// Non-blocking sends are used so a slow caller cannot stall ICE gathering.
func (c *Client) makePC(iceCh chan<- string) (*webrtc.PeerConnection, error) {
	pc, err := c.api.NewPeerConnection(c.opts.Configuration)
	if err != nil {
		return nil, fmt.Errorf("creating peer connection: %w", err)
	}
	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			close(iceCh)
			return
		}
		b, err := json.Marshal(candidate.ToJSON())
		if err != nil {
			return
		}
		select {
		case iceCh <- string(b):
		default:
		}
	})
	return pc, nil
}

// parseSenderAndSig decodes the sender public key and signature from a message.
func parseSenderAndSig(from, sig string) (ed25519.PublicKey, []byte, error) {
	sender, err := base64.RawURLEncoding.DecodeString(from)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid sender pubkey")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid signature")
	}
	return ed25519.PublicKey(sender), sigBytes, nil
}

func (c *Client) signAndSend(ctx context.Context, remotePubkey string, payload []byte, msg wireMessage) error {
	msg.Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.opts.PrivateKey, payload))
	return c.send(ctx, remotePubkey, msg)
}

func (c *Client) postOffer(ctx context.Context, remotePubkey, offerSdp string, challenge, ts []byte) error {
	recipientBytes, err := base64.RawURLEncoding.DecodeString(remotePubkey)
	if err != nil {
		return fmt.Errorf("decoding remote pubkey: %w", err)
	}
	return c.signAndSend(ctx, remotePubkey, offerPayload(challenge, ts, recipientBytes, offerSdp), wireMessage{
		From:      c.Pubkey(),
		Data:      offerSdp,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Ts:        base64.RawURLEncoding.EncodeToString(ts),
	})
}

func (c *Client) postAnswer(remotePubkey, answerSdp string, challenge []byte, offerSdp string) error {
	ts := currentTsBytes()
	return c.signAndSend(c.ctx, remotePubkey, answerPayload(challenge, ts, offerSdp, answerSdp), wireMessage{
		From:      c.Pubkey(),
		Data:      answerSdp,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Ts:        base64.RawURLEncoding.EncodeToString(ts),
	})
}

func (c *Client) postICE(remotePubkey, candidateJSON string, challenge []byte) error {
	return c.signAndSend(c.ctx, remotePubkey, icePayload(challenge, candidateJSON), wireMessage{
		From:      c.Pubkey(),
		Data:      candidateJSON,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
	})
}

func (c *Client) send(ctx context.Context, remotePubkey string, msg wireMessage) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	body := base64.RawURLEncoding.EncodeToString(b)
	if c.opts.OnSignal != nil {
		c.opts.OnSignal(SignalEvent{SignalOutboundPOST, remotePubkey, body})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.opts.ServerURL+"/"+remotePubkey, strings.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("relay POST failed: %s", resp.Status)
	}
	return nil
}

// Listen opens an authenticated SSE stream and delivers incoming messages
// until ctx is cancelled. It reconnects automatically on transient failures.
// Returns ctx.Err() when ctx is cancelled.
func (c *Client) Listen(ctx context.Context) error {
	path := "/" + c.Pubkey()
	backoff := time.Duration(reconnectBaseMS) * time.Millisecond

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := c.connectSSE(ctx, path)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			backoff = reconnectBaseMS * time.Millisecond
		} else {
			backoff = min(backoff*2, reconnectMaxMS*time.Millisecond)
		}
		jitter := time.Duration(mathrand.IntN(1000)) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff + jitter):
		}
	}
}

// connectSSE opens one SSE connection and reads until it closes or ctx is
// cancelled. Returns nil on clean close, error on failure.
func (c *Client) connectSSE(ctx context.Context, path string) error {
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(time.Now().Unix()))
	sig := ed25519.Sign(c.opts.PrivateKey, ssePayload(tsBytes))
	combined := append(sig, tsBytes...)

	url := c.opts.ServerURL + path + "?sig=" + base64.RawURLEncoding.EncodeToString(combined)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSE connect: %s", resp.Status)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := line[len("data: "):]
		if c.opts.OnSignal != nil {
			c.opts.OnSignal(SignalEvent{SignalInboundSSE, c.Pubkey(), payload})
		}
		c.routeSSEMessage(payload)
	}
	return scanner.Err()
}

// routeSSEMessage decodes a raw SSE payload and routes it to the appropriate
// per-connection goroutine via the bus. If no goroutine is waiting for this
// (from, challenge) pair, the message is a new incoming offer: subscribe first
// (so subsequent ICE candidates aren't missed) then spawn a goroutine.
func (c *Client) routeSSEMessage(line string) {
	raw, err := base64.RawURLEncoding.DecodeString(line)
	if err != nil {
		return
	}
	var msg wireMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return
	}
	if msg.From == "" || msg.Data == "" || msg.Challenge == "" || msg.Sig == "" {
		return
	}
	challenge, err := base64.RawURLEncoding.DecodeString(msg.Challenge)
	if err != nil || len(challenge) != 32 {
		return
	}

	key := makeConnKey(msg.From, challenge)
	if c.bus.dispatch(key, msg) {
		// Delivered to an existing Dial or handleIncoming goroutine.
		return
	}
	// Unknown (from, challenge): treat as a new incoming offer.
	// Subscribe before spawning so ICE candidates arriving immediately after
	// the offer can't be lost before handleIncoming starts reading.
	msgs, unsub := c.bus.subscribe(key)
	go c.handleIncoming(msg, challenge, msgs, unsub)
}
