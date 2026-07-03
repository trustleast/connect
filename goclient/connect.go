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
	"log"
	mathrand "math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
)

const (
	_ReconnectBaseMS  = 1_000
	_ReconnectMaxMS   = 30_000
	_ConnCleanupSecs  = 5
	_DefaultServerURL = "https://connect.peerwave.ai"

	SignalInboundSSE   SignalDirection = "inbound-sse"
	SignalOutboundPOST SignalDirection = "outbound-post"
)

var defaultConfiguration = webrtc.Configuration{
	ICEServers: []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
	},
}

// options configures a Client.
type options struct {
	ServerURL     string
	Configuration webrtc.Configuration
	SettingEngine *webrtc.SettingEngine
	PrivateKey    ed25519.PrivateKey
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
	return func(o *options) {
		if url != "" {
			o.ServerURL = url
		}
	}
}

// WithConfiguration sets the WebRTC configuration (ICE servers, etc.).
func WithConfiguration(cfg webrtc.Configuration) Option {
	return func(o *options) { o.Configuration = cfg }
}

// WithSettingEngine sets the pion SettingEngine for advanced WebRTC tuning.
func WithSettingEngine(se *webrtc.SettingEngine) Option {
	return func(o *options) { o.SettingEngine = se }
}

// WithPrivateKey sets the ed25519 private key. If not set, one is generated.
func WithPrivateKey(key ed25519.PrivateKey) Option {
	return func(o *options) { o.PrivateKey = key }
}

// WithAcceptConnection sets the callback that decides whether to accept an
// incoming offer. Return false to silently drop. If not set, all offers are
// denied.
func WithAcceptConnection(fn func(remotePubkey string) bool) Option {
	return func(o *options) { o.AcceptConnection = fn }
}

// WithOnIncoming sets the callback invoked when an incoming offer is verified
// and accepted, before the answer is sent.
func WithOnIncoming(fn func(pc *webrtc.PeerConnection, remotePubkey string)) Option {
	return func(o *options) { o.OnIncoming = fn }
}

// WithOnSignal sets a passive observer for every raw signaling payload sent or
// received. It is informational only; the callback cannot mutate or drop
// messages.
func WithOnSignal(fn func(SignalEvent)) Option {
	return func(o *options) { o.OnSignal = fn }
}

// SignalDirection identifies where a signaling payload was observed.
type SignalDirection string

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
	Token     string `json:"token,omitempty"` // sender's node routing token, not signed
}

// redirectCacheTransport is an http.RoundTripper that caches 308 redirect
// responses. On a cache hit it returns a synthetic 308 without a network
// round-trip; http.Client's built-in redirect logic then follows it directly
// to the node, skipping the entry-node hop entirely.
type redirectCacheTransport struct {
	mu    sync.RWMutex
	cache map[string]redirectEntry
}

type redirectEntry struct {
	location  string
	expiresAt time.Time
}

func (t *redirectCacheTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.URL.String()

	t.mu.RLock()
	entry, ok := t.cache[key]
	t.mu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		log.Printf("[signaling] redirect cache hit: %s → %s", key, entry.location)
		return &http.Response{
			StatusCode: http.StatusPermanentRedirect,
			Header:     http.Header{"Location": []string{entry.location}},
			Body:       http.NoBody,
		}, nil
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusPermanentRedirect {
		return resp, err
	}

	// Cache the redirect using the TTL from Cache-Control: max-age=N.
	location := resp.Header.Get("Location")
	if maxAge := parseMaxAge(resp.Header.Get("Cache-Control")); location != "" && maxAge > 0 {
		t.mu.Lock()
		t.cache[key] = redirectEntry{location: location, expiresAt: time.Now().Add(maxAge)}
		t.mu.Unlock()
	}
	return resp, nil
}

// parseMaxAge extracts the max-age seconds from a Cache-Control header value.
func parseMaxAge(cc string) time.Duration {
	for _, part := range strings.Split(cc, ",") {
		if after, ok := strings.CutPrefix(strings.TrimSpace(part), "max-age="); ok {
			if n, err := strconv.Atoi(after); err == nil && n > 0 {
				return time.Duration(n) * time.Second
			}
		}
	}
	return 0
}

// connKey is the composite key for the conns map. Including the challenge
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
type Client struct {
	api        *webrtc.API
	opts       options
	httpClient *http.Client
	conns      sync.Map   // connKey → *connState
	nodeToken  atomic.Value // string; set from raw token data line on SSE connect
}

func (c *Client) getNodeToken() string {
	v := c.nodeToken.Load()
	if v == nil {
		return ""
	}
	return v.(string)
}

// connState holds per-connection state.
//
// For outbound connections (created by Dial): authDone is a buffered channel
// that receives nil on successful auth or an error on failure; offerSdp is the
// SDP sent with the offer, written before the connState is stored in conns and
// read only after it is loaded, so no additional synchronization is needed.
//
// For inbound connections (created by handleOffer): authDone and offerSdp are
// zero; no goroutine is waiting on auth. dialerToken holds the routing token
// extracted from the offer, used as X-Node-Token on replies back to the dialer.
type connState struct {
	pc          *webrtc.PeerConnection
	authDone    chan error // buffered(1); nil for inbound connections
	offerSdp    string    // set before conns.Store; empty for inbound connections
	dialerToken string    // routing token from offer; empty for outbound connections
}

// sendAuth signals the auth channel if set. Non-blocking: if a prior signal
// was already sent (e.g. timeout fired before auth completed), this is a no-op.
func sendAuth(ch chan error, err error) {
	if ch == nil {
		return
	}
	select {
	case ch <- err:
	default:
	}
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

func (c *Client) pubKeyRaw() ed25519.PublicKey {
	return c.opts.PrivateKey.Public().(ed25519.PublicKey)
}

// Pubkey returns the base64url-encoded Ed25519 public key identifying this
// client on the relay. Share this so others can reach you via Dial.
func (c *Client) Pubkey() string {
	return base64.RawURLEncoding.EncodeToString(c.pubKeyRaw())
}

// New creates a Client. Call Listen to start receiving incoming connections.
func New(optFuncs ...Option) (*Client, error) {
	opts := options{
		ServerURL:     _DefaultServerURL,
		Configuration: defaultConfiguration,
	}
	for _, fn := range optFuncs {
		fn(&opts)
	}

	if opts.PrivateKey == nil {
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating key pair: %w", err)
		}
		opts.PrivateKey = privKey
	}
	opts.ServerURL = strings.TrimRight(opts.ServerURL, "/")

	api := webrtc.NewAPI()
	if opts.SettingEngine != nil {
		api = webrtc.NewAPI(webrtc.WithSettingEngine(*opts.SettingEngine))
	}
	return &Client{
		api:  api,
		opts: opts,
		httpClient: &http.Client{
			Transport: &redirectCacheTransport{cache: make(map[string]redirectEntry)},
		},
	}, nil
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

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}

	pc, releaseICE, err := c.makePC(ctx, remotePubkey, challenge, "")
	if err != nil {
		return nil, err
	}

	setup(pc)

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

	// Store in conns with offerSdp set before posting the offer, so that when
	// the answer arrives on the SSE stream it can be verified immediately.
	key := makeConnKey(remotePubkey, challenge)
	state := &connState{pc: pc, authDone: make(chan error, 1), offerSdp: desc.SDP}
	c.conns.Store(key, state)

	if err := c.postOffer(ctx, remotePubkey, desc.SDP, challenge, currentTsBytes()); err != nil {
		c.closeConnWithError(key, state, err)
		return nil, err
	}
	releaseICE()

	select {
	case err := <-state.authDone:
		if err != nil {
			return nil, err
		}
		return pc, nil
	case <-ctx.Done():
		err := ctx.Err()
		c.closeConnWithError(key, state, err)
		return nil, err
	}
}

// Close closes all peer connections. Cancel the context passed to Listen to
// stop the SSE loop.
func (c *Client) Close() {
	c.conns.Range(func(_, v any) bool {
		state := v.(*connState)
		sendAuth(state.authDone, fmt.Errorf("client closed"))
		state.pc.Close()
		return true
	})
	c.conns.Clear()
}

func (c *Client) closeConn(key connKey, state *connState) {
	state.pc.Close()
	c.conns.Delete(key)
}

func (c *Client) closeConnWithError(key connKey, state *connState, err error) {
	sendAuth(state.authDone, err)
	c.closeConn(key, state)
}

// makePC creates a new PeerConnection and buffers ICE candidates until
// releaseICE is called. Call releaseICE after the local description is set
// and the offer/answer is sent to the remote peer. dialerToken is included
// as X-Node-Token on outgoing ICE POST requests to route to the remote node.
func (c *Client) makePC(ctx context.Context, remotePubkey string, challenge []byte, dialerToken string) (*webrtc.PeerConnection, func(), error) {
	pc, err := c.api.NewPeerConnection(c.opts.Configuration)
	if err != nil {
		return nil, nil, fmt.Errorf("creating peer connection: %w", err)
	}

	var mu sync.Mutex
	released := false
	var pending []string

	send := func(candidateJSON string) {
		_ = c.postICE(ctx, remotePubkey, candidateJSON, challenge, dialerToken)
	}

	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		b, err := json.Marshal(candidate.ToJSON())
		if err != nil {
			return
		}
		j := string(b)
		mu.Lock()
		if !released {
			pending = append(pending, j)
			mu.Unlock()
			return
		}
		mu.Unlock()
		send(j)
	})

	return pc, func() {
		mu.Lock()
		if released {
			mu.Unlock()
			return
		}
		released = true
		flushed := pending
		pending = nil
		mu.Unlock()
		for _, j := range flushed {
			send(j)
		}
	}, nil
}

// signAndSend signs the given payload with the client's private key and sends
// the message. msg.Sig must be empty; it is filled in by this function.
// nodeToken, if non-empty, is sent as X-Node-Token to route to the remote node.
func (c *Client) signAndSend(ctx context.Context, remotePubkey string, payload []byte, msg wireMessage, nodeToken string) error {
	msg.Sig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.opts.PrivateKey, payload))
	return c.send(ctx, remotePubkey, msg, nodeToken)
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
		Token:     c.getNodeToken(),
	}, "")
}

func (c *Client) postAnswer(ctx context.Context, remotePubkey, answerSdp string, challenge []byte, offerSdp, nodeToken string) error {
	ts := currentTsBytes()
	return c.signAndSend(ctx, remotePubkey, answerPayload(challenge, ts, offerSdp, answerSdp), wireMessage{
		From:      c.Pubkey(),
		Data:      answerSdp,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Ts:        base64.RawURLEncoding.EncodeToString(ts),
	}, nodeToken)
}

func (c *Client) postICE(ctx context.Context, remotePubkey, candidateJSON string, challenge []byte, nodeToken string) error {
	return c.signAndSend(ctx, remotePubkey, icePayload(challenge, candidateJSON), wireMessage{
		From:      c.Pubkey(),
		Data:      candidateJSON,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
	}, nodeToken)
}

func (c *Client) send(ctx context.Context, remotePubkey string, msg wireMessage, nodeToken string) error {
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
	if nodeToken != "" {
		req.Header.Set("X-Node-Token", nodeToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("relay POST failed: %s", resp.Status)
	}
	return nil
}

// handleOffer verifies an incoming offer, checks AcceptConnection, creates a
// PC, and sends an answer. Silently returns on any verification failure.
// AcceptConnection is called after signature verification to prevent untrusted
// pubkeys from driving policy decisions.
func (c *Client) handleOffer(ctx context.Context, msg wireMessage, challenge []byte) {
	tsBytes, err := base64.RawURLEncoding.DecodeString(msg.Ts)
	if err != nil || parseTsBytes(tsBytes) == nil {
		return
	}

	sender, sigBytes, err := parseSenderAndSig(msg.From, msg.Sig)
	if err != nil {
		return
	}
	if !ed25519.Verify(sender, offerPayload(challenge, tsBytes, c.pubKeyRaw(), msg.Data), sigBytes) {
		return
	}

	if c.opts.AcceptConnection == nil || !c.opts.AcceptConnection(msg.From) {
		return
	}

	pc, releaseICE, err := c.makePC(ctx, msg.From, challenge, msg.Token)
	if err != nil {
		return
	}

	if c.opts.OnIncoming != nil {
		c.opts.OnIncoming(pc, msg.From)
	}

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
	if err := c.postAnswer(ctx, msg.From, desc.SDP, challenge, msg.Data, msg.Token); err != nil {
		pc.Close()
		return
	}
	releaseICE()
	c.conns.Store(makeConnKey(msg.From, challenge), &connState{pc: pc, dialerToken: msg.Token})
}

// handleAnswer verifies timestamp and signature (covering the full offer SDP),
// then applies the remote description. Returns an error on any failure.
func (c *Client) handleAnswer(state *connState, msg wireMessage, challenge []byte) error {
	tsBytes, err := base64.RawURLEncoding.DecodeString(msg.Ts)
	if err != nil || parseTsBytes(tsBytes) == nil {
		return fmt.Errorf("answer timestamp invalid or out of window")
	}
	if state.offerSdp == "" {
		return fmt.Errorf("no sent offer SDP when verifying answer")
	}
	sender, sigBytes, err := parseSenderAndSig(msg.From, msg.Sig)
	if err != nil {
		return err
	}
	if !ed25519.Verify(sender, answerPayload(challenge, tsBytes, state.offerSdp, msg.Data), sigBytes) {
		return fmt.Errorf("invalid answer signature from %s", msg.From)
	}
	if err := state.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: msg.Data}); err != nil {
		return err
	}
	sendAuth(state.authDone, nil)
	return nil
}

// handleICE verifies the ICE candidate signature and adds the candidate.
// Returns an error on any failure.
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

// Listen opens an authenticated SSE stream and delivers incoming messages
// until ctx is cancelled. It reconnects automatically on transient failures.
// Returns ctx.Err() when ctx is cancelled.
func (c *Client) Listen(ctx context.Context) error {
	path := "/" + c.Pubkey()
	backoff := time.Duration(_ReconnectBaseMS) * time.Millisecond

	go func() {
		ticker := time.NewTicker(_ConnCleanupSecs * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.conns.Range(func(k, v any) bool {
					state := v.(*connState)
					switch state.pc.ConnectionState() {
					case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
						sendAuth(state.authDone, fmt.Errorf("peer connection closed before authentication"))
						c.conns.Delete(k)
					}
					return true
				})
			}
		}
	}()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := c.connectSSE(ctx, path)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil {
			backoff = _ReconnectBaseMS * time.Millisecond
		} else {
			backoff = min(backoff*2, _ReconnectMaxMS*time.Millisecond)
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
		if err := c.handleSSEMessage(ctx, payload); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func (c *Client) handleSSEMessage(ctx context.Context, line string) error {
	raw, err := base64.RawURLEncoding.DecodeString(line)
	if err != nil {
		return nil
	}
	var msg wireMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		// Not a JSON wire message — treat as raw node routing token.
		c.nodeToken.Store(line)
		return nil
	}
	if msg.From == "" || msg.Data == "" || msg.Challenge == "" || msg.Sig == "" {
		return nil
	}
	challenge, err := base64.RawURLEncoding.DecodeString(msg.Challenge)
	if err != nil || len(challenge) != 32 {
		return nil
	}

	key := makeConnKey(msg.From, challenge)
	val, known := c.conns.Load(key)
	if !known {
		c.handleOffer(ctx, msg, challenge)
		return nil
	}

	state := val.(*connState)
	if state.pc.RemoteDescription() == nil {
		// Known session with no remote description: this is an answer to our offer.
		if err := c.handleAnswer(state, msg, challenge); err != nil {
			c.closeConnWithError(key, state, err)
		}
	} else {
		// Remote description already set: this must be an ICE candidate.
		if err := c.handleICE(state.pc, msg, challenge); err != nil {
			c.closeConnWithError(key, state, err)
		}
	}
	return nil
}
