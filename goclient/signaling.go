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
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

const (
	reconnectBaseMS = 1_000
	reconnectMaxMS  = 30_000
	connCleanupSecs = 5
)

var defaultConfiguration = webrtc.Configuration{
	ICEServers: []webrtc.ICEServer{
		{URLs: []string{"stun:stun.l.google.com:19302"}},
	},
}

// Options configures a Client.
type Options struct {
	ServerURL string
	// Configuration is the WebRTC configuration. If zero, a default configuration
	// with a Google STUN server is used.
	Configuration webrtc.Configuration
	SettingEngine *webrtc.SettingEngine
	// PrivateKey is an optional Ed25519 private key. If nil, one is generated.
	PrivateKey ed25519.PrivateKey
	// AcceptConnection is called on receipt of an offer from a new sender, before
	// signature verification. Return false to silently drop the offer — no
	// response is sent to the dialer, to avoid leaking whether the key is active.
	// If nil, all offers are accepted.
	AcceptConnection func(remotePubkey string) bool
	// OnIncoming is called when an incoming offer has been verified and accepted,
	// after SetLocalDescription but before the answer is sent. Wire data channel
	// and media track handlers here. The PC may still be closed by the library
	// if a subsequent ICE candidate fails auth — "incoming" means a valid
	// authenticated offer arrived, not that a working P2P connection exists.
	OnIncoming func(pc *webrtc.PeerConnection, remotePubkey string)
}

// wireMessage is the signed envelope relayed through the server.
// base64url(JSON) keeps the payload newline-free for SSE framing.
type wireMessage struct {
	From      string `json:"from"`         // base64url sender pubkey
	Data      string `json:"data"`         // offer SDP | answer SDP | JSON(RTCIceCandidateInit)
	Challenge string `json:"challenge"`    // base64url(random[32]), set by dialer
	Ts        string `json:"ts,omitempty"` // base64url(uint64 unix seconds, big-endian) — offers and answers only
	Sig       string `json:"sig"`          // ed25519 signature — see crypto.go for payload construction
}

// connKey is the composite key for the conns map. Including the challenge
// allows a single remote pubkey to have multiple simultaneous connections
// (each dial generates a fresh challenge).
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

// Client connects to the relay server, authenticates its SSE stream, and
// manages WebRTC peer connections on behalf of the caller.
type Client struct {
	api   *webrtc.API
	opts  Options
	conns sync.Map // connKey → *connState
}

type connState struct {
	pc         *webrtc.PeerConnection
	releaseICE func()

	mu       sync.RWMutex
	offerSdp string
}

func (s *connState) setOfferSdp(offerSdp string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offerSdp = offerSdp
}

func (s *connState) getOfferSdp() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.offerSdp
}

func (c *Client) pubKeyRaw() ed25519.PublicKey {
	return c.opts.PrivateKey.Public().(ed25519.PublicKey)
}

// Pubkey returns the base64url-encoded Ed25519 public key identifying this
// client on the relay. Share this so others can reach you via Dial.
// Use base32Encode(base64RawURLDecode(Pubkey())) to get a human-friendly form.
func (c *Client) Pubkey() string {
	return base64.RawURLEncoding.EncodeToString(c.pubKeyRaw())
}

// New creates a Client. Call Listen to start receiving incoming connections.
func New(opts Options) (*Client, error) {
	if opts.PrivateKey == nil {
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating key pair: %w", err)
		}
		opts.PrivateKey = privKey
	}
	if len(opts.Configuration.ICEServers) == 0 {
		opts.Configuration = defaultConfiguration
	}
	opts.ServerURL = strings.TrimRight(opts.ServerURL, "/")

	api := webrtc.NewAPI()
	if opts.SettingEngine != nil {
		api = webrtc.NewAPI(webrtc.WithSettingEngine(*opts.SettingEngine))
	}
	return &Client{api: api, opts: opts}, nil
}

// Dial opens a connection to the peer identified by remotePubkey (base64url).
// Returns a raw *webrtc.PeerConnection. Add data channels or media tracks
// before returning — they will be included in the initial offer. The library
// closes the PC if the answer or any ICE candidate fails auth verification.
// ctx governs all signaling HTTP requests for this connection.
func (c *Client) Dial(ctx context.Context, remotePubkey string) (*webrtc.PeerConnection, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("generating challenge: %w", err)
	}

	pc, releaseICE, err := c.makePC(ctx, remotePubkey, challenge)
	if err != nil {
		return nil, err
	}

	state := &connState{pc: pc, releaseICE: releaseICE}
	c.conns.Store(makeConnKey(remotePubkey, challenge), state)

	pc.OnNegotiationNeeded(func() {
		if err := c.createAndSendOffer(ctx, remotePubkey, state, challenge); err != nil {
			pc.Close()
			c.conns.Delete(makeConnKey(remotePubkey, challenge))
		}
	})

	return pc, nil
}

// Close closes all peer connections. Cancel the context passed to Listen to
// stop the SSE loop.
func (c *Client) Close() {
	c.conns.Range(func(_, v any) bool {
		v.(*connState).pc.Close()
		return true
	})
	c.conns.Clear()
}

// makePC creates a new PeerConnection keyed by remotePubkey+challenge.
// Multiple simultaneous connections to the same peer are allowed — each dial
// generates a fresh challenge, yielding a distinct connKey.
// ctx governs all ICE candidate HTTP sends for this connection.
// makePC creates a new PeerConnection and wires ICE candidate signing.
// The caller is responsible for storing it in c.conns.
func (c *Client) makePC(ctx context.Context, remotePubkey string, challenge []byte) (*webrtc.PeerConnection, func(), error) {
	pc, err := c.api.NewPeerConnection(c.opts.Configuration)
	if err != nil {
		return nil, nil, fmt.Errorf("creating peer connection: %w", err)
	}

	var iceMu sync.Mutex
	iceReleased := false
	var pendingICE []string

	sendICE := func(candidateJSON string) {
		_ = c.postICE(ctx, remotePubkey, candidateJSON, challenge)
	}

	releaseICE := func() {
		iceMu.Lock()
		if iceReleased {
			iceMu.Unlock()
			return
		}
		iceReleased = true
		pending := append([]string(nil), pendingICE...)
		pendingICE = nil
		iceMu.Unlock()

		for _, candidateJSON := range pending {
			sendICE(candidateJSON)
		}
	}

	pc.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			return
		}
		b, err := json.Marshal(candidate.ToJSON())
		if err != nil {
			return
		}
		candidateJSON := string(b)

		iceMu.Lock()
		if !iceReleased {
			pendingICE = append(pendingICE, candidateJSON)
			iceMu.Unlock()
			return
		}
		iceMu.Unlock()

		sendICE(candidateJSON)
	})

	return pc, releaseICE, nil
}

func (c *Client) postOffer(ctx context.Context, remotePubkey, offerSdp string, challenge, ts []byte) error {
	remotePubKeyBytes, err := base64.RawURLEncoding.DecodeString(remotePubkey)
	if err != nil {
		return fmt.Errorf("decoding remote pubkey: %w", err)
	}

	sig := ed25519.Sign(c.opts.PrivateKey, offerPayload(challenge, ts, remotePubKeyBytes, offerSdp))
	return c.send(ctx, remotePubkey, wireMessage{
		From:      c.Pubkey(),
		Data:      offerSdp,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Ts:        base64.RawURLEncoding.EncodeToString(ts),
		Sig:       base64.RawURLEncoding.EncodeToString(sig),
	})
}

func (c *Client) postAnswer(ctx context.Context, remotePubkey, answerSdp string, challenge []byte, offerSdp string) error {
	ts := currentTsBytes()
	sig := ed25519.Sign(c.opts.PrivateKey, answerPayload(challenge, ts, offerSdp, answerSdp))
	return c.send(ctx, remotePubkey, wireMessage{
		From:      c.Pubkey(),
		Data:      answerSdp,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Ts:        base64.RawURLEncoding.EncodeToString(ts),
		Sig:       base64.RawURLEncoding.EncodeToString(sig),
	})
}

func (c *Client) postICE(ctx context.Context, remotePubkey, candidateJson string, challenge []byte) error {
	sig := ed25519.Sign(c.opts.PrivateKey, icePayload(challenge, candidateJson))
	return c.send(ctx, remotePubkey, wireMessage{
		From:      c.Pubkey(),
		Data:      candidateJson,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Sig:       base64.RawURLEncoding.EncodeToString(sig),
	})
}

func (c *Client) send(ctx context.Context, remotePubkey string, msg wireMessage) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	body := base64.RawURLEncoding.EncodeToString(b)

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
	return nil
}

func (c *Client) createAndSendOffer(ctx context.Context, remotePubkey string, state *connState, challenge []byte) error {
	pc := state.pc
	if pc.RemoteDescription() != nil {
		return nil
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		return err
	}
	desc := pc.LocalDescription()
	if desc == nil {
		return fmt.Errorf("no local description after creating offer")
	}
	state.setOfferSdp(desc.SDP)
	if err := c.postOffer(ctx, remotePubkey, desc.SDP, challenge, currentTsBytes()); err != nil {
		return err
	}
	state.releaseICE()
	return nil
}

// handleOffer verifies timestamp and signature (including recipient binding),
// creates a PC, negotiates an answer, calls onIncoming, then sends the answer.
// AcceptConnection filtering is done by the caller before this is invoked.
func (c *Client) handleOffer(ctx context.Context, msg wireMessage, challenge []byte) (*webrtc.PeerConnection, error) {
	tsBytes, err := base64.RawURLEncoding.DecodeString(msg.Ts)
	if err != nil {
		return nil, err
	}
	ts := parseTsBytes(tsBytes)
	if ts == nil {
		return nil, fmt.Errorf("offer timestamp out of window")
	}

	senderKeyBytes, err := base64.RawURLEncoding.DecodeString(msg.From)
	if err != nil {
		return nil, err
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(msg.Sig)
	if err != nil {
		return nil, err
	}

	// Recipient binding: own pubkey must appear in the signed payload.
	if !ed25519.Verify(senderKeyBytes, offerPayload(challenge, ts, c.pubKeyRaw(), msg.Data), sigBytes) {
		return nil, fmt.Errorf("invalid offer signature from %s", msg.From)
	}

	pc, releaseICE, err := c.makePC(ctx, msg.From, challenge)
	if err != nil {
		return nil, err
	}

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer, SDP: msg.Data,
	}); err != nil {
		return pc, err
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return pc, err
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		return pc, err
	}
	desc := pc.LocalDescription()
	if desc == nil {
		return pc, fmt.Errorf("no local description after answer")
	}

	if c.opts.OnIncoming != nil {
		c.opts.OnIncoming(pc, msg.From)
	}

	if err := c.postAnswer(ctx, msg.From, desc.SDP, challenge, msg.Data); err != nil {
		return pc, err
	}
	releaseICE()
	return pc, nil
}

// handleAnswer verifies timestamp and signature (covering the full offer SDP),
// then applies the remote description. Returns an error on any verification
// failure — the caller is responsible for closing the PC.
func (c *Client) handleAnswer(state *connState, msg wireMessage, challenge []byte) error {
	pc := state.pc
	tsBytes, err := base64.RawURLEncoding.DecodeString(msg.Ts)
	if err != nil {
		return fmt.Errorf("decoding answer timestamp: %w", err)
	}
	ts := parseTsBytes(tsBytes)
	if ts == nil {
		return fmt.Errorf("answer timestamp out of window")
	}

	offerSdp := state.getOfferSdp()
	if offerSdp == "" {
		return fmt.Errorf("no sent offer SDP when verifying answer")
	}

	senderKeyBytes, err := base64.RawURLEncoding.DecodeString(msg.From)
	if err != nil {
		return fmt.Errorf("decoding answer sender key: %w", err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(msg.Sig)
	if err != nil {
		return fmt.Errorf("decoding answer signature: %w", err)
	}
	if !ed25519.Verify(senderKeyBytes, answerPayload(challenge, ts, offerSdp, msg.Data), sigBytes) {
		return fmt.Errorf("invalid answer signature from %s", msg.From)
	}

	return pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: msg.Data,
	})
}

// handleICE verifies the ICE candidate signature, then adds the candidate.
// Returns an error on any verification failure — the caller is responsible
// for closing the PC.
func (c *Client) handleICE(pc *webrtc.PeerConnection, msg wireMessage, challenge []byte) error {
	senderKeyBytes, err := base64.RawURLEncoding.DecodeString(msg.From)
	if err != nil {
		return fmt.Errorf("decoding ICE sender key: %w", err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(msg.Sig)
	if err != nil {
		return fmt.Errorf("decoding ICE signature: %w", err)
	}
	if !ed25519.Verify(senderKeyBytes, icePayload(challenge, msg.Data), sigBytes) {
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
// Returns ctx.Err() when ctx is cancelled, or an error on setup failure.
func (c *Client) Listen(ctx context.Context) error {
	path := "/" + c.Pubkey()
	backoff := time.Duration(reconnectBaseMS) * time.Millisecond

	go func() {
		ticker := time.NewTicker(connCleanupSecs * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.conns.Range(func(k, v any) bool {
					switch v.(*connState).pc.ConnectionState() {
					case webrtc.PeerConnectionStateFailed,
						webrtc.PeerConnectionStateClosed:
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
		if err := c.handleSSEMessage(ctx, line[len("data: "):]); err != nil {
			return err
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func (c *Client) handleSSEMessage(ctx context.Context, line string) error {
	raw, err := base64.RawURLEncoding.DecodeString(line)
	if err != nil {
		return nil
	}

	var msg wireMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
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
		// No session for this pubkey+challenge: treat as a new offer.
		if c.opts.AcceptConnection != nil && !c.opts.AcceptConnection(msg.From) {
			return nil
		}
		pc, err := c.handleOffer(ctx, msg, challenge)
		if err != nil {
			if pc != nil {
				pc.Close()
			}
		} else {
			c.conns.Store(makeConnKey(msg.From, challenge), &connState{pc: pc})
		}
	} else {
		state := val.(*connState)
		pc := state.pc
		if pc.RemoteDescription() == nil {
			// No remote description, this is an answer to an offer we sent.
			if err := c.handleAnswer(state, msg, challenge); err != nil {
				pc.Close()
				c.conns.Delete(key)
			}
		} else {
			// Remote description already set, this must be an ICE candidate.
			if err := c.handleICE(pc, msg, challenge); err != nil {
				pc.Close()
				c.conns.Delete(key)
			}
		}
	}

	return nil
}
