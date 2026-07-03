package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/pion/webrtc/v4"
	connect "github.com/trustleast/connect/goclient"
)

const _PropagationDelay = 5 * time.Second

// ---------------------------------------------------------------------------
// Trial result types
// ---------------------------------------------------------------------------

type check struct {
	Name string
	Err  error
}

func (c check) passed() bool { return c.Err == nil }

type trial struct {
	PubKey   string
	Checks   []check
	TimedOut bool
}

func (t *trial) record(name string, err error) {
	t.Checks = append(t.Checks, check{name, err})
}

func (t trial) passed() bool {
	if len(t.Checks) == 0 {
		return false
	}
	for _, c := range t.Checks {
		if !c.passed() {
			return false
		}
	}
	return true
}

func printTrial(t trial) {
	fmt.Fprintf(os.Stderr, "--- TRIAL %s ---\n", t.PubKey)
	for _, c := range t.Checks {
		if c.passed() {
			fmt.Fprintf(os.Stderr, "  [PASS] %s\n", c.Name)
		} else {
			fmt.Fprintf(os.Stderr, "  [FAIL] %s: %v\n", c.Name, c.Err)
		}
	}
	switch {
	case t.passed():
		fmt.Fprintf(os.Stderr, "  RESULT: PASS\n")
	case t.TimedOut:
		fmt.Fprintf(os.Stderr, "  RESULT: FAIL (timed out)\n")
	default:
		fmt.Fprintf(os.Stderr, "  RESULT: FAIL\n")
	}
}

// ---------------------------------------------------------------------------
// Signal bus: routes events to per-trial mailboxes keyed by session challenge
// ---------------------------------------------------------------------------

type observedSignal struct {
	event connect.SignalEvent
	msg   wireMessage
}

type trialMailbox struct {
	mu     sync.Mutex
	events []observedSignal
}

func (m *trialMailbox) add(e observedSignal) {
	m.mu.Lock()
	m.events = append(m.events, e)
	m.mu.Unlock()
}

func (m *trialMailbox) snapshot() []observedSignal {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]observedSignal, len(m.events))
	copy(out, m.events)
	return out
}

type signalBus struct {
	quiet     bool
	mu        sync.Mutex
	mailboxes map[string]*trialMailbox // challenge → mailbox
	pending   map[string]string        // remotePubkey → challenge (inbound offers awaiting claim)
}

func newSignalBus(quiet bool) *signalBus {
	return &signalBus{
		quiet:     quiet,
		mailboxes: make(map[string]*trialMailbox),
		pending:   make(map[string]string),
	}
}

func (b *signalBus) observe(event connect.SignalEvent) {
	var msg wireMessage
	raw, err := base64.RawURLEncoding.DecodeString(event.Payload)
	if err != nil || json.Unmarshal(raw, &msg) != nil || msg.Challenge == "" {
		return
	}

	direction := ">"
	if event.Direction == connect.SignalInboundSSE {
		direction = "<"
	}
	if !b.quiet {
		fmt.Printf("%s %s\n", direction, raw)
	}

	b.mu.Lock()
	mb, exists := b.mailboxes[msg.Challenge]
	if !exists {
		mb = &trialMailbox{}
		b.mailboxes[msg.Challenge] = mb
		// Register inbound offers so OnIncoming can claim the mailbox by remotePubkey.
		if event.Direction == connect.SignalInboundSSE && msg.Ts != "" {
			b.pending[msg.From] = msg.Challenge
		}
	}
	b.mu.Unlock()

	mb.add(observedSignal{event: event, msg: msg})
}

// claimIncoming retrieves the mailbox for the offer that just arrived from
// remotePubkey. Called synchronously in OnIncoming before the goroutine.
// The mailbox is intentionally left in b.mailboxes so that subsequent events
// (our answer, ICE candidates) are still routed to it. Call releaseMailbox
// with the returned challenge when the trial goroutine exits.
func (b *signalBus) claimIncoming(remotePubkey string) (*trialMailbox, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	challenge, ok := b.pending[remotePubkey]
	if !ok {
		return &trialMailbox{}, ""
	}
	delete(b.pending, remotePubkey)
	return b.mailboxes[challenge], challenge
}

// releaseMailbox removes a mailbox from the bus once its trial is complete.
func (b *signalBus) releaseMailbox(challenge string) {
	if challenge == "" {
		return
	}
	b.mu.Lock()
	delete(b.mailboxes, challenge)
	b.mu.Unlock()
}

// claimOutbound finds the mailbox for a dial-back session by identifying the
// one whose first event is our outbound offer. This distinguishes it from the
// inbound mailbox, which begins with the remote's offer. Called after
// client.Dial returns and after pong completes so all ICE has arrived.
func (b *signalBus) claimOutbound(selfPubkey, remotePubkey string) *trialMailbox {
	b.mu.Lock()
	defer b.mu.Unlock()
	for challenge, mb := range b.mailboxes {
		events := mb.snapshot()
		if len(events) == 0 {
			continue
		}
		first := events[0]
		if first.event.Direction == connect.SignalOutboundPOST &&
			first.event.RemotePubkey == remotePubkey &&
			first.msg.From == selfPubkey &&
			first.msg.Ts != "" {
			delete(b.mailboxes, challenge)
			return mb
		}
	}
	return &trialMailbox{}
}

// ---------------------------------------------------------------------------
// main / run
// ---------------------------------------------------------------------------

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	verbose := flag.Bool("verbose", false, "add more verbose logging")
	serverURL := flag.String("server-url", "", "connect relay URL")
	provideServerURL := flag.String("provide-server-url", "", "connect relay URL")
	trialTimeout := flag.Duration("timeout", 30*time.Second, "per-trial timeout")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "per-dial signaling timeout")
	privateKeyFlag := flag.String("private-key", "", "base64url-encoded ed25519 private key (32-byte seed or 64-byte key); generates a new key if not set")
	continuous := flag.Bool("continuous", false, "keep running and validate all incoming connections; candidate command is not used")
	flag.Parse()

	key, err := getPrivateKey(*privateKeyFlag)
	if err != nil {
		return err
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if *continuous {
		ctx, cancel = context.WithCancel(context.Background())
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), *trialTimeout)
	}
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	bus := newSignalBus(!*verbose)
	results := make(chan trial, 64)

	var client *connect.Client
	client, err = connect.New(
		connect.WithServerURL(*serverURL),
		connect.WithPrivateKey(key),
		connect.WithOnSignal(bus.observe),
		connect.WithAcceptConnection(func(remotePubkey string) bool { return true }),
		connect.WithOnIncoming(func(pc *webrtc.PeerConnection, remotePubkey string) {
			// Claim the mailbox and wire the PC synchronously before spawning the
			// goroutine so no events or state transitions can be missed.
			mb, challenge := bus.claimIncoming(remotePubkey)

			inboundPongDone := make(chan error, 1)
			label := uuid.New().String()
			pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
				if state == webrtc.PeerConnectionStateConnected {
					if *verbose {
						fmt.Fprintf(os.Stderr, "peer connection state connected for inbound from %s\n", remotePubkey)
					}
					dc, err := pc.CreateDataChannel(label, nil)
					if err != nil {
						inboundPongDone <- fail("connection-flow.inbound.datachannel.create", "create data channel: %v", err)
					} else {
						wireChallenge(dc, inboundPongDone, *verbose)
					}
				}
			})

			trialCtx, trialCancel := context.WithTimeout(ctx, *trialTimeout)
			go func() {
				defer trialCancel()
				defer bus.releaseMailbox(challenge)
				results <- handleIncoming(trialCtx, client, bus, mb, inboundPongDone, remotePubkey, *dialTimeout, *verbose)
			}()
		}),
	)
	if err != nil {
		return fmt.Errorf("create spec client: %w", err)
	}
	defer client.Close()
	if *verbose {
		fmt.Fprintf(os.Stderr, "spec-tester listening pubkey=%s\n", client.Pubkey())
	}

	listenErr := make(chan error, 1)
	go func() { listenErr <- client.Listen(ctx) }()
	// Wait until we are propagated across the network
	time.Sleep(_PropagationDelay)

	if !*continuous {
		candidateCmd := flag.Args()
		if len(candidateCmd) == 0 {
			return fmt.Errorf("usage: spec-tester [flags] -- candidate-command [args...]\n       or: spec-tester -continuous [flags]")
		}
		candidateServerURL := *serverURL
		if *provideServerURL != "" {
			candidateServerURL = *provideServerURL
		}
		go func() {
			if err := runCandidateCommand(ctx, candidateServerURL, client.Pubkey()); err != nil {
				fmt.Printf("candidate command failed: %v\n", err)
				cancel()
			}
		}()
	}

	once := true
	for once || *continuous {
		once = false
		select {
		case err := <-listenErr:
			return fmt.Errorf("listen failed: %w", err)
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded || ctx.Err() == context.Canceled {
				return fail("trial.failed", "%v", ctx.Err().Error())
			}
			return nil
		case t := <-results:
			printTrial(t)
		}
	}
	return nil
}

func runCandidateCommand(ctx context.Context, serverURL string, pubkey string) error {
	candidateCmd := flag.Args()
	if len(candidateCmd) == 0 {
		return nil
	}
	candidateArgs := append(candidateCmd[1:], serverURL, pubkey)
	cmd := exec.CommandContext(ctx, candidateCmd[0], candidateArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fail("spec-tester.candidate.start", "start candidate: %v", err)
	}
	return cmd.Wait()
}

// ---------------------------------------------------------------------------
// Trial execution
// ---------------------------------------------------------------------------

func handleIncoming(ctx context.Context, client *connect.Client, bus *signalBus, inboundMb *trialMailbox, inboundPongDone <-chan error, remotePubkey string, dialTimeout time.Duration, verbose bool) trial {
	t := trial{PubKey: remotePubkey}
	if verbose {
		fmt.Fprintf(os.Stderr, "inbound offer accepted from %s\n", remotePubkey)
	}

	// inbound.pong: wait for the PC to connect and complete challenge/response.
	err := waitResult(ctx, inboundPongDone, "inbound.pong")
	t.record("inbound.pong", err)
	if err != nil {
		t.TimedOut = ctx.Err() != nil
		checkInboundSignaling(&t, inboundMb.snapshot(), client.Pubkey(), remotePubkey)
		return t
	}

	checkInboundSignaling(&t, inboundMb.snapshot(), client.Pubkey(), remotePubkey)

	// outbound.dial: the setup func passed to Dial is called synchronously before
	// the offer is sent, so wiring wireChallenge there is race-free.
	dialCtx, dialCancel := context.WithTimeout(ctx, dialTimeout)
	defer dialCancel()

	outboundPongDone := make(chan error, 1)
	setupConn := func(pc *webrtc.PeerConnection) {
		lbl, err := randomChannelLabel()
		if err != nil {
			outboundPongDone <- err
			return
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "creating outbound data channel label=%s\n", lbl)
		}
		dc, err := pc.CreateDataChannel(lbl, nil)
		if err != nil {
			outboundPongDone <- fail("connection-flow.outbound.datachannel.create", "create data channel: %v", err)
			return
		}
		wireChallenge(dc, outboundPongDone, verbose)
	}

	// Wait 5 seconds before we respond to make sure our client can be reached back without tokens
	time.Sleep(_PropagationDelay)

	if verbose {
		fmt.Printf("Dialing back")
	}

	outPC, err := client.Dial(dialCtx, remotePubkey, setupConn)
	t.record("outbound.dial", err)
	if err != nil {
		t.TimedOut = dialCtx.Err() != nil || ctx.Err() != nil
		return t
	}
	defer outPC.Close()

	// outbound.pong: wait for challenge/response on the dial-back connection.
	err = waitResult(dialCtx, outboundPongDone, "outbound.pong")
	t.record("outbound.pong", err)
	if err != nil {
		t.TimedOut = dialCtx.Err() != nil || ctx.Err() != nil
	}

	// Claim the outbound mailbox after pong so all ICE candidates have arrived.
	outboundMb := bus.claimOutbound(client.Pubkey(), remotePubkey)
	checkOutboundSignaling(&t, outboundMb.snapshot(), client.Pubkey(), remotePubkey)

	return t
}

// ---------------------------------------------------------------------------
// Signaling checks
// ---------------------------------------------------------------------------

// checkInboundSignaling validates the exchange where the tester acted as answerer.
func checkInboundSignaling(t *trial, events []observedSignal, selfPubkey, remotePubkey string) {
	var offer *wireMessage
	var answer *wireMessage
	var iceBeforeAnswer bool
	var multipleAnswers bool
	var outboundICE []wireMessage

	for i := range events {
		e := events[i]
		if e.event.Direction == connect.SignalInboundSSE && e.msg.From == remotePubkey {
			if offer == nil && e.msg.Ts != "" {
				m := e.msg
				offer = &m
			}
		}
		if e.event.Direction == connect.SignalOutboundPOST && e.event.RemotePubkey == remotePubkey {
			if e.msg.Ts != "" {
				if answer == nil {
					m := e.msg
					answer = &m
				} else {
					multipleAnswers = true
				}
			} else {
				if answer == nil {
					iceBeforeAnswer = true
				} else {
					outboundICE = append(outboundICE, e.msg)
				}
			}
		}
	}

	if offer == nil {
		t.record("inbound.offer", fmt.Errorf("no offer observed from remote"))
		t.record("inbound.answer.ordering", fmt.Errorf("skipped: no offer"))
		t.record("inbound.answer", fmt.Errorf("skipped: no offer"))
		t.record("inbound.ice", fmt.Errorf("skipped: no offer"))
		return
	}
	t.record("inbound.offer", checkOfferValid(*offer, selfPubkey))

	switch {
	case iceBeforeAnswer:
		t.record("inbound.answer.ordering", fmt.Errorf("tester sent ICE before answer"))
	case multipleAnswers:
		t.record("inbound.answer.ordering", fmt.Errorf("tester sent multiple answers"))
	default:
		t.record("inbound.answer.ordering", nil)
	}

	if answer == nil {
		t.record("inbound.answer", fmt.Errorf("no answer observed from tester"))
	} else {
		t.record("inbound.answer", checkAnswerValid(*answer, *offer))
	}

	t.record("inbound.ice", checkICEsValid(outboundICE, offer.Challenge))
}

// checkOutboundSignaling validates the exchange where the tester acted as dialer.
func checkOutboundSignaling(t *trial, events []observedSignal, selfPubkey, remotePubkey string) {
	var offer *wireMessage
	var answer *wireMessage
	var iceBeforeAnswer bool
	var multipleAnswers bool
	var inboundICE []wireMessage

	for i := range events {
		e := events[i]
		if e.event.Direction == connect.SignalOutboundPOST &&
			e.event.RemotePubkey == remotePubkey &&
			e.msg.From == selfPubkey {
			if offer == nil && e.msg.Ts != "" {
				m := e.msg
				offer = &m
			}
		}
		if e.event.Direction == connect.SignalInboundSSE && e.msg.From == remotePubkey {
			if offer == nil || e.msg.Challenge != offer.Challenge {
				continue
			}
			if e.msg.Ts != "" {
				if answer == nil {
					m := e.msg
					answer = &m
				} else {
					multipleAnswers = true
				}
			} else {
				if answer == nil {
					iceBeforeAnswer = true
				} else {
					inboundICE = append(inboundICE, e.msg)
				}
			}
		}
	}

	if offer == nil {
		t.record("outbound.offer", fmt.Errorf("no outbound offer observed"))
		t.record("outbound.answer.ordering", fmt.Errorf("skipped: no offer"))
		t.record("outbound.answer", fmt.Errorf("skipped: no offer"))
		t.record("outbound.ice", fmt.Errorf("skipped: no offer"))
		return
	}
	t.record("outbound.offer", checkOfferValid(*offer, remotePubkey))

	switch {
	case iceBeforeAnswer:
		t.record("outbound.answer.ordering", fmt.Errorf("candidate sent ICE before answer"))
	case multipleAnswers:
		t.record("outbound.answer.ordering", fmt.Errorf("candidate sent multiple answers"))
	default:
		t.record("outbound.answer.ordering", nil)
	}

	if answer == nil {
		t.record("outbound.answer", fmt.Errorf("no answer observed from candidate"))
	} else {
		t.record("outbound.answer", checkAnswerValid(*answer, *offer))
	}

	t.record("outbound.ice", checkICEsValid(inboundICE, offer.Challenge))
}

// ---------------------------------------------------------------------------
// Per-message validation
// ---------------------------------------------------------------------------

func checkOfferValid(msg wireMessage, recipientPubkey string) error {
	challenge, err := base64.RawURLEncoding.DecodeString(msg.Challenge)
	if err != nil || len(challenge) != 32 {
		return fail("offer.challenge", "challenge was not 32 base64url bytes")
	}
	ts, err := base64.RawURLEncoding.DecodeString(msg.Ts)
	if err != nil || len(ts) != 8 {
		return fail("offer.timestamp", "timestamp was not 8 base64url bytes")
	}
	if err := checkTsWindow(ts, "offer"); err != nil {
		return err
	}
	recipient, err := base64.RawURLEncoding.DecodeString(recipientPubkey)
	if err != nil {
		return fail("offer.recipient", "recipient pubkey invalid: %v", err)
	}
	sender, sig, err := senderAndSig(msg)
	if err != nil {
		return err
	}
	if !ed25519.Verify(sender, offerPayload(challenge, ts, recipient, msg.Data), sig) {
		return fail("offer.signature", "offer signature did not verify over challenge, timestamp, recipient, and SDP")
	}
	return nil
}

func checkAnswerValid(answer, offer wireMessage) error {
	if answer.Challenge != offer.Challenge {
		return fail("answer.challenge", "answer challenge does not match offer challenge")
	}
	challenge, err := base64.RawURLEncoding.DecodeString(answer.Challenge)
	if err != nil || len(challenge) != 32 {
		return fail("answer.challenge", "challenge was not 32 base64url bytes")
	}
	ts, err := base64.RawURLEncoding.DecodeString(answer.Ts)
	if err != nil || len(ts) != 8 {
		return fail("answer.timestamp", "timestamp was not 8 base64url bytes")
	}
	if err := checkTsWindow(ts, "answer"); err != nil {
		return err
	}
	sender, sig, err := senderAndSig(answer)
	if err != nil {
		return err
	}
	if !ed25519.Verify(sender, answerPayload(challenge, ts, offer.Data, answer.Data), sig) {
		return fail("answer.signature", "answer signature did not verify over offer SDP and answer SDP")
	}
	return nil
}

func checkICEsValid(msgs []wireMessage, expectedChallenge string) error {
	for _, msg := range msgs {
		if msg.Ts != "" {
			return fail("ice.no-timestamp", "ICE candidate must not carry a ts field")
		}
		if msg.Challenge != expectedChallenge {
			return fail("ice.challenge", "ICE challenge does not match session challenge")
		}
		challenge, err := base64.RawURLEncoding.DecodeString(msg.Challenge)
		if err != nil || len(challenge) != 32 {
			return fail("ice.challenge", "challenge was not 32 base64url bytes")
		}
		sender, sig, err := senderAndSig(msg)
		if err != nil {
			return err
		}
		if !ed25519.Verify(sender, icePayload(challenge, msg.Data), sig) {
			return fail("ice.signature", "ICE signature did not verify over challenge and candidate JSON")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Wire message and payload construction
// ---------------------------------------------------------------------------

type wireMessage struct {
	From      string `json:"from"`
	Data      string `json:"data"`
	Challenge string `json:"challenge"`
	Ts        string `json:"ts,omitempty"`
	Sig       string `json:"sig"`
}

func offerPayload(challenge, ts, answererPubkey []byte, offerSdp string) []byte {
	var b bytes.Buffer
	b.WriteString("connect.offer.v1\x00")
	b.Write(challenge)
	b.Write(ts)
	b.Write(answererPubkey)
	b.WriteString(offerSdp)
	return b.Bytes()
}

func answerPayload(challenge, ts []byte, offerSdp, answerSdp string) []byte {
	var b bytes.Buffer
	b.WriteString("connect.answer.v1\x00")
	b.Write(challenge)
	b.Write(ts)
	b.WriteString(offerSdp)
	b.WriteByte(0)
	b.WriteString(answerSdp)
	return b.Bytes()
}

func icePayload(challenge []byte, candidateJSON string) []byte {
	var b bytes.Buffer
	b.WriteString("connect.ice.v1\x00")
	b.Write(challenge)
	b.WriteString(candidateJSON)
	return b.Bytes()
}

const tsWindowSecs = 30

func checkTsWindow(ts []byte, kind string) error {
	v := int64(binary.BigEndian.Uint64(ts))
	diff := time.Now().Unix() - v
	if diff < 0 {
		diff = -diff
	}
	if diff > tsWindowSecs {
		return fail(kind+".timestamp", "%s timestamp is %ds outside ±%ds window", kind, diff, tsWindowSecs)
	}
	return nil
}

func senderAndSig(msg wireMessage) (ed25519.PublicKey, []byte, error) {
	sender, err := base64.RawURLEncoding.DecodeString(msg.From)
	if err != nil || len(sender) != ed25519.PublicKeySize {
		return nil, nil, fail("wire.from", "sender pubkey was not valid base64url ed25519 public key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(msg.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, fail("wire.signature", "signature was not valid base64url ed25519 signature")
	}
	return ed25519.PublicKey(sender), sig, nil
}

// ---------------------------------------------------------------------------
// Data channel challenge/response
// ---------------------------------------------------------------------------

func wireChallenge(dc *webrtc.DataChannel, done chan<- error, verbose bool) {
	challenge, err := randomChallenge()
	if err != nil {
		done <- err
		return
	}
	expected := "pong:" + challenge

	dc.OnOpen(func() {
		if verbose {
			fmt.Fprintf(os.Stderr, "data channel open label=%s sending challenge=%s\n", dc.Label(), challenge[:12])
		}
		if err := dc.SendText("challenge:" + challenge); err != nil {
			done <- fail("connection-flow.challenge.send", "send challenge: %v", err)
		}
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if strings.TrimSpace(string(msg.Data)) != expected {
			done <- fail("connection-flow.challenge.pong", "expected %q, got %q", expected, string(msg.Data))
			return
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "received expected pong for challenge=%s\n", challenge[:12])
		}
		done <- nil
	})
}

func randomChallenge() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fail("connection-flow.challenge.generate", "generate challenge: %v", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func randomChannelLabel() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fail("connection-flow.channel.generate", "generate channel label: %v", err)
	}
	return "spec-" + hex.EncodeToString(b[:]), nil
}

func waitResult(ctx context.Context, done <-chan error, name string) error {
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fail(name, "%v", ctx.Err())
	}
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

func fail(section, format string, args ...any) error {
	return fmt.Errorf("[%s] %s", section, fmt.Sprintf(format, args...))
}

func getPrivateKey(keyData string) (ed25519.PrivateKey, error) {
	if keyData != "" {
		keyBytes, err := base64.RawURLEncoding.DecodeString(keyData)
		if err != nil {
			return nil, fmt.Errorf("decoding -private-key: %w", err)
		}
		switch len(keyBytes) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(keyBytes), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(keyBytes), nil
		default:
			return nil, fmt.Errorf("-private-key must be 32 bytes (seed) or 64 bytes, got %d", len(keyBytes))
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}
