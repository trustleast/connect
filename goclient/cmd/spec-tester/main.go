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
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pion/webrtc/v4"
	connect "github.com/trustleast/connect/goclient"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	serverURL := flag.String("server-url", "", "connect relay URL")
	timeout := flag.Duration("timeout", 30*time.Second, "overall spec timeout (single-run only)")
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
		ctx, cancel = context.WithTimeout(context.Background(), *timeout)
	}
	defer cancel()

	trace := newSignalTrace()
	firstResult := make(chan error, 1) // single-run only

	var client *connect.Client
	opts := []connect.Option{
		connect.WithServerURL(*serverURL),
		connect.WithPrivateKey(key),
		connect.WithOnSignal(trace.observe),
		connect.WithAcceptConnection(func(remotePubkey string) bool { return true }),
		connect.WithOnIncoming(func(pc *webrtc.PeerConnection, remotePubkey string) {
			// OnSignal fires before OnIncoming, so the offer is already the last
			// event in the trace. Subtract 1 to include it in validation.
			startIdx := trace.len() - 1
			go func() {
				err := handleIncoming(ctx, client, pc, remotePubkey, trace, startIdx, *dialTimeout)
				if err != nil {
					fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", remotePubkey, err)
				} else {
					fmt.Fprintf(os.Stderr, "PASS %s\n", remotePubkey)
				}

				if !*continuous {
					select {
					case firstResult <- err:
					default:
					}
					cancel()
				}
			}()
		}),
	}

	client, err = connect.New(opts...)
	if err != nil {
		return fmt.Errorf("create spec client: %w", err)
	}
	defer client.Close()
	fmt.Fprintf(os.Stderr, "spec-tester listening pubkey=%s\n", client.Pubkey())

	listenErr := make(chan error, 1)
	go func() { listenErr <- client.Listen(ctx) }()

	if *continuous {
		return <-listenErr
	}

	// Single-run: launch the candidate and wait for one full validation.
	candidateCmd := flag.Args()
	if len(candidateCmd) == 0 {
		return fmt.Errorf("usage: spec-tester [flags] -- candidate-command [args...]\n       or: spec-tester -continuous [flags]")
	}
	candidateDone := make(chan error, 1)
	candidateArgs := append(candidateCmd[1:], *serverURL, client.Pubkey())
	fmt.Fprintf(os.Stderr, "starting candidate: %s %s\n", candidateCmd[0], strings.Join(candidateArgs, " "))
	cmd := exec.CommandContext(ctx, candidateCmd[0], candidateArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fail("spec-tester.candidate.start", "start candidate: %v", err)
	}
	go func() { candidateDone <- cmd.Wait() }()

	select {
	case err := <-firstResult:
		if err != nil {
			return err
		}
	case err := <-listenErr:
		return fail("spec-tester.listen", "listen failed: %v", err)
	case err := <-candidateDone:
		return fail("spec-tester.candidate.before-result", "candidate exited before validation completed: %v", err)
	case <-ctx.Done():
		return fail("spec-tester.timeout", "%v", ctx.Err())
	}

	select {
	case err := <-candidateDone:
		if err != nil {
			return fail("spec-tester.candidate.exit", "candidate failed: %v", err)
		}
	case <-time.After(time.Second):
		_ = cmd.Process.Kill()
		return fail("spec-tester.candidate.exit", "candidate did not exit after dial-back passed")
	case <-ctx.Done():
		return fail("spec-tester.timeout", "%v", ctx.Err())
	}

	return nil
}

func handleIncoming(ctx context.Context, client *connect.Client, pc *webrtc.PeerConnection, remotePubkey string, trace *signalTrace, startIdx int, dialTimeout time.Duration) error {
	fmt.Fprintf(os.Stderr, "inbound offer accepted from %s\n", remotePubkey)

	done := make(chan error, 1)
	label := uuid.New().String()
	pc.OnConnectionStateChange(func(pcs webrtc.PeerConnectionState) {
		if pcs == webrtc.PeerConnectionStateConnected {
			fmt.Fprintf(os.Stderr, "peer connection state connected for inbound from %s\n", remotePubkey)
			dc, err := pc.CreateDataChannel(label, nil)
			if err != nil {
				done <- fail("connection-flow.inbound.datachannel.create", "create data channel: %v", err)
			} else {
				wireChallenge(dc, done)
			}
		}
	})

	fmt.Fprintf(os.Stderr, "waiting for inbound-leg challenge/pong\n")
	if err := waitResult(ctx, done, "connection-flow.inbound.challenge-pong"); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "validating inbound-leg signaling invariants\n")
	if err := trace.validateInboundAnswerer(startIdx, client.Pubkey(), remotePubkey); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "dialing candidate back\n")
	dialCtx, dialCancel := context.WithTimeout(ctx, dialTimeout)
	defer dialCancel()
	dialStartIdx := trace.len()
	if err := dialBack(dialCtx, client, remotePubkey, dialTimeout); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "validating outbound-leg signaling invariants\n")
	if err := trace.validateOutboundDialer(dialStartIdx, client.Pubkey(), remotePubkey); err != nil {
		return err
	}

	return nil
}

type wireMessage struct {
	From      string `json:"from"`
	Data      string `json:"data"`
	Challenge string `json:"challenge"`
	Ts        string `json:"ts,omitempty"`
	Sig       string `json:"sig"`
}

type observedSignal struct {
	event connect.SignalEvent
	msg   wireMessage
	ok    bool
}

type signalTrace struct {
	mu     sync.Mutex
	events []observedSignal
}

func newSignalTrace() *signalTrace {
	return &signalTrace{}
}

func (t *signalTrace) observe(event connect.SignalEvent) {
	var msg wireMessage
	raw, err := base64.RawURLEncoding.DecodeString(event.Payload)
	ok := err == nil && json.Unmarshal(raw, &msg) == nil

	direction := ">"
	if event.Direction == connect.SignalInboundSSE {
		direction = "<"
	}
	fmt.Printf("%s %s\n", direction, raw)

	t.mu.Lock()
	t.events = append(t.events, observedSignal{event: event, msg: msg, ok: ok})
	t.mu.Unlock()
}

func (t *signalTrace) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.events)
}

func (t *signalTrace) snapshot(fromIdx int) []observedSignal {
	t.mu.Lock()
	defer t.mu.Unlock()
	src := t.events[fromIdx:]
	out := make([]observedSignal, len(src))
	copy(out, src)
	return out
}

func (t *signalTrace) validateInboundAnswerer(fromIdx int, selfPubkey, remotePubkey string) error {
	events := t.snapshot(fromIdx)
	var offer *wireMessage
	var answerSeen bool
	for i := range events {
		event := events[i]
		if !event.ok {
			return fail("wire.envelope.base64-json", "invalid observed envelope in %s", event.event.Direction)
		}
		msg := event.msg
		if event.event.Direction == connect.SignalInboundSSE && msg.From == remotePubkey {
			if offer == nil {
				if msg.Ts == "" {
					return fail("offer.timestamp", "inbound first message from candidate had no timestamp")
				}
				if err := validateOffer(msg, selfPubkey); err != nil {
					return err
				}
				offer = &msg
			}
		}
		if event.event.Direction == connect.SignalOutboundPOST && event.event.RemotePubkey == remotePubkey {
			if msg.Ts == "" {
				if !answerSeen {
					return fail("answer.before-ice", "tester sent ICE before answer on inbound leg")
				}
				if err := validateICE(msg, offer.Challenge); err != nil {
					return err
				}
				continue
			}
			if offer == nil {
				return fail("answer.after-offer", "tester sent answer before observing offer")
			}
			if answerSeen {
				return fail("answer.once", "tester sent multiple answers on inbound leg")
			}
			if err := validateAnswer(msg, *offer); err != nil {
				return err
			}
			answerSeen = true
		}
	}
	if offer == nil {
		return fail("offer.present", "candidate offer was not observed")
	}
	if !answerSeen {
		return fail("answer.present", "tester answer was not observed")
	}
	return nil
}

func (t *signalTrace) validateOutboundDialer(fromIdx int, selfPubkey, remotePubkey string) error {
	events := t.snapshot(fromIdx)
	var offer *wireMessage
	var answerSeen bool
	for i := range events {
		event := events[i]
		if !event.ok {
			return fail("wire.envelope.base64-json", "invalid observed envelope in %s", event.event.Direction)
		}
		msg := event.msg
		if event.event.Direction == connect.SignalOutboundPOST && event.event.RemotePubkey == remotePubkey && msg.From == selfPubkey {
			if offer != nil && msg.Challenge != offer.Challenge {
				continue
			}
			if msg.Ts == "" {
				if offer == nil {
					continue
				}
				if err := validateICE(msg, offer.Challenge); err != nil {
					return err
				}
				continue
			}
			if offer == nil {
				if validateOffer(msg, remotePubkey) == nil {
					offer = &msg
				}
				continue
			}
		}
		if event.event.Direction == connect.SignalInboundSSE && msg.From == remotePubkey {
			if offer == nil {
				continue
			}
			if msg.Challenge != offer.Challenge {
				continue
			}
			if msg.Ts == "" {
				if !answerSeen {
					return fail("answer.before-ice", "candidate sent ICE before answer on outbound leg")
				}
				if err := validateICE(msg, offer.Challenge); err != nil {
					return err
				}
				continue
			}
			if answerSeen {
				return fail("answer.once", "candidate sent multiple answers on outbound leg")
			}
			if err := validateAnswer(msg, *offer); err != nil {
				return err
			}
			answerSeen = true
		}
	}
	if offer == nil {
		return fail("offer.present", "tester outbound offer was not observed")
	}
	if !answerSeen {
		return fail("answer.present", "candidate answer was not observed")
	}
	return nil
}

func validateOffer(msg wireMessage, expectedRecipient string) error {
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
	recipient, err := base64.RawURLEncoding.DecodeString(expectedRecipient)
	if err != nil {
		return fail("offer.recipient", "expected recipient pubkey was invalid: %v", err)
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

func validateAnswer(msg wireMessage, offer wireMessage) error {
	if msg.Challenge != offer.Challenge {
		return fail("answer.challenge", "answer challenge did not match offer challenge")
	}
	challenge, err := base64.RawURLEncoding.DecodeString(msg.Challenge)
	if err != nil || len(challenge) != 32 {
		return fail("answer.challenge", "challenge was not 32 base64url bytes")
	}
	ts, err := base64.RawURLEncoding.DecodeString(msg.Ts)
	if err != nil || len(ts) != 8 {
		return fail("answer.timestamp", "timestamp was not 8 base64url bytes")
	}
	if err := checkTsWindow(ts, "answer"); err != nil {
		return err
	}
	sender, sig, err := senderAndSig(msg)
	if err != nil {
		return err
	}
	if !ed25519.Verify(sender, answerPayload(challenge, ts, offer.Data, msg.Data), sig) {
		return fail("answer.signature", "answer signature did not verify over exact signaled offer SDP and answer SDP")
	}
	return nil
}

func validateICE(msg wireMessage, sessionChallenge string) error {
	if msg.Ts != "" {
		return fail("ice.no-timestamp", "ICE candidate must not carry a ts field")
	}
	if msg.Challenge != sessionChallenge {
		return fail("ice.challenge", "ICE challenge did not match session offer challenge")
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
	return nil
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

func dialBack(ctx context.Context, client *connect.Client, remotePubkey string, timeout time.Duration) error {
	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()
	done := make(chan error, 1)
	pc, err := client.Dial(dialCtx, remotePubkey, func(pc *webrtc.PeerConnection) {
		label, err := randomChannelLabel()
		if err != nil {
			done <- err
			return
		}
		fmt.Fprintf(os.Stderr, "creating outbound-leg tester data channel label=%s\n", label)
		dc, err := pc.CreateDataChannel(label, nil)
		if err != nil {
			done <- fail("connection-flow.outbound.datachannel.create", "create data channel: %v", err)
			return
		}
		wireChallenge(dc, done)
	})
	if err != nil {
		return fail("connection-flow.outbound.signaling-auth", "dial back signaling/auth failed: %v", err)
	}
	defer pc.Close()

	fmt.Fprintf(os.Stderr, "waiting for outbound-leg challenge/pong\n")
	return waitResult(ctx, done, "connection-flow.outbound.challenge-pong")
}

func wireChallenge(dc *webrtc.DataChannel, done chan<- error) {
	challenge, err := randomChallenge()
	if err != nil {
		done <- err
		return
	}
	expected := "pong:" + challenge

	dc.OnOpen(func() {
		fmt.Fprintf(os.Stderr, "data channel open label=%s sending challenge=%s\n", dc.Label(), challenge[:12])
		if err := dc.SendText("challenge:" + challenge); err != nil {
			done <- fail("connection-flow.challenge.send", "send challenge: %v", err)
		}
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if strings.TrimSpace(string(msg.Data)) != expected {
			done <- fail("connection-flow.challenge.pong", "expected %q, got %q", expected, string(msg.Data))
			return
		}
		fmt.Fprintf(os.Stderr, "received expected pong for challenge=%s\n", challenge[:12])
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
