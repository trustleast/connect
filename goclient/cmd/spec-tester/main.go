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
	serverURL := flag.String("server-url", getenv("CONNECT_URL", "http://localhost:8080"), "connect relay URL")
	timeout := flag.Duration("timeout", 30*time.Second, "overall spec timeout")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "per-dial signaling timeout")
	flag.Parse()

	candidateCmd := flag.Args()
	if len(candidateCmd) == 0 {
		return fmt.Errorf("usage: spec-tester [flags] -- candidate-command [args...]")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	trace := newSignalTrace()
	inboundResult := make(chan inboundConnection, 1)
	client, err := connect.New(connect.Options{
		ServerURL: *serverURL,
		OnSignal:  trace.observe,
		AcceptConnection: func(remotePubkey string) bool {
			fmt.Fprintf(os.Stderr, "accepting inbound connection from %s\n", shortKey(remotePubkey))
			return true
		},
		OnIncoming: func(pc *webrtc.PeerConnection, remotePubkey string) {
			fmt.Fprintf(os.Stderr, "inbound offer accepted from %s\n", shortKey(remotePubkey))
			result := inboundConnection{remotePubkey: remotePubkey, done: make(chan error, 1)}
			inboundResult <- result
			label := uuid.New().String()
			pc.OnConnectionStateChange(func(pcs webrtc.PeerConnectionState) {
				if pcs == webrtc.PeerConnectionStateConnected {
					fmt.Fprintf(os.Stderr, "peer connection state connected for inbound from %s\n", shortKey(remotePubkey))

					dc, err := pc.CreateDataChannel(label, nil)
					if err != nil {
						result.done <- fail("connection-flow.inbound.datachannel.create", "create data channel: %v", err)
					} else {
						wireChallenge(dc, result.done)
					}
				}
			})
		},
	})

	if err != nil {
		return fail("spec-tester.client.create", "create spec client: %v", err)
	}
	defer client.Close()
	fmt.Fprintf(os.Stderr, "tester pubkey=%s\n", client.Pubkey())

	listenErr := make(chan error, 1)
	go func() {
		listenErr <- client.Listen(ctx)
	}()

	candidateDone := make(chan error, 1)
	candidateArgs := append(candidateCmd[1:], *serverURL, client.Pubkey())
	fmt.Fprintf(os.Stderr, "starting candidate: %s %s\n", candidateCmd[0], strings.Join(candidateArgs, " "))
	cmd := exec.CommandContext(ctx, candidateCmd[0], candidateArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fail("spec-tester.candidate.start", "start candidate: %v", err)
	}
	go func() {
		candidateDone <- cmd.Wait()
	}()

	var inbound inboundConnection
	fmt.Fprintf(os.Stderr, "waiting for candidate to dial tester\n")
	select {
	case inbound = <-inboundResult:
		fmt.Fprintf(os.Stderr, "candidate dial observed from %s\n", shortKey(inbound.remotePubkey))
	case err := <-listenErr:
		return fail("spec-tester.listen.before-inbound", "listen failed before inbound dial: %v", err)
	case err := <-candidateDone:
		return fail("spec-tester.candidate.before-inbound", "candidate exited before inbound dial: %v", err)
	case <-ctx.Done():
		return fail("spec-tester.timeout.before-inbound", "%v", ctx.Err())
	}

	fmt.Fprintf(os.Stderr, "waiting for inbound-leg challenge/pong\n")
	if err := waitResult(ctx, inbound.done, "connection-flow.inbound.challenge-pong"); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "validating inbound-leg signaling invariants\n")
	if err := trace.validateInboundAnswerer(client.Pubkey(), inbound.remotePubkey); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "dialing candidate back\n")
	if err := dialBack(ctx, client, inbound.remotePubkey, *dialTimeout); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "validating outbound-leg signaling invariants\n")
	if err := trace.validateOutboundDialer(client.Pubkey(), inbound.remotePubkey); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "waiting for candidate exit\n")
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

type inboundConnection struct {
	remotePubkey string
	done         chan error
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

func (t *signalTrace) snapshot() []observedSignal {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]observedSignal, len(t.events))
	copy(out, t.events)
	return out
}

func (t *signalTrace) validateInboundAnswerer(selfPubkey, remotePubkey string) error {
	events := t.snapshot()
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

func (t *signalTrace) validateOutboundDialer(selfPubkey, remotePubkey string) error {
	events := t.snapshot()
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
	done := make(chan error, 1)
	pc, err := client.Dial(ctx, remotePubkey,
		connect.WithDialTimeout(timeout),
		connect.WithDialSetup(func(pc *webrtc.PeerConnection) {
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
		}),
	)
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
		if err != nil {
			return err
		}
		return nil
	case <-ctx.Done():
		return fail(name, "%v", ctx.Err())
	}
}

func fail(section, format string, args ...any) error {
	return fmt.Errorf("[%s] %s", section, fmt.Sprintf(format, args...))
}

func shortKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12]
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
