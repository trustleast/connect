package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

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
	timeout := flag.Duration("timeout", 30*time.Second, "overall candidate timeout")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "per-dial signaling timeout")
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		return fmt.Errorf("usage: spec-candidate serverURL remote-pubkey")
	}
	serverURL := args[0]
	remotePubkey := args[1]
	logStep("starting candidate server_url=%s remote=%s timeout=%s dial_timeout=%s", serverURL, shortKey(remotePubkey), timeout.String(), dialTimeout.String())

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	inboundDone := make(chan error, 1)
	client, err := connect.New(connect.Options{
		ServerURL: serverURL,
		AcceptConnection: func(remotePubkey string) bool {
			logStep("accepting inbound connection from %s", shortKey(remotePubkey))
			return true
		},
		OnIncoming: func(pc *webrtc.PeerConnection, remotePubkey string) {
			logStep("inbound offer authenticated from %s", shortKey(remotePubkey))
			pc.OnDataChannel(func(dc *webrtc.DataChannel) {
				logStep("inbound data channel observed label=%s", dc.Label())
				respondToChallenge(dc, inboundDone)
			})
		},
	})
	if err != nil {
		return fmt.Errorf("create candidate client: %w", err)
	}
	defer client.Close()
	logStep("candidate pubkey=%s", client.Pubkey())

	listenErr := make(chan error, 1)
	go func() {
		logStep("starting listener")
		listenErr <- client.Listen(ctx)
	}()

	outboundDone := make(chan error, 1)
	logStep("dialing tester %s", shortKey(remotePubkey))
	pc, err := client.Dial(ctx, remotePubkey,
		connect.WithDialTimeout(*dialTimeout),
		connect.WithDialSetup(func(pc *webrtc.PeerConnection) {
			pc.CreateDataChannel("test", nil)
			logStep("installing outbound data channel listener before offer")
			pc.OnDataChannel(func(dc *webrtc.DataChannel) {
				logStep("outbound data channel observed label=%s", dc.Label())
				respondToChallenge(dc, outboundDone)
			})
		}),
	)
	if err != nil {
		return fmt.Errorf("outbound signaling/auth failed: %w", err)
	}
	defer pc.Close()
	logStep("outbound dial authenticated")

	logStep("waiting for outbound challenge")
	if err := waitResult(ctx, outboundDone, "outbound challenge"); err != nil {
		return err
	}
	logStep("waiting for inbound challenge")
	if err := waitResult(ctx, inboundDone, "inbound challenge"); err != nil {
		return err
	}

	select {
	case err := <-listenErr:
		if err != nil && ctx.Err() == nil {
			return fmt.Errorf("listen failed: %w", err)
		}
	default:
	}

	fmt.Println("ok")
	logStep("candidate passed")
	return nil
}

func respondToChallenge(dc *webrtc.DataChannel, done chan<- error) {
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		text := strings.TrimSpace(string(msg.Data))
		logStep("received data channel message label=%s text=%q", dc.Label(), text)
		if !strings.HasPrefix(text, "challenge:") {
			done <- fmt.Errorf("unexpected challenge message: %q", string(msg.Data))
			return
		}
		if err := dc.SendText("pong:" + strings.TrimPrefix(text, "challenge:")); err != nil {
			done <- fmt.Errorf("send pong: %w", err)
			return
		}
		logStep("sent pong label=%s", dc.Label())
		done <- nil
	})
}

func waitResult(ctx context.Context, done <-chan error, name string) error {
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("%s failed: %w", name, err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func logStep(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[spec-candidate] %s %s\n", time.Now().Format("15:04:05.000"), fmt.Sprintf(format, args...))
}

func shortKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12]
}
