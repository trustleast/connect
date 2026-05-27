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

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	inboundDone := make(chan error, 1)
	client, err := connect.New(connect.Options{
		ServerURL: serverURL,
		AcceptConnection: func(remotePubkey string) bool {
			return true
		},
		OnIncoming: func(pc *webrtc.PeerConnection, remotePubkey string) {
			pc.OnDataChannel(func(dc *webrtc.DataChannel) {
				respondToChallenge(dc, inboundDone)
			})
		},
	})
	if err != nil {
		return fmt.Errorf("create candidate client: %w", err)
	}
	defer client.Close()

	listenErr := make(chan error, 1)
	go func() {
		listenErr <- client.Listen(ctx)
	}()

	outboundDone := make(chan error, 1)
	pc, err := client.Dial(ctx, remotePubkey,
		connect.WithDialTimeout(*dialTimeout),
		connect.WithDialSetup(func(pc *webrtc.PeerConnection) {
			pc.CreateDataChannel("test", nil)
			pc.OnDataChannel(func(dc *webrtc.DataChannel) {
				respondToChallenge(dc, outboundDone)
			})
		}),
	)
	if err != nil {
		return fmt.Errorf("outbound signaling/auth failed: %w", err)
	}
	defer pc.Close()

	if err := waitResult(ctx, outboundDone, "outbound challenge"); err != nil {
		return err
	}
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

	return nil
}

func respondToChallenge(dc *webrtc.DataChannel, done chan<- error) {
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		text := strings.TrimSpace(string(msg.Data))
		if !strings.HasPrefix(text, "challenge:") {
			done <- fmt.Errorf("unexpected challenge message: %q", string(msg.Data))
			return
		}
		if err := dc.SendText("pong:" + strings.TrimPrefix(text, "challenge:")); err != nil {
			done <- fmt.Errorf("send pong: %w", err)
			return
		}
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
