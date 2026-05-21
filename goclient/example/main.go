// Command example is a terminal chat app demonstrating the connect client.
// It mirrors the JavaScript example: displays your key, listens for incoming
// connections, and lets you dial a peer by their base32 public key.
//
// Usage:
//
//	# Listen for incoming connections
//	go run ./example
//
//	# Dial a peer
//	go run ./example -dial ABCDEFGHIJKLMNOP...
package main

import (
	"bufio"
	"context"
	"encoding/base32"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/pion/webrtc/v4"
	connect "github.com/trustleast/connect/goclient"
)

// b32 is the standard RFC 4648 base32 alphabet without padding,
// matching the base32 encoding used in the JS example.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

var (
	mu sync.Mutex
	dc *webrtc.DataChannel
)

func main() {
	serverURL := flag.String("server", "http://localhost:8080", "connect server URL")
	dialKey := flag.String("dial", "", "peer public key (base32) to dial")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := connect.New(connect.Options{
		ServerURL: *serverURL,
		OnIncoming: func(pc *webrtc.PeerConnection, remotePubkey string) {
			dbg("incoming from", shortKey(remotePubkey))
			setupPC(pc)
			pc.OnDataChannel(func(d *webrtc.DataChannel) {
				if d.Label() != "chat" {
					return
				}
				dbg("got data channel")
				attachChannel(d)
			})
			dbg("auth ok with", shortKey(remotePubkey))
			dbg("type to send, Ctrl+C to quit")
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer client.Close()

	go func() {
		if err := client.Listen(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "listen error:", err)
		}
	}()

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(client.Pubkey())
	if err != nil {
		fmt.Fprintln(os.Stderr, "error decoding public key:", err)
		os.Exit(1)
	}
	fmt.Println("your key:", b32.EncodeToString(pubKeyBytes))

	if *dialKey != "" {
		keyBytes, err := b32.DecodeString(strings.ToUpper(*dialKey))
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid peer key:", err)
			os.Exit(1)
		}
		remotePubkey := base64.RawURLEncoding.EncodeToString(keyBytes)

		dbg("calling", shortKey(remotePubkey))
		pc, err := client.Dial(ctx, remotePubkey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dial error:", err)
			os.Exit(1)
		}
		setupPC(pc)

		chatDC, err := pc.CreateDataChannel("chat", nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, "creating data channel:", err)
			os.Exit(1)
		}
		attachChannel(chatDC)
		dbg("auth ok with", shortKey(remotePubkey))
		dbg("type to send, Ctrl+C to quit")
	} else {
		dbg("listening for incoming connections...")
	}

	go readStdin()
	<-ctx.Done()
}

func readStdin() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		mu.Lock()
		d := dc
		mu.Unlock()
		if d == nil || d.ReadyState() != webrtc.DataChannelStateOpen {
			dbg("not connected yet")
			continue
		}
		if err := d.SendText(line); err != nil {
			dbg("send error:", err)
			continue
		}
		fmt.Println(">", line)
	}
	if err := scanner.Err(); err != nil {
		dbg("stdin error:", err)
	}
}

func attachChannel(d *webrtc.DataChannel) {
	mu.Lock()
	dc = d
	mu.Unlock()

	d.OnOpen(func() { dbg("channel open:", d.Label()) })
	d.OnClose(func() {
		dbg("channel closed")
		mu.Lock()
		if dc == d {
			dc = nil
		}
		mu.Unlock()
	})
	d.OnError(func(err error) { dbg("channel error:", err) })
	d.OnMessage(func(msg webrtc.DataChannelMessage) {
		fmt.Println("<", string(msg.Data))
	})
}

func setupPC(pc *webrtc.PeerConnection) {
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) { dbg("ice:", s) })
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) { dbg("connection:", s) })
	pc.OnSignalingStateChange(func(s webrtc.SignalingState) { dbg("signaling:", s) })
}

func shortKey(base64Key string) string {
	b, _ := base64.RawURLEncoding.DecodeString(base64Key)
	s := b32.EncodeToString(b)
	if len(s) > 8 {
		return s[:8] + "…"
	}
	return s
}

func dbg(args ...any) {
	fmt.Fprint(os.Stderr, "# ")
	fmt.Fprintln(os.Stderr, args...)
}
