// ping is a minimal WebRTC connectivity probe.
//
// Usage:
//
//	# Listen mode — print your pubkey and wait for a ping:
//	go run ./cmd/ping
//
//	# Dial mode — send a ping to the remote key and exit on pong:
//	go run ./cmd/ping -remote <pubkey>
//
// Flags:
//
//	-server   relay server URL (default: https://connect.peerwave.ai)
//	-remote   remote pubkey to dial (omit to run in listen mode)
//	-timeout  total timeout (default 60s)
//	-ice      comma-separated STUN/TURN URLs (default: stun:stun.l.google.com:19302)
//	-mdns     enable mDNS candidate gathering (default false)
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/pion/webrtc/v4"
	connect "github.com/trustleast/connect/goclient"
)

func main() {
	remote := flag.String("remote", "", "remote pubkey to dial (listen mode if empty)")
	timeout := flag.Duration("timeout", 60*time.Second, "total timeout")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	c, err := connect.New(
		connect.WithOnSignal(func(e connect.SignalEvent) {
			dir := "recv"
			if e.Direction == connect.SignalOutboundPOST {
				dir = "send"
			}
			fmt.Printf("[signal %s] %s\n", dir, decodePayload(e.Payload))
		}),
		connect.WithAcceptConnection(func(remotePubkey string) bool {
			fmt.Printf("[accept] inbound from %s\n", remotePubkey)
			return *remote == ""
		}),
		connect.WithOnIncoming(func(pc *webrtc.PeerConnection, remotePubkey string) {
			fmt.Printf("[incoming] offer verified from %s\n", remotePubkey)

			pc.OnConnectionStateChange(func(pcs webrtc.PeerConnectionState) {
				fmt.Println("Connection state:", pcs)
			})

			pc.OnDataChannel(func(dc *webrtc.DataChannel) {
				fmt.Printf("[dc] new data channel: %s\n", dc.Label())
				dc.OnMessage(func(msg webrtc.DataChannelMessage) {
					text := string(msg.Data)
					fmt.Printf("[dc msg] received: %q\n", text)
					if text == "ping" {
						fmt.Printf("[dc msg] sending pong\n")
						if err := dc.SendText("pong"); err != nil {
							log.Printf("send pong: %v", err)
						}
					}
				})
			})
		}),
	)
	if err != nil {
		log.Fatalf("create client: %v", err)
	}
	defer c.Close()

	fmt.Println(c.Pubkey())

	if *remote != "" {
		go c.Listen(ctx)
		time.Sleep(1 * time.Second) // wait for Listen to set up before dialing
		if err := dial(ctx, c, *remote); err != nil {
			log.Fatalf("dial: %v", err)
		} else {
			fmt.Printf("[done] ping/pong complete, connection succeeded\n")
		}
	} else {
		c.Listen(ctx)
	}
}

func dial(ctx context.Context, c *connect.Client, remote string) error {
	pingDone := make(chan error, 1)
	pc, err := c.Dial(ctx, remote, func(pc *webrtc.PeerConnection) {
		pc.OnConnectionStateChange(func(pcs webrtc.PeerConnectionState) {
			fmt.Println("Connection state:", pcs)
		})
		dc, err := pc.CreateDataChannel("ping", nil)
		if err != nil {
			log.Fatalf("create data channel: %v", err)
		}
		dc.OnOpen(func() {
			fmt.Printf("[dc open] label=%s sending ping\n", dc.Label())
			if err := dc.SendText("ping"); err != nil {
				pingDone <- fmt.Errorf("send ping: %w", err)
			}
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			text := string(msg.Data)
			fmt.Printf("[dc msg] received: %q\n", text)
			if text == "pong" {
				pingDone <- nil
			} else {
				pingDone <- fmt.Errorf("expected pong, got %q", text)
			}
		})
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	fmt.Println("Dial completed")
	defer pc.Close()

	select {
	case err := <-pingDone:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		return fmt.Errorf("timeout: %w", ctx.Err())
	}

	return nil
}

// decodePayload base64url-decodes the wire payload, returning the raw JSON bytes.
func decodePayload(payload string) string {
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return payload
	}
	return string(raw)
}
