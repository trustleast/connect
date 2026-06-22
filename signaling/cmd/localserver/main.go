package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"connect"
)

func main() {
	ctx := context.Background()
	if err := run(ctx); err != nil {
		for {
			log.Println("fatal:", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func run(ctx context.Context) error {
	addr := flag.String("addr", ":8080", "TCP listen address")
	network := flag.String("network", "tcp", "listen network (tcp, tcp4, tcp6)")
	gossipAddr := flag.String("gossip-addr", ":9876", "UDP address for gossip")
	gossipPeers := flag.String("gossip-peers", "", "comma-separated peer gossip UDP addresses")
	proxyURL := flag.String("proxy-url", "", "this node's internal HTTP base URL (e.g. http://localhost:8080)")
	flag.Parse()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, *network, *addr)
	if err != nil {
		return fmt.Errorf("listen %s %s: %w", *network, *addr, err)
	}

	var pp connect.PeerProvider
	if *gossipPeers != "" {
		var peers []*net.UDPAddr
		for _, s := range strings.Split(*gossipPeers, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			a, err := net.ResolveUDPAddr("udp", s)
			if err != nil {
				return fmt.Errorf("resolving gossip peer %q: %w", s, err)
			}
			peers = append(peers, a)
		}
		pp = &staticPeerProvider{
			proxyURL:   *proxyURL,
			gossipAddr: *gossipAddr,
			peers:      peers,
			onChange:   make(chan struct{}),
		}
	}

	fmt.Println("Listening on:", *network, *addr)
	srv, err := connect.NewHTTPServer(ctx, pp)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// staticPeerProvider implements connect.PeerProvider with a fixed peer list.
// OnChange returns a channel that is never written to (the peer set never changes).
type staticPeerProvider struct {
	proxyURL   string
	gossipAddr string
	peers      []*net.UDPAddr
	onChange   chan struct{}
}

func (p *staticPeerProvider) Self() string              { return p.proxyURL }
func (p *staticPeerProvider) GossipAddr() string        { return p.gossipAddr }
func (p *staticPeerProvider) Peers() []*net.UDPAddr     { return p.peers }
func (p *staticPeerProvider) OnChange() <-chan struct{} { return p.onChange }
