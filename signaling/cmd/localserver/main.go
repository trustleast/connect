package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
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
	gossipAddr := flag.String("gossip-addr", ":9876", "TCP listen address for internal gossip server")
	gossipPeers := flag.String("gossip-peers", "", "comma-separated peer gossip base URLs (e.g. http://localhost:9877)")
	proxyURL := flag.String("proxy-url", "", "this node's public HTTP base URL (e.g. http://localhost:8080)")
	flag.Parse()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, *network, *addr)
	if err != nil {
		return fmt.Errorf("listen %s %s: %w", *network, *addr, err)
	}

	var pp connect.PeerProvider
	if *gossipPeers != "" {
		var peers []string
		for _, s := range strings.Split(*gossipPeers, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			peers = append(peers, s)
		}
		pp = &staticPeerProvider{
			proxyURL: *proxyURL,
			peers:    peers,
		}
	}

	fmt.Println("Listening on:", *network, *addr)
	srvs := connect.NewServers(ctx, pp)

	if srvs.Gossip != nil {
		gossipLn, err := lc.Listen(ctx, "tcp", *gossipAddr)
		if err != nil {
			return fmt.Errorf("gossip listen %s: %w", *gossipAddr, err)
		}
		go func() {
			if err := srvs.Gossip.Serve(gossipLn); err != nil && err != http.ErrServerClosed {
				log.Printf("gossip server: %v", err)
			}
		}()
	}

	return srvs.Public.Serve(ln)
}

// staticPeerProvider implements connect.PeerProvider with a fixed peer list.
type staticPeerProvider struct {
	proxyURL string
	peers    []string
}

func (p *staticPeerProvider) Self() string    { return p.proxyURL }
func (p *staticPeerProvider) Peers() []string { return p.peers }
