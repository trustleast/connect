package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"connect"
)

// serverConfig is the fully resolved runtime configuration. JSON tags allow it
// to be decoded directly from the S3 cluster config; CLI-only fields use
// json:"-". Priority: defaults → S3 → explicit CLI flags (see getConfig).
type serverConfig struct {
	Addr    string
	Network string
}

func getConfig(ctx context.Context) (serverConfig, error) {
	// 1. Sensible defaults.
	cfg := serverConfig{
		Addr:    ":8080",
		Network: "tcp",
	}

	// Define flags. Defaults match cfg above so the usage text is accurate, but
	// cfg is the authoritative default — flag values are only applied when the
	// flag was explicitly set on the command line (see flag.Visit below).
	addr := flag.String("addr", cfg.Addr, "listen address")
	network := flag.String("network", cfg.Network, "listen network (tcp, tcp4, tcp6)")
	flag.Parse()

	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "addr":
			cfg.Addr = *addr
		case "network":
			cfg.Network = *network
		}
	})

	return cfg, nil
}

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
	nodeURL := flag.String("url", "", "The url pointing to this node")
	peers := flag.String("peers", "", "comma-separated static peer base URLs, e.g. http://localhost:8081,http://localhost:8082")
	secret := flag.String("secret", "", "The secret to seed the peer finder with")
	flag.Parse()

	cfg, err := getConfig(ctx)
	if err != nil {
		return fmt.Errorf("getting config: %w", err)
	}

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, cfg.Network, cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s %s: %w", cfg.Network, cfg.Addr, err)
	}

	var peerFinder connect.PeerFinder
	if peers := strings.Split(*peers, ","); len(peers) > 0 && *nodeURL != "" {
		pf, err := newStaticPeerFinder(*nodeURL, peers, *secret)
		if err != nil {
			return err
		}
		peerFinder = pf
	}

	fmt.Println("Listening on:", cfg.Network, cfg.Addr)
	srv := connect.NewHTTPServer(ctx, peerFinder)
	return srv.Serve(ln)
}

// staticPeerFinder implements connect.PeerFinder for a fixed peer list.
// OnChange returns a channel that is never written to because the peer set never changes.
type staticPeerFinder struct {
	nodeURL  *url.URL
	peers    []*url.URL
	onChange chan struct{}
	secret   [32]byte
}

func newStaticPeerFinder(nodeURL string, peerStrs []string, secret string) (*staticPeerFinder, error) {
	u, err := url.Parse(nodeURL)
	if err != nil {
		return nil, err
	}
	peerURLs := make([]*url.URL, 0, len(peerStrs))
	for _, p := range peerStrs {
		u, err := url.Parse(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		peerURLs = append(peerURLs, u)
	}
	return &staticPeerFinder{
		nodeURL:  u,
		peers:    peerURLs,
		onChange: make(chan struct{}),
		secret:   sha256.Sum256([]byte(secret)),
	}, nil
}

func (f *staticPeerFinder) Node() *url.URL            { return f.nodeURL }
func (f *staticPeerFinder) Peers() []*url.URL         { return f.peers }
func (f *staticPeerFinder) OnChange() <-chan struct{} { return f.onChange }
func (f *staticPeerFinder) Secret() [32]byte          { return f.secret }
