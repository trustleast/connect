package connect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/FastFilter/xorfilter"
)

const (
	_GossipInterval = 5 * time.Second
	_GossipPath     = "/gossip"
	_PeerTimeout    = 30 * time.Second
	_MaxGossipBody  = 128 << 10 // 128 KB — comfortably above max filter at 30k keys (~37 KB)
)

// peerSnapshot holds the most recently received gossip state from a remote node.
type peerSnapshot struct {
	ts     time.Time // unix nanos when this snapshot was received
	filter *xorfilter.BinaryFuse[uint8]
}

// gossip manages intra-AZ presence gossip over HTTP.
//
// Each node periodically POSTs a BinaryFuse[uint8] filter of its locally
// connected SSE pubkeys to peer internal gossip endpoints. On a POST hub miss,
// the server calls findPeer to locate a peer that likely holds the target key.
//
// gossip implements http.Handler; serve it on a separate internal-only listener.
type gossip struct {
	proxyURL    string
	proxyScheme string // scheme parsed from pp.Self() — "http" or "https"
	proxyPort   string // port parsed from pp.Self()
	hub         *hub
	pp          PeerProvider
	client      *http.Client

	mu          sync.RWMutex
	peerByProxy map[string]*peerSnapshot // keyed by sender's derived proxy URL
}

func newGossip(ctx context.Context, pp PeerProvider, h *hub) *gossip {
	u, _ := url.Parse(pp.Self())
	scheme := u.Scheme
	_, port, _ := net.SplitHostPort(u.Host)
	g := &gossip{
		proxyURL:    pp.Self(),
		proxyScheme: scheme,
		proxyPort:   port,
		hub:         h,
		pp:          pp,
		client:      &http.Client{Timeout: 5 * time.Second},
		peerByProxy: make(map[string]*peerSnapshot),
	}
	go g.periodicBroadcast(ctx)
	return g
}

// broadcast rebuilds the filter from the current hub state and POSTs it to all known peers.
func (g *gossip) broadcast(ctx context.Context) {
	peers := g.pp.Peers()
	filter := g.hub.buildFilter()
	filterData := serializeFilter(filter)

	for _, peerURL := range peers {
		g.postTo(ctx, peerURL, filterData)
	}
}

func (g *gossip) postTo(ctx context.Context, gossipBaseURL string, filterData []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gossipBaseURL+_GossipPath, bytes.NewReader(filterData))
	if err != nil {
		return
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// ServeHTTP handles incoming gossip POSTs on the internal listener.
// Only POST /gossip is accepted; everything else returns 404.
func (g *gossip) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != _GossipPath {
		http.NotFound(w, r)
		return
	}

	senderIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		http.Error(w, "invalid remote addr", http.StatusBadRequest)
		return
	}
	fromURL := fmt.Sprintf("%s://%s", g.proxyScheme, net.JoinHostPort(senderIP, g.proxyPort))

	body, err := io.ReadAll(io.LimitReader(r.Body, _MaxGossipBody+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if len(body) > _MaxGossipBody {
		http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
		return
	}

	filter := deserializeFilter(body)
	ts := time.Now()

	g.mu.Lock()
	g.peerByProxy[fromURL] = &peerSnapshot{ts: ts, filter: filter}
	g.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// nodeToken computes the deterministic routing token for pubkey on proxyURL.
// The token is the first 8 bytes of SHA-256(pubkey || proxyURL), base64url-encoded.
// It is used both for generation (self) and verification (scanning known peers).
func nodeToken(pubkey, proxyURL string) string {
	h := sha256.New()
	h.Write([]byte(pubkey))
	h.Write([]byte(proxyURL))
	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

// tokenFor returns the node token for pubkey on this node.
// The client receives this token on SSE connect and shares it with its peer,
// who can attach it to POST requests to route directly to this node.
func (g *gossip) tokenFor(pubkey string) string {
	return nodeToken(pubkey, g.proxyURL)
}

// findPeer returns the proxy base URL of the peer most likely to hold pubkey,
// using gossip filter membership. When token is non-empty it is used as a
// tie-breaker: if multiple peers' filters claim the key, the peer whose computed
// token matches wins over the most-recent-timestamp heuristic.
// Returns "", false if no live peer's filter claims the key.
func (g *gossip) findPeer(pubkey, token string) (string, bool) {
	h := pubkeyToUint64(pubkey)
	deadline := time.Now().Add(-_PeerTimeout)
	g.mu.RLock()
	defer g.mu.RUnlock()
	var bestURL string
	var missingMatchURL string
	var best *peerSnapshot
	for proxyURL, ps := range g.peerByProxy {
		if ps.ts.Before(deadline) || ps.filter == nil {
			continue
		}

		// Store the missingMatchURL in case we have no candidates and fall back to that
		tokenMatch := false
		if token != "" && nodeToken(pubkey, proxyURL) == token {
			tokenMatch = true
			missingMatchURL = proxyURL
		}
		if ps.filter.Contains(h) {
			// Token match wins immediately — prefer the authoritative node over
			// the most-recently-seen heuristic when filters have false positives.
			if tokenMatch {
				return proxyURL, true
			}

			if best == nil || ps.ts.After(best.ts) {
				best = ps
				bestURL = proxyURL
			}
		}
	}
	if best == nil {
		if missingMatchURL != "" {
			return missingMatchURL, true
		}
		return "", false
	}
	return bestURL, true
}

func (g *gossip) periodicBroadcast(ctx context.Context) {
	tick := time.NewTicker(_GossipInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			g.broadcast(ctx)
		}
	}
}

func serializeFilter(f *xorfilter.BinaryFuse[uint8]) []byte {
	if f == nil {
		return nil
	}
	var buf bytes.Buffer
	if err := f.Save(&buf); err != nil {
		return nil
	}
	return buf.Bytes()
}

func deserializeFilter(data []byte) *xorfilter.BinaryFuse[uint8] {
	if len(data) == 0 {
		return nil
	}
	f, err := xorfilter.LoadBinaryFuse[uint8](bytes.NewReader(data))
	if err != nil {
		return nil
	}
	return f
}
