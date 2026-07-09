package connect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
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

// peerRange calls fn for every entry. Returning false stops iteration.
func peerRange(m *sync.Map, fn func(proxyURL string, ps *peerSnapshot) bool) {
	m.Range(func(k, v any) bool {
		return fn(k.(string), v.(*peerSnapshot))
	})
}

// gossip manages intra-AZ presence gossip over HTTP.
//
// Each node periodically POSTs a BinaryFuse[uint8] filter of its locally
// connected SSE pubkeys to peer internal gossip endpoints. On a POST hub miss,
// the server calls findPeer to locate a peer that likely holds the target key.
//
// gossip implements http.Handler; serve it on a separate internal-only listener.
type gossip struct {
	hub    *hub
	pp     PeerProvider
	client *http.Client

	peers sync.Map // *peerSnapshot, keyed by sender's proxy URL (from Connect-Proxy-URL header)
}

func newGossip(ctx context.Context, pp PeerProvider, h *hub, tlsCfg *tls.Config) *gossip {
	transport := &http.Transport{}
	if tlsCfg != nil {
		transport.TLSClientConfig = tlsCfg
	}
	g := &gossip{
		hub: h,
		pp:  pp,
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
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
	req.Header.Set("Connect-Proxy-URL", g.pp.Self())
	resp, err := g.client.Do(req)
	if err != nil {
		fmt.Printf("Error posting to %s: %v\n", gossipBaseURL, err)
		return
	}
	_, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error posting to %s: %v\n", gossipBaseURL, err)
	}
}

// ServeHTTP handles incoming gossip POSTs on the internal listener.
// Only POST /gossip is accepted; everything else returns 404.
func (g *gossip) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != _GossipPath {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	fromURL := r.Header.Get("Connect-Proxy-URL")
	if fromURL == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, _MaxGossipBody+1))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(body) > _MaxGossipBody {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	filter, err := deserializeFilter(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	g.peers.Store(fromURL, &peerSnapshot{ts: time.Now(), filter: filter})

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
	return nodeToken(pubkey, g.pp.Self())
}

// findPeer returns the proxy base URL of the peer most likely to hold pubkey,
// using gossip filter membership. When token is non-empty it is used as a
// tie-breaker: if multiple peers' filters claim the key, the peer whose computed
// token matches wins over the most-recent-timestamp heuristic.
// Returns "", false if no live peer's filter claims the key.
func (g *gossip) findPeer(pubkey, token string) (string, bool) {
	h := pubkeyToUint64(pubkey)
	deadline := time.Now().Add(-_PeerTimeout)
	var bestURL string
	var missingMatchURL string
	var best *peerSnapshot
	g.peers.Range(func(key any, value any) bool {
		proxyURL := key.(string)
		ps := value.(*peerSnapshot)

		fmt.Println("Trying peer", proxyURL, "for pubkey", pubkey, "with token", token, "and filter", ps.filter == nil)

		// Store the missingMatchURL in case we have no candidates and fall back to that
		tokenMatch := false
		if token != "" && nodeToken(pubkey, proxyURL) == token {
			tokenMatch = true
			missingMatchURL = proxyURL
		}

		if ps.ts.Before(deadline) || ps.filter == nil {
			return true
		}
		if ps.filter.Contains(h) {
			// Token match wins immediately — prefer the authoritative node over
			// the most-recently-seen heuristic when filters have false positives.
			if tokenMatch {
				bestURL = proxyURL
				best = ps
				return false // stop iteration
			}

			if best == nil || ps.ts.After(best.ts) {
				best = ps
				bestURL = proxyURL
			}
		}
		return true
	})
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

func deserializeFilter(data []byte) (*xorfilter.BinaryFuse[uint8], error) {
	if len(data) == 0 {
		return nil, nil
	}
	return xorfilter.LoadBinaryFuse[uint8](bytes.NewReader(data))
}
