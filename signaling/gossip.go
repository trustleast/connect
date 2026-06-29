package connect

import (
	"bytes"
	"context"
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
	_PeerTimeout    = 30 * time.Second
	_MaxGossipBody  = 128 << 10 // 128 KB — comfortably above max filter at 30k keys (~37 KB)
)

// peerSnapshot holds the most recently received gossip state from a remote node.
type peerSnapshot struct {
	ts     int64 // unix nanos when this snapshot was received
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
	filter      *xorfilter.BinaryFuse[uint8]
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
	go g.trackPeerChanges(ctx)
	go g.periodicBroadcast(ctx)
	return g
}

// listen starts the periodic broadcast and peer-change tracking goroutines.
func (g *gossip) listen(ctx context.Context) {

}

func (g *gossip) trackPeerChanges(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-g.pp.OnChange():
			if !ok {
				return
			}
			g.broadcast()
		}
	}
}

// broadcast rebuilds the filter from the current hub state and POSTs it to all
// known peers. Called by the server on SSE connect/disconnect and on peer changes.
func (g *gossip) broadcast() {
	peers := g.pp.Peers()
	g.mu.Lock()
	g.filter = g.hub.buildFilter()
	filterData := serializeFilter(g.filter)
	g.mu.Unlock()

	for _, peerURL := range peers {
		peerURL := peerURL
		go g.postTo(peerURL, filterData)
	}
}

func (g *gossip) postTo(gossipBaseURL string, filterData []byte) {
	req, err := http.NewRequest(http.MethodPost, gossipBaseURL+"/gossip", bytes.NewReader(filterData))
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
	if r.Method != http.MethodPost || r.URL.Path != "/gossip" {
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
	ts := time.Now().UnixNano()

	g.mu.Lock()
	g.peerByProxy[fromURL] = &peerSnapshot{ts: ts, filter: filter}
	g.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// findPeer returns the proxy base URL of the peer most likely to hold pubkey,
// picking the peer with the most recent gossip timestamp among those whose
// filter claims the key. Returns "", false if no live peer matches.
func (g *gossip) findPeer(pubkey string) (string, bool) {
	h := pubkeyToUint64(pubkey)
	deadline := time.Now().UnixNano() - int64(_PeerTimeout)
	g.mu.RLock()
	defer g.mu.RUnlock()
	var bestURL string
	var best *peerSnapshot
	for proxyURL, ps := range g.peerByProxy {
		if ps.ts < deadline || ps.filter == nil {
			continue
		}
		if ps.filter.Contains(h) {
			if best == nil || ps.ts > best.ts {
				best = ps
				bestURL = proxyURL
			}
		}
	}
	if best == nil {
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
			g.broadcast()
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
