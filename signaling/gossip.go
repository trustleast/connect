package connect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"hash/fnv"
	"net"
	"sync"
	"time"

	"github.com/FastFilter/xorfilter"
)

const (
	_GossipInterval = 5 * time.Second
	_PeerTimeout    = 30 * time.Second

	// Gossip UDP packet layout (variable size):
	//   [0:8]      seq        uint64 big-endian (monotone per node)
	//   [8:16]     ts         int64  big-endian (unix nanos, emitted time)
	//   [16:18]    urlLen     uint16 big-endian
	//   [18:82]    proxyURL   [64]byte null-padded UTF-8
	//   [82:86]    filterLen  uint32 big-endian (0 if no active keys)
	//   [86:...]   filter     filterLen bytes (BinaryFuse[uint8].Save format)
	_GossipURLMax  = 64
	_GossipHdrSize = 8 + 8 + 2 + _GossipURLMax + 4 // 86
)

// pubkeyToUint64 maps a raw 32-byte ed25519 public key to a uint64 for the
// BinaryFuse filter. FNV-1a over the full key ensures uniform distribution.
func pubkeyToUint64(raw []byte) uint64 {
	h := fnv.New64a()
	h.Write(raw)
	return h.Sum64()
}

// peerSnapshot holds the most recently received gossip state from a remote node.
type peerSnapshot struct {
	seq      uint64
	ts       int64 // unix nanos when the remote node emitted this packet
	proxyURL string
	filter   *xorfilter.BinaryFuse[uint8] // nil if peer has no active keys
}

// gossip manages intra-AZ presence gossip over UDP.
//
// Each node periodically broadcasts a BinaryFuse[uint8] filter of its locally
// connected SSE pubkeys. On a POST hub miss, the server calls findPeer to
// locate a peer that likely holds the target key.
type gossip struct {
	proxyURL string
	conn     *net.UDPConn
	hub      *hub
	pp       PeerProvider

	mu         sync.RWMutex
	seq        uint64
	filter     *xorfilter.BinaryFuse[uint8] // nil when hub has no clients
	peerByAddr map[string]*peerSnapshot     // keyed by source UDP addr string
}

// newGossip creates a gossip instance bound to the UDP address from pp.
// Returns nil if the address cannot be bound (best-effort; the server still
// functions without gossip, just without intra-AZ proxy routing).
// Call listen to start background goroutines.
func newGossip(pp PeerProvider, h *hub) (*gossip, error) {
	ua, err := net.ResolveUDPAddr("udp", pp.GossipAddr())
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	return &gossip{
		proxyURL:   pp.Self(),
		conn:       conn,
		hub:        h,
		pp:         pp,
		peerByAddr: make(map[string]*peerSnapshot),
	}, nil
}

// listen starts the gossip background goroutines and owns the conn lifetime.
// The conn is closed when ctx is cancelled, which unblocks receive.
func (g *gossip) listen(ctx context.Context) {
	go func() { <-ctx.Done(); g.conn.Close() }()
	go g.trackPeerChanges(ctx)
	go g.periodicBroadcast(ctx)
	go g.receive(ctx)
}

// trackPeerChanges watches pp.OnChange() and broadcasts immediately so new
// peers learn this node's current state.
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

// broadcast rebuilds the filter from the current hub state and sends it to all
// known peers. Called by the server whenever a client connects or disconnects.
func (g *gossip) broadcast() {
	peers := g.pp.Peers()
	g.mu.Lock()
	g.rebuildFilter()
	g.seq++
	pkt := g.buildPacket()
	g.mu.Unlock()
	g.sendTo(pkt, peers)
}

// findPeer returns the internal HTTP proxy base URL of the peer most likely to
// hold pubkey, picking the peer with the most recent gossip timestamp among
// those whose filter claims the key. Returns "", false if no live peer matches.
func (g *gossip) findPeer(pubkey string) (proxyURL string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(pubkey)
	if err != nil {
		return "", false
	}
	h := pubkeyToUint64(raw)
	deadline := time.Now().UnixNano() - int64(_PeerTimeout)
	g.mu.RLock()
	defer g.mu.RUnlock()
	var best *peerSnapshot
	for _, ps := range g.peerByAddr {
		if ps.ts < deadline || ps.filter == nil {
			continue
		}
		if ps.filter.Contains(h) {
			if best == nil || ps.ts > best.ts {
				best = ps
			}
		}
	}
	if best == nil {
		return "", false
	}
	return best.proxyURL, true
}

// rebuildFilter builds g.filter from the hub's current client set.
// Must be called with g.mu held.
func (g *gossip) rebuildFilter() {
	seen := make(map[uint64]struct{})
	g.hub.clients.Range(func(k, _ any) bool {
		raw, err := base64.RawURLEncoding.DecodeString(k.(string))
		if err != nil {
			return true
		}
		seen[pubkeyToUint64(raw)] = struct{}{}
		return true
	})
	if len(seen) == 0 {
		g.filter = nil
		return
	}
	keys := make([]uint64, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	f, err := xorfilter.NewBinaryFuse[uint8](keys)
	if err != nil {
		g.filter = nil
		return
	}
	g.filter = f
}

// buildPacket serialises the current gossip state into a variable-size UDP
// payload. Must be called with g.mu held.
func (g *gossip) buildPacket() []byte {
	filterData := serializeFilter(g.filter)
	pkt := make([]byte, _GossipHdrSize+len(filterData))
	binary.BigEndian.PutUint64(pkt[0:], g.seq)
	binary.BigEndian.PutUint64(pkt[8:], uint64(time.Now().UnixNano()))
	u := []byte(g.proxyURL)
	if len(u) > _GossipURLMax {
		u = u[:_GossipURLMax]
	}
	binary.BigEndian.PutUint16(pkt[16:], uint16(len(u)))
	copy(pkt[18:], u)
	binary.BigEndian.PutUint32(pkt[82:], uint32(len(filterData)))
	copy(pkt[_GossipHdrSize:], filterData)
	return pkt
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

func (g *gossip) sendTo(pkt []byte, peers []*net.UDPAddr) {
	for _, peer := range peers {
		g.conn.WriteTo(pkt, peer) //nolint:errcheck
	}
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

func (g *gossip) receive(ctx context.Context) {
	buf := make([]byte, 32768)
	for {
		n, addr, err := g.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		if n < _GossipHdrSize {
			continue
		}

		seq := binary.BigEndian.Uint64(buf[0:])
		ts := int64(binary.BigEndian.Uint64(buf[8:]))
		urlLen := binary.BigEndian.Uint16(buf[16:])
		if int(urlLen) > _GossipURLMax {
			continue
		}
		proxyURL := string(buf[18 : 18+urlLen])
		filterLen := int(binary.BigEndian.Uint32(buf[82:]))
		if n < _GossipHdrSize+filterLen {
			continue // truncated
		}

		filter := deserializeFilter(buf[_GossipHdrSize : _GossipHdrSize+filterLen])
		addrKey := addr.String()

		g.mu.Lock()
		existing, ok := g.peerByAddr[addrKey]
		if !ok || seq > existing.seq {
			g.peerByAddr[addrKey] = &peerSnapshot{
				seq:      seq,
				ts:       ts,
				proxyURL: proxyURL,
				filter:   filter,
			}
		}
		g.mu.Unlock()
	}
}
