# Multi-Region Signaling Architecture

Desired end state for a low-cost, fast, region-aware WebRTC signaling relay.

The relay stays opaque: clients GET an SSE stream and POST bytes to a pubkey. Servers do
not parse SDP, ICE, JSON envelopes, or client message type. All smart routing is in DNS,
node hostnames, HRW, and regional presence filters.

Priority order:

1. Cost
2. Speed
3. Regional reliability

---

## Architecture

```mermaid
flowchart TD
    C["Client"] --> G["connect.example.com<br/>Route53 geo DNS"]

    G --> USE["us-east.connect.example.com<br/>Cloudflare DNS round-robin"]
    G --> EUW["eu-west.connect.example.com<br/>Cloudflare DNS round-robin"]
    G --> APS["ap-southeast.connect.example.com<br/>Cloudflare DNS round-robin"]

    USE --> U1["node-a.us-east"]
    USE --> U2["node-b.us-east"]
    EUW --> E1["node-c.eu-west"]
    EUW --> E2["node-d.eu-west"]
    APS --> A1["node-e.ap-southeast"]

    U1 <-. "private HTTP/UDP" .-> U2
    E1 <-. "private HTTP/UDP" .-> E2
    U1 <-. "direct inter-region UDP/HTTP<br/>presence mesh" .-> E1
    E1 <-. "direct inter-region UDP/HTTP<br/>presence mesh" .-> A1
    U1 <-. "direct inter-region UDP/HTTP<br/>presence mesh" .-> A1
```

| Layer                                    | Owner          | Purpose                                                    |
| ---------------------------------------- | -------------- | ---------------------------------------------------------- |
| `connect.example.com`                    | Route53        | Geo DNS to nearest regional domain                         |
| `{region}.connect.example.com`           | Cloudflare DNS | Regional round-robin over live nodes                       |
| `node-{id}.{region}.connect.example.com` | Cloudflare DNS | Stable node target; CNAMEs to regional domain during drain |

There are no AWS load balancers and no Cloudflare Load Balancers. Cloudflare is DNS for
regional and node records. Inter-node presence traffic uses direct node addresses, not
Cloudflare.

---

## Intra-Cluster Routing (Implemented)

Within a cluster, nodes route POSTs to each other via server-side HTTP proxy. There are no
client-visible redirects within a cluster. Clients POST to any node and receive a 202 if
delivered or a 404 if the target is not connected anywhere in the cluster.

### Node Token

Each node computes a deterministic routing token for each connected client:

```text
node_token(pubkey, proxy_url) = base64url( sha256(pubkey || proxy_url)[:8] )
```

The token is sent to the client as the first SSE data line immediately after the stream opens:

```
data: <token>\n\n
```

Clients include the token as the `token` field in offer wire messages (not signed — it is
a routing hint, not an identity claim). The answerer appends it as `?t=<token>` on POST
requests back to the dialer. The server uses it to locate the dialer's home node directly.

`?t=<token>` solves two distinct problems:

1. **Pre-gossip delivery** — gossip propagates every 5 seconds. A token lets a node route
   a POST immediately after the dialer connects, before any broadcast has gone out. The
   token identifies the home node even when no peer filter yet contains the key.

2. **False-positive tie-breaking** — `BinaryFuse[uint8]` is probabilistic. When multiple
   peers' filters claim a key, the token deterministically selects the correct peer instead
   of falling back to a recency heuristic.

In the future the same token mechanism can be extended for cross-region routing: a dialer's
token encodes which node (and implicitly which region) they connected to, giving the answerer
a direct routing hint across regions without a separate presence lookup.

### Gossip

Each node maintains a `BinaryFuse[uint8]` filter over its locally-connected SSE pubkeys.
Every 5 seconds, the node POSTs the serialized filter to each known peer's `/gossip`
endpoint. The sender identifies itself in the `X-Proxy-URL` request header. The receiver
stores the snapshot keyed by that URL with a 30-second expiry.

```
POST /gossip HTTP/1.1
X-Proxy-URL: https://[2001:db8::1]:8080
Content-Type: application/octet-stream

<serialized BinaryFuse[uint8]>
```

Peers are discovered via `PeerProvider.Peers()` (e.g. EC2 ASG polling every 30s).

### POST Routing Within a Cluster

On a local hub miss, the node runs the following lookup sequence:

1. **Token fast path** — if `?t=<token>` is present, scan known peers for the one where
   `node_token(pubkey, peer_url) == token`. Proxy to that peer if found. Does not require
   the peer to have a filter.

2. **Filter scan with token tie-breaker** — scan `peerByProxy` for peers whose filter
   contains the pubkey. If the token matches a peer but its filter predates the connection
   (key not yet included), that peer is still selected as a best-effort fallback
   (`missingMatchURL`). Among filter matches, the most recently seen peer wins unless the
   token identifies a specific one.

3. **404** — if no peer claims the key.

`X-Internal-Relay: 1` is set on proxied requests to prevent proxy loops; a node that
receives a proxied request never re-proxies it.

### Intra-Cluster Routing Rules

| Request param/header | Behavior                                                                              |
| -------------------- | ------------------------------------------------------------------------------------- |
| `?t=<token>`         | Bypass filter scan; proxy to the matching peer's proxy URL                            |
| `X-Internal-Relay`   | Already proxied; attempt local deliver only, return 404 on miss — never re-proxy      |
| (none)               | Local deliver first; fall back to filter scan; 404 on total miss                      |

---

## Cross-Region Routing (Planned)

The following architecture is the intended future state. It is not yet implemented.

Hostnames carry the routing budget:

| Request host    | Meaning                    | Server behavior                                                                        |
| --------------- | -------------------------- | -------------------------------------------------------------------------------------- |
| Regional host   | First regional hop         | Normal lookup; usually 307 to a node or region                                         |
| Own node host   | Arrived at intended node   | Normal lookup; deliver only if this node is still the target                           |
| Other node host | DNS drain/failure fallback | Recompute current target; 307 if target differs, 404 if it points back to the bad host |

GET establishes where a pubkey listens. POST looks for the pubkey. Every POST checks
the current region filter first:

1. If the key is in this region, proxy internally to the node that holds the connection.
2. If the key is not in this region, 307 to the region selected by distributed presence.
3. If a drained/stale hostname recomputes to itself, return 404 instead of looping.

---

## Flow: SSE GET

```mermaid
sequenceDiagram
    participant C as Client
    participant R53 as Route53
    participant DNS as Cloudflare DNS
    participant N1 as Entry node
    participant N2 as HRW owner

    C->>R53: GET connect.example.com/{pubkey}
    R53-->>C: nearest region domain
    C->>DNS: GET us-east.connect.example.com/{pubkey}
    DNS->>N1: round-robin
    N1->>N1: HRW(pubkey) = N2
    N1-->>C: 307 node-b.us-east.connect.example.com/{pubkey}
    C->>DNS: GET node-b.us-east.connect.example.com/{pubkey}
    DNS->>N2: node target
    N2-->>C: 200 text/event-stream
```

Clients reconnect from their configured server URL, not from cached node URLs. The node
URL is an implementation detail of redirect handling.

---

## Flow: POST In Region

```mermaid
sequenceDiagram
    participant C as Client
    participant N1 as Entry node
    participant N2 as HRW owner
    participant H as SSE listener

    C->>N1: POST us-east.connect.example.com/{pubkey}
    N1->>N1: us-east filter contains pubkey
    N1->>N1: HRW(pubkey) = N2
    N1-->>C: 307 node-b.us-east.connect.example.com/{pubkey}
    C->>N2: POST node-b.us-east.connect.example.com/{pubkey}
    N2->>N2: host = self and us-east filter contains pubkey
    N2->>H: hub.deliver(bytes)
    N2-->>C: 202
```

The POST body is never inspected. The in-region reroute is a 307 so the client repeats
the same opaque POST body at the current HRW owner.

---

## Flow: POST Wrong Region

Each region publishes one region-level presence filter:

```text
region_filter[region].Contains(pubkey)
```

The filter says which region probably has the pubkey, not which node has it. POSTs do
not become server-side cross-region forwards. A cluster looks locally; on miss, it sends
the client a 307 to the next candidate cluster so the client repeats the same opaque
POST body there.

```mermaid
sequenceDiagram
    participant C as Client
    participant U as us-east node
    participant E1 as eu-west entry
    participant E2 as eu-west HRW owner
    participant H as Bob SSE listener

    C->>U: POST us-east.connect.example.com/{bob}
    U->>U: us-east filter misses bob
    U->>U: eu-west filter contains bob
    U-->>C: 307 eu-west.connect.example.com/{bob}
    C->>E1: POST eu-west.connect.example.com/{bob}
    E1->>E1: eu-west filter contains bob
    E1->>E1: HRW(bob) = E2
    E1-->>C: 307 node-d.eu-west.connect.example.com/{bob}
    C->>E2: POST node-d.eu-west.connect.example.com/{bob}
    E2->>E2: host = self and eu-west filter contains bob
    E2->>H: hub.deliver(bytes)
    E2-->>C: 202
```

Candidate order is nearest matching region filters first, then the remaining regions in
a deterministic ring. Any search state is encoded by the server in the 307 target URL;
clients only follow redirects. If the search is exhausted, return 404.

---

## Presence Distribution

Each region maintains one logical filter:

```text
region_filter = xor8(all active SSE pubkeys in this region)
```

Simplest topology: full mesh.

```mermaid
flowchart TD
    subgraph USE["us-east"]
        U1["node-a"]
        U2["node-b"]
        UF["us-east region filter"]
        U1 <-->|"local listener deltas"| U2
        U1 --> UF
        U2 --> UF
    end

    subgraph EUW["eu-west"]
        E1["node-c"]
        E2["node-d"]
        EF["eu-west region filter"]
        E1 <-->|"local listener deltas"| E2
        E1 --> EF
        E2 --> EF
    end

    subgraph APS["ap-southeast"]
        A1["node-e"]
        A2["node-f"]
        AF["ap-southeast region filter"]
        A1 <-->|"local listener deltas"| A2
        A1 --> AF
        A2 --> AF
    end

    UF <-. "full mesh<br/>signed filter" .-> EF
    UF <-. "full mesh<br/>signed filter" .-> AF
    EF <-. "full mesh<br/>signed filter" .-> AF
```

Presence rules:

- On SSE open, the owner adds the pubkey to the local region set.
- On SSE close, the owner removes the pubkey from the local region set.
- Nodes in the same region exchange listener add/remove deltas directly.
- Each region publishes a signed full region filter to every other region.
- Full filters are sent every 5-10s at first; 60s is acceptable after delta repair exists.
- UDP can announce a new filter version; HTTP can fetch the full filter if needed.

The filter is only a routing hint. A false positive causes one extra 307. A false
negative causes the search to continue to the next region.

---

## Flow: Node Joins

```mermaid
sequenceDiagram
    participant ASG as Autoscaling
    participant DNS as Cloudflare DNS controller
    participant N3 as new node
    participant N1 as existing node
    participant C as Client

    ASG->>N3: launch
    N3->>N3: derive node_id and join peer set
    ASG->>DNS: launch lifecycle event
    DNS->>DNS: add node-c.us-east to regional round-robin
    N1->>N1: peer set changed<br/>recompute HRW for local SSE clients
    N1--xC: close SSE for clients now owned by node-c
    C->>DNS: reconnect GET us-east.connect.example.com/{pubkey}
    DNS->>N1: regional round-robin
    N1-->>C: 307 node-c.us-east.connect.example.com/{pubkey}
    C->>N3: GET node-c.us-east.connect.example.com/{pubkey}
    N3-->>C: 200 text/event-stream
```

This keeps GET ownership aligned with HRW after scale-out. The disconnect is intentional
and bounded to keys whose owner changed.

---

## Flow: Node Terminates

```mermaid
sequenceDiagram
    participant ASG as Autoscaling
    participant DNS as Cloudflare DNS controller
    participant N as terminating node
    participant C as Client
    participant R as Regional pool

    ASG->>DNS: termination lifecycle event
    DNS->>DNS: remove node from regional round-robin
    DNS->>DNS: node-a.us-east CNAME us-east.connect.example.com
    ASG->>N: terminate
    N--xC: SSE closes or times out
    C->>R: reconnect via connect.example.com or regional domain
    R-->>C: 307 to current HRW owner
```

Abrupt failure follows the same end state after health detection. Other nodes cache a
failed peer after the first timeout so redirects stop pointing at a dead HRW owner.

---

## Failure Cases

```mermaid
flowchart TD
    P["POST /pubkey"] --> F{"current region<br/>filter contains key?"}
    F -->|yes| H["compute local HRW hostname"]
    H --> S{"target host differs<br/>from request host?"}
    S -->|yes| R1["307 to local HRW node"]
    S -->|no, host is self| D["deliver locally"]
    S -->|no, host is stale/other| NF["404"]
    D -->|hit| OK["202"]
    D -->|miss| NF
    F -->|no| X{"foreign region<br/>filter match?"}
    X -->|yes| R2["307 to matching region"]
    X -->|no| R3["307 to next region in ring"]
    R1 --> C2["client repeats same POST body"]
    R2 --> C2
    R3 --> C2
    C2 -->|found| OK
    C2 -->|search exhausted| NF
```

Expected misses:

| Case                                      | Result                                                                                |
| ----------------------------------------- | ------------------------------------------------------------------------------------- |
| Filter false positive                     | One extra 307 to a region that returns 404 or continues the search                    |
| Filter false negative                     | 307 search continues to the next region in the deterministic ring                     |
| Dead local owner                          | Redirect target is suppressed after health detection or peer timeout                  |
| Old node hostname CNAMEs to regional pool | Receiver recomputes target; 307 if different, 404 if it points back to the stale host |

---

## Rough Costs

Assumptions: xor8 at ~9.1 bits/key, direct inter-region presence mesh, and one filter
per region. Initial full-filter cadence is 10s; 60s is the later target once delta
repair exists.

| Scope                                        | Bandwidth estimate                                                 |
| -------------------------------------------- | ------------------------------------------------------------------ |
| Key, full snapshot                           | ~1.14 bytes per foreign edge                                       |
| Key, 2 foreign edges at 10s cadence          | ~0.23 B/s steady-state                                             |
| Key, 2 foreign edges at 60s cadence          | ~0.038 B/s steady-state                                            |
| Key, connect/disconnect delta                | ~150-250 bytes per forwarded edge                                  |
| Node, local delta publish                    | ~150-250 bytes per local connect/disconnect                        |
| Node, ownership sweep                        | O(local SSE clients) CPU on peer-set change; no extra body traffic |
| Node, POST redirect                          | One 307 plus repeated opaque POST body; max body 8KB               |
| Region, 100k-key snapshot                    | ~112KB per foreign region; ~11KB/s at 10s or ~1.9KB/s at 60s       |
| Region, 1M-key snapshot                      | ~1.1MB per foreign region; ~110KB/s at 10s or ~19KB/s at 60s       |
| Region, false-positive POST                  | One extra client-followed 307 and repeated POST body               |

Region-level filters keep snapshot bandwidth proportional to keys per region, not
`keys * nodes`.

---

## Reconnect And Failure Timing

Actual reconnect time includes client backoff and TCP/SSE behavior. These are operating
targets, not hard guarantees.

| Failure                          | Expected client impact                                                           |
| -------------------------------- | -------------------------------------------------------------------------------- |
| Scale-out ownership change       | Affected SSE streams are closed; reconnect usually lands healthy in 1-5s         |
| Graceful scale-in                | Regional DNS updated before termination; reconnect usually lands healthy in 1-5s |
| Process crash with closed socket | Client reconnect starts immediately; usually 1-10s                               |
| Abrupt node loss or blackhole    | Health detection plus SSE timeout; expect 20-60s worst common case               |
| Cached old node URL              | Node CNAME sends it to regional pool after DNS update                            |
| Dead HRW owner for POST          | Redirect target suppressed after peer timeout or health detection; expect 2-30s  |
