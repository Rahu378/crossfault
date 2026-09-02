# CrossFault

A Raft implementation that survives a network broken in **one direction**, compiled to
WebAssembly so anyone can break it themselves in a browser.

**Live demo:** https://rahu378.github.io/crossfault/ · **Source:** `internal/`

---

## The problem

Raft and Paxos carry an unstated assumption: that if A can reach B, B can reach A. Inside a
single datacenter that is nearly always true. Across clouds it is not — asymmetric routing,
one-way security-group rules and half-open NAT state all produce links that work in exactly
one direction.

The resulting failure is not a crash, which is what makes it nasty. It is a **livelock**: a
replica that can send but not receive campaigns forever, incrementing its term each round and
forcing a healthy leader to stand down every time. Every health check reports green, because
from the other side the path looks fine.

## What this repository is

Three layers, deliberately separable, sharing one Raft implementation so that comparisons
between them are honest:

| Layer | Package | What it does |
|---|---|---|
| Directed reachability | `internal/netmatrix` | Tracks who can reach whom as a *directed graph*, so a node with one-way connectivity declines to campaign, and messages relay around a broken edge |
| Authenticated replication | `internal/crypt` | Every message Ed25519-signed end-to-end and hash-chained, so wire tampering becomes a dropped packet rather than a forged entry |
| Accountability | *not yet built* | Making equivocation provable and attributable, in the spirit of PeerReview |

`internal/sim` runs a cluster against a network you can break; `cmd/wasm` exposes it to the
browser; `cmd/serve` is a local dev server.

## Measured results

Produced by `go test ./internal/sim/ -v`, not written by hand. Three nodes (one AWS, two GCP),
all inbound links to `aws-a` cut while its outbound still works, 300 ticks:

| mode | term bumps | stable leader | declined to campaign |
|---|---|---|---|
| `baseline` (textbook Raft) | **30** | **none — livelocked** | 0 |
| `prevote` (PreVote + CheckQuorum) | 1 | yes | 0 |
| `crossfault` (+ directed matrix + relay) | 1 | yes | 20 |

**Reported as found:** under this fault, PreVote alone already fixes the livelock. CrossFault
matches it; it does not beat it. Claiming a win here would be easy and dishonest.

What CrossFault adds is different in kind: the partitioned node *knows* it is partitioned and
stands down deliberately rather than losing elections, and traffic is **relayed** through a
third node around the broken edge (63 messages relayed in the same scenario) — the approach
from *Toward a Generic Fault Tolerance Technique for Partial Network Partitioning* (OSDI '20).

Under a hostile intermediary rewriting one link: **281 messages corrupted in transit, 280
rejected at the signature check**, all three replica logs byte-identical. Nothing forged
reached consensus state.

## Why there is no BFT here

A hostile transit path is **not** a Byzantine fault, and conflating the two is the most common
error in this problem space.

Byzantine fault tolerance is for a compromised *node* that lies. Tampering on the *wire* is a
different, much cheaper problem: sign the payload end-to-end at the node, verify before
applying, and an attacker who fully controls the network can only **destroy** a message, never
forge one. Destruction is an *omission* — a fault class crash-fault-tolerant consensus already
handles. No 3f+1 replicas, no consensus-layer rewrite.

### Where this is weaker than the boring option

An earlier version of this README claimed TLS doesn't solve this "because it terminates at load
balancers". That describes a misconfiguration, not the norm, and it oversold the layer.

etcd, CockroachDB and TiKV all run **mTLS directly peer-to-peer** with an internal PKI or SPIFFE
identities — no terminating proxy in the path. Where you can deploy that, it provides the same
confidentiality and integrity as the signing here, *plus* key issuance, rotation and revocation,
none of which this project has. `Keyring` is a fixed map of public keys populated at startup.

Google's [ALTS](https://docs.cloud.google.com/docs/security/encryption-in-transit/application-layer-transport-security)
is a fair citation for the *principle* of authenticating at the application layer. It is not a
citation for this implementation being comparable to it.

So what does signing buy that mTLS doesn't? Exactly one thing: a signature is **transferable
evidence**. Any third party holding the public key can verify what a node said; a TLS session
proves nothing once it closes. That property is the foundation equivocation detection is built
on — which means its value here is currently **potential, not realised**, because that layer
isn't built.

What signing does **not** buy: protection from a compromised node, which holds a valid key and
can sign whatever it likes.

### Known limits of the relay

One hop, and no further. `View.Relay` scans for a single intermediary — it cannot route around a
two-hop-deep partition, has no TTL, no path cost, and no loop protection. With `N=3` there is
exactly one candidate, so it is closer to a fallback than to routing. Above three nodes it is
untested, and the added hop latency interacts with the election timeout in a way this project
does not currently model: a slow enough relay is indistinguishable from a dead leader, so relays
could plausibly trigger the elections they exist to prevent.

The right fix is probably to bound it hard — a strict one-hop TTL and an honest "no route"
otherwise — rather than to grow a mesh routing protocol inside a consensus layer, which would
mean two distributed protocols with independent convergence dynamics fighting each other.

## Design notes worth reading

Three decisions in here were arrived at the hard way, and the reasoning is in the source:

- **A chain gap must not sever a link.** An early version rejected every message after a
  sequence gap. That turned one lost packet into a permanent self-inflicted partition, strictly
  worse than the fault being defended against. A receiver cannot distinguish "the network
  dropped it" from "the sender skipped it" on its own — so gaps are *recorded* as evidence and
  the chain resyncs. See `internal/crypt/chain.go`.
- **Nodes cannot read the true topology.** The simulator holds ground truth; replicas learn
  connectivity only from which messages arrive. A simulator where nodes can consult the real
  topology proves nothing, because not seeing the whole picture is the entire difficulty of a
  partial partition.
- **Hearing from a peer proves an edge is up; only silence suggests one is down.** Without
  timeout-driven silence detection a node's view stays optimistic forever and the
  decline-to-campaign guard never fires. `internal/consensus/node.go`.

## Running it

```bash
go test ./...                                    # the whole suite
go run ./cmd/serve                               # dev server on :8787
GOOS=js GOARCH=wasm go build -o web/engine.wasm ./cmd/wasm
```

The deployed engine is 3.6 MB raw and ~1.0 MB gzipped over the wire, with no runtime
dependencies — no framework, no build step for the front end, nothing but Go and the platform.
(A local build may differ by a megabyte or so; binary size moves with the Go version, and CI
pins a different one than you may have installed.)

## Prior art

- Ongaro, *Consensus: Bridging Theory and Practice* (2014), §9.6 — PreVote and the disruptive-server problem
- Alquraan et al., *An Analysis of Network-Partitioning Failures in Cloud Systems*, OSDI '18
- Alfatafta et al., *Toward a Generic Fault Tolerance Technique for Partial Network Partitioning*, OSDI '20
- Liu et al., *XFT: Practical Fault Tolerance Beyond Crashes*, OSDI '16 — Byzantine tolerance without 3f+1
- Haeberlen, Kouznetsov & Druschel, *PeerReview: Practical Accountability for Distributed Systems*, SOSP '07

## Status

The consensus core, authentication layer and directed reachability matrix are implemented and
tested. The accountability layer is designed but not built. This is a demonstrator, not a
production database — it has no persistence, no snapshotting, no membership changes, and has
never run outside a simulator.
