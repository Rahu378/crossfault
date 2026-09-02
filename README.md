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

TLS does not solve this, because TLS is hop-by-hop and terminates at cloud load balancers and
API gateways, which then see plaintext. Google's
[ALTS](https://docs.cloud.google.com/docs/security/encryption-in-transit/application-layer-transport-security)
exists for exactly this reason.

What signing does **not** buy: protection from a compromised node, which holds a valid key and
can sign whatever it likes. That needs accountability, which is the unbuilt third layer above.

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
