// Package netmatrix tracks *directed* reachability between nodes.
//
// Standard Raft carries an unstated assumption: that reachability is symmetric.
// If A can hear B, the protocol assumes B can hear A. Inside one datacenter
// that is nearly always true. Across clouds it is not — asymmetric routing,
// one-way security-group rules, and half-open NAT state all produce links that
// work in exactly one direction.
//
// The failure this causes is not a crash. It is a livelock. A node that can
// SEND to a majority but not RECEIVE from it will campaign, time out, increment
// its term, and campaign again forever, disrupting a perfectly healthy leader
// each time. PreVote (Ongaro's Raft thesis §9.6) fixes the special case where
// a rejoining node disrupts the cluster, and CheckQuorum makes a leader step
// down when it loses contact with a majority — etcd ships both. Neither is
// sufficient when the partition is genuinely partial and persistent, because
// both still reason about connectivity as a single number rather than as a
// directed graph.
//
// This package makes the graph explicit. Prior art worth reading: "An Analysis
// of Network-Partitioning Failures in Cloud Systems" (OSDI '18) and "Toward a
// Generic Fault Tolerance Technique for Partial Network Partitioning"
// (OSDI '20), which proposes relaying around a broken link rather than
// tolerating it.
package netmatrix

import (
	"sort"

	"github.com/Rahu378/crossfault/internal/crypt"
)

// View is one node's belief about who can reach whom.
//
// A node only ever observes its own inbound edges directly ("I heard from X").
// Everything else is second-hand, learned by gossiping views. That is an honest
// model of reality and it is why the type is called View rather than Truth: two
// correct nodes can hold different views at the same instant without either
// being faulty.
type View struct {
	owner   crypt.NodeID
	members []crypt.NodeID

	// edges[from][to] is true when `from` is believed able to deliver to `to`.
	edges map[crypt.NodeID]map[crypt.NodeID]bool

	// age[from] counts ticks since we last refreshed `from`'s row, so stale
	// second-hand information can be discounted rather than trusted forever.
	age map[crypt.NodeID]uint64
}

// NewView builds a view that optimistically assumes full connectivity.
//
// Optimism is the right default: a node that assumes it is partitioned until
// proven otherwise will never start. Evidence then subtracts edges.
func NewView(owner crypt.NodeID, members []crypt.NodeID) *View {
	sorted := append([]crypt.NodeID(nil), members...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })

	v := &View{
		owner:   owner,
		members: sorted,
		edges:   make(map[crypt.NodeID]map[crypt.NodeID]bool, len(sorted)),
		age:     make(map[crypt.NodeID]uint64, len(sorted)),
	}
	for _, from := range sorted {
		v.edges[from] = make(map[crypt.NodeID]bool, len(sorted))
		for _, to := range sorted {
			v.edges[from][to] = true
		}
	}
	return v
}

// Owner is the node whose beliefs this view represents.
func (v *View) Owner() crypt.NodeID { return v.owner }

// Members returns the cluster roster in sorted order.
func (v *View) Members() []crypt.NodeID { return v.members }

// ObserveInbound records first-hand evidence that `from` reached us. This is
// the only edge a node can ever know with certainty.
func (v *View) ObserveInbound(from crypt.NodeID) {
	v.setEdge(from, v.owner, true)
	v.age[from] = 0
}

// ObserveSilence records that we have not heard from `from` within the failure
// detection window. Note the asymmetry: this tells us nothing about whether our
// messages reach `from`.
func (v *View) ObserveSilence(from crypt.NodeID) {
	v.setEdge(from, v.owner, false)
}

// Merge folds a peer's gossiped view into ours.
//
// We trust a peer's report about its OWN inbound edges (it observed those
// first-hand) and ignore its opinions about edges between two other nodes,
// preferring to learn those from the nodes that actually observed them. This
// keeps second-hand error from compounding across gossip hops.
func (v *View) Merge(peer *View) {
	for _, from := range v.members {
		if peer.edges[from] == nil {
			continue
		}
		if val, ok := peer.edges[from][peer.owner]; ok {
			v.setEdge(from, peer.owner, val)
		}
	}
	v.age[peer.owner] = 0
}

// Tick ages every second-hand row by one unit.
func (v *View) Tick() {
	for _, id := range v.members {
		if id != v.owner {
			v.age[id]++
		}
	}
}

// CanSend reports whether `from` is believed able to deliver to `to`.
func (v *View) CanSend(from, to crypt.NodeID) bool {
	if from == to {
		return true
	}
	row, ok := v.edges[from]
	if !ok {
		return false
	}
	return row[to]
}

// Bidirectional reports whether a and b can reach each other in BOTH
// directions. This is the predicate standard Raft silently assumes and never
// checks — and checking it is most of the fix.
func (v *View) Bidirectional(a, b crypt.NodeID) bool {
	return v.CanSend(a, b) && v.CanSend(b, a)
}

// BidirectionalPeers lists every node with which `id` has a working two-way
// link, including itself.
func (v *View) BidirectionalPeers(id crypt.NodeID) []crypt.NodeID {
	out := make([]crypt.NodeID, 0, len(v.members))
	for _, m := range v.members {
		if m == id || v.Bidirectional(id, m) {
			out = append(out, m)
		}
	}
	return out
}

// Quorum is the smallest majority of the cluster.
func (v *View) Quorum() int { return len(v.members)/2 + 1 }

// HasBidirectionalQuorum is the election guard.
//
// A candidate must be able both to send to and receive from a majority. Without
// this check, a node with one-way connectivity wins an election it cannot then
// service, and the cluster loses availability until a human intervenes. With
// it, such a node declines to campaign and the cluster elects someone who can
// actually do the job.
func (v *View) HasBidirectionalQuorum(id crypt.NodeID) bool {
	return len(v.BidirectionalPeers(id)) >= v.Quorum()
}

// Relay finds an intermediary that can carry a message from -> via -> to when
// the direct edge is down.
//
// This is the OSDI '20 insight: a partial partition rarely isolates a node from
// everyone, so routing around the broken edge restores liveness without
// changing the consensus protocol at all. Returns ok=false when no relay
// exists, which is a genuine partition rather than a partial one.
func (v *View) Relay(from, to crypt.NodeID) (crypt.NodeID, bool) {
	if v.CanSend(from, to) {
		return to, true // direct path is fine
	}
	// Deterministic order so the same fault always picks the same relay,
	// keeping simulation runs reproducible.
	for _, via := range v.members {
		if via == from || via == to {
			continue
		}
		if v.CanSend(from, via) && v.CanSend(via, to) {
			return via, true
		}
	}
	return "", false
}

// Asymmetries lists every pair whose link works in one direction only. This is
// what the dashboard highlights: it is the fault class the whole project exists
// to survive, and it is invisible to conventional health checks, which test
// only whether *a* path exists.
func (v *View) Asymmetries() [][2]crypt.NodeID {
	var out [][2]crypt.NodeID
	for i, a := range v.members {
		for _, b := range v.members[i+1:] {
			ab, ba := v.CanSend(a, b), v.CanSend(b, a)
			if ab != ba {
				if ab {
					out = append(out, [2]crypt.NodeID{a, b})
				} else {
					out = append(out, [2]crypt.NodeID{b, a})
				}
			}
		}
	}
	return out
}

// Snapshot exports the adjacency matrix for the UI, in sorted member order.
func (v *View) Snapshot() ([]crypt.NodeID, [][]bool) {
	grid := make([][]bool, len(v.members))
	for i, from := range v.members {
		grid[i] = make([]bool, len(v.members))
		for j, to := range v.members {
			grid[i][j] = v.CanSend(from, to)
		}
	}
	return v.members, grid
}

// SetEdge records a directed edge. Exported for the consensus layer (folding in
// gossiped observations) and for the simulator (injecting faults). Callers
// outside this package should prefer ObserveInbound/Merge, which encode the
// rules about which evidence may be trusted from whom.
func (v *View) SetEdge(from, to crypt.NodeID, up bool) { v.setEdge(from, to, up) }

func (v *View) setEdge(from, to crypt.NodeID, up bool) {
	if v.edges[from] == nil {
		v.edges[from] = make(map[crypt.NodeID]bool, len(v.members))
	}
	v.edges[from][to] = up
}
