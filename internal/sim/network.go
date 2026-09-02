// Package sim runs a cluster against a network the caller can break.
//
// The important design decision here is that the network holds the *ground
// truth* topology, and no node can read it. Nodes learn about connectivity only
// by observing which messages arrive — exactly as in reality. A simulator where
// nodes can consult the true topology proves nothing, because the hard part of
// a partial partition is precisely that nobody can see the whole picture.
package sim

import (
	"fmt"
	"math/rand"
	"sort"

	"github.com/Rahu378/crossfault/internal/consensus"
	"github.com/Rahu378/crossfault/internal/crypt"
)

type edge struct{ from, to crypt.NodeID }

// inflight is a message in transit, due for delivery at a future tick.
type inflight struct {
	env     *crypt.Envelope
	dueTick uint64
	via     crypt.NodeID // relay hop, empty for a direct delivery
}

// Network is the simulated inter-cloud fabric.
type Network struct {
	nodes map[crypt.NodeID]*consensus.Node
	order []crypt.NodeID

	// down holds directed edges that are broken. Directed is the whole point:
	// down[{a,b}] without down[{b,a}] is the asymmetric partition that
	// conventional health checks cannot see.
	down map[edge]bool
	// corrupt holds edges where a hostile intermediary rewrites payloads.
	corrupt map[edge]bool

	latency    map[edge]int
	baseDelay  int
	crossDelay int // extra ticks for an AWS<->GCP hop

	inflight []inflight
	tick     uint64
	rng      *rand.Rand

	// relay lets crossfault-mode nodes route around a broken edge.
	relay bool

	Delivered int
	Dropped   int
	Corrupted int
	Relayed   int

	log []string
}

// Options configures a run.
type Options struct {
	Mode              consensus.Mode
	Seed              int64
	BaseDelay         int // ticks for an intra-cloud hop
	CrossCloudDelay   int // additional ticks for a cross-cloud hop
	ElectionTimeout   int
	HeartbeatInterval int
	ProbeInterval     int
}

// NodeSpec describes one replica to build.
type NodeSpec struct {
	ID    crypt.NodeID
	Cloud string
}

// DefaultCluster is the topology from the problem statement: one node in AWS,
// two in GCP. Three nodes is the smallest cluster where a majority can exist
// without the partitioned node, which is what makes the fault interesting.
func DefaultCluster() []NodeSpec {
	return []NodeSpec{
		{ID: "aws-a", Cloud: "aws"},
		{ID: "gcp-b", Cloud: "gcp"},
		{ID: "gcp-c", Cloud: "gcp"},
	}
}

// New builds a network and its cluster.
func New(specs []NodeSpec, opt Options) (*Network, error) {
	if opt.BaseDelay <= 0 {
		opt.BaseDelay = 1
	}
	if opt.CrossCloudDelay < 0 {
		opt.CrossCloudDelay = 0
	}

	members := make([]crypt.NodeID, 0, len(specs))
	for _, s := range specs {
		members = append(members, s.ID)
	}
	sort.Slice(members, func(a, b int) bool { return members[a] < members[b] })

	ring := crypt.NewKeyring()
	idents := make(map[crypt.NodeID]*crypt.Identity, len(specs))
	for i, s := range specs {
		// Seeded identities keep the whole run reproducible.
		id, err := crypt.NewIdentityFromSeed(s.ID, []byte{byte(opt.Seed), byte(i + 1)})
		if err != nil {
			return nil, fmt.Errorf("identity for %s: %w", s.ID, err)
		}
		idents[s.ID] = id
		ring.Add(s.ID, id.Public())
	}

	n := &Network{
		nodes:      make(map[crypt.NodeID]*consensus.Node, len(specs)),
		order:      members,
		down:       make(map[edge]bool),
		corrupt:    make(map[edge]bool),
		latency:    make(map[edge]int),
		baseDelay:  opt.BaseDelay,
		crossDelay: opt.CrossCloudDelay,
		rng:        rand.New(rand.NewSource(opt.Seed)),
		relay:      opt.Mode == consensus.ModeCrossFault,
	}

	for i, s := range specs {
		n.nodes[s.ID] = consensus.NewNode(consensus.Config{
			ID:                s.ID,
			Cloud:             s.Cloud,
			Mode:              opt.Mode,
			Members:           members,
			Identity:          idents[s.ID],
			Keyring:           ring,
			Seed:              opt.Seed + int64(i)*7919, // distinct but deterministic
			ElectionTimeout:   opt.ElectionTimeout,
			HeartbeatInterval: opt.HeartbeatInterval,
			ProbeInterval:     opt.ProbeInterval,
		})
	}
	return n, nil
}

// Nodes returns replicas in deterministic order.
func (n *Network) Nodes() []*consensus.Node {
	out := make([]*consensus.Node, 0, len(n.order))
	for _, id := range n.order {
		out = append(out, n.nodes[id])
	}
	return out
}

// Node looks up one replica.
func (n *Network) Node(id crypt.NodeID) *consensus.Node { return n.nodes[id] }

// Tick returns the current simulation tick.
func (n *Network) Tick() uint64 { return n.tick }

// ---------- Fault injection ----------

// CutLink breaks a single directed edge, leaving the reverse direction intact.
// This is the asymmetric partition: from's messages to `to` vanish, while to's
// messages to `from` still arrive.
func (n *Network) CutLink(from, to crypt.NodeID) {
	n.down[edge{from, to}] = true
	n.logf("cut %s -> %s (one direction only)", from, to)
}

// HealLink restores a directed edge.
func (n *Network) HealLink(from, to crypt.NodeID) {
	delete(n.down, edge{from, to})
	n.logf("healed %s -> %s", from, to)
}

// PartitionBoth breaks a link in both directions — an ordinary, symmetric
// partition, which standard Raft already handles correctly.
func (n *Network) PartitionBoth(a, b crypt.NodeID) {
	n.CutLink(a, b)
	n.CutLink(b, a)
}

// CorruptLink installs a hostile intermediary on a directed edge. It rewrites
// payloads in flight but cannot forge a signature, because it has no key.
func (n *Network) CorruptLink(from, to crypt.NodeID) {
	n.corrupt[edge{from, to}] = true
	n.logf("hostile intermediary on %s -> %s", from, to)
}

// CleanLink removes a hostile intermediary.
func (n *Network) CleanLink(from, to crypt.NodeID) {
	delete(n.corrupt, edge{from, to})
}

// IsDown reports the ground-truth state of a directed edge.
func (n *Network) IsDown(from, to crypt.NodeID) bool { return n.down[edge{from, to}] }

// IsCorrupt reports whether a directed edge has a hostile intermediary.
func (n *Network) IsCorrupt(from, to crypt.NodeID) bool { return n.corrupt[edge{from, to}] }

// ---------- Execution ----------

// Step advances the whole simulation by one tick: deliver what is due, then let
// every node run, then queue whatever they emit.
func (n *Network) Step() {
	n.tick++

	// Deliver messages due at or before now.
	//
	// The queue is swapped out before iterating, because delivering a message
	// makes the receiver reply, and those replies enqueue onto n.inflight. An
	// earlier version built a "still pending" slice and assigned it back at the
	// end, which silently discarded every reply generated during the loop — the
	// cluster could never complete an election because votes were being eaten by
	// the simulator rather than by any modelled fault.
	pending := n.inflight
	n.inflight = nil
	for _, m := range pending {
		if m.dueTick > n.tick {
			n.inflight = append(n.inflight, m)
			continue
		}
		n.deliver(m)
	}

	// Nodes run in deterministic order.
	for _, id := range n.order {
		for _, env := range n.nodes[id].Tick() {
			n.enqueue(env)
		}
	}
}

// deliver hands a message to its destination and queues any replies.
func (n *Network) deliver(m inflight) {
	dst, ok := n.nodes[m.env.To]
	if !ok {
		return
	}
	n.Delivered++
	for _, reply := range dst.Deliver(m.env) {
		n.enqueue(reply)
	}
}

// enqueue applies the network's faults to an outbound message and schedules it.
//
// This function is the entire adversary model. An attacker on the wire can drop
// a message or rewrite its bytes. It cannot sign, because signing happens
// inside the node and the key never leaves.
func (n *Network) enqueue(env *crypt.Envelope) {
	e := edge{env.From, env.To}

	if n.down[e] {
		// The direct path is gone. In crossfault mode the sender may know a
		// relay; this is the OSDI '20 route-around-the-partition idea.
		if n.relay {
			if via, ok := n.findRelay(env.From, env.To); ok {
				n.Relayed++
				n.inflight = append(n.inflight, inflight{
					env:     env,
					dueTick: n.tick + uint64(n.delayFor(env.From, via)+n.delayFor(via, env.To)),
					via:     via,
				})
				return
			}
		}
		n.Dropped++
		return
	}

	if n.corrupt[e] {
		// A hostile gateway rewrites the payload. The signature no longer
		// matches, so the receiver will drop it — which is the point. We still
		// deliver it, because a demo that silently discarded the attack would
		// prove nothing; we want the receiver to *reject* it visibly.
		n.Corrupted++
		env.Tamper(func(b []byte) []byte {
			out := append([]byte(nil), b...)
			if len(out) > 0 {
				out[n.rng.Intn(len(out))] ^= 0xff
			}
			return out
		})
	}

	n.inflight = append(n.inflight, inflight{
		env:     env,
		dueTick: n.tick + uint64(n.delayFor(env.From, env.To)),
	})
}

// findRelay looks for a third node that can carry the message. It consults the
// SENDER's view, not ground truth — a relay chosen from information the sender
// does not have would be cheating.
func (n *Network) findRelay(from, to crypt.NodeID) (crypt.NodeID, bool) {
	src, ok := n.nodes[from]
	if !ok {
		return "", false
	}
	via, found := src.View().Relay(from, to)
	if !found || via == to {
		return "", false
	}
	// The relay must actually work in ground truth, or the message is lost
	// anyway — the sender's belief can be wrong, and that is realistic.
	if n.down[edge{from, via}] || n.down[edge{via, to}] {
		return "", false
	}
	return via, true
}

// delayFor returns propagation delay in ticks, charging extra for a
// cross-cloud hop. Real AWS<->GCP RTT in nearby regions is tens of
// milliseconds; the ratio matters more than the absolute number here.
func (n *Network) delayFor(from, to crypt.NodeID) int {
	if d, ok := n.latency[edge{from, to}]; ok {
		return d
	}
	a, b := n.nodes[from], n.nodes[to]
	if a != nil && b != nil && a.Cloud != b.Cloud {
		return n.baseDelay + n.crossDelay
	}
	return n.baseDelay
}

// SetLatency pins a directed edge's delay in ticks.
func (n *Network) SetLatency(from, to crypt.NodeID, ticks int) {
	n.latency[edge{from, to}] = ticks
}

// Leader returns the current leader, if the cluster agrees on exactly one.
// Two nodes claiming leadership in the same term would be a safety violation;
// in different terms it is normal and transient.
func (n *Network) Leader() (crypt.NodeID, bool) {
	var found crypt.NodeID
	count := 0
	for _, id := range n.order {
		if n.nodes[id].IsLeader() {
			found = id
			count++
		}
	}
	return found, count == 1
}

// Propose submits a command to the current leader.
func (n *Network) Propose(cmd string) error {
	id, ok := n.Leader()
	if !ok {
		return consensus.ErrNotLeader
	}
	return n.nodes[id].Propose(cmd)
}

// Log returns the network's fault-injection history, for the UI.
func (n *Network) Log() []string { return n.log }

func (n *Network) logf(format string, args ...any) {
	n.log = append(n.log, fmt.Sprintf("t=%d "+format, append([]any{n.tick}, args...)...))
	if len(n.log) > 200 {
		n.log = n.log[len(n.log)-200:]
	}
}
