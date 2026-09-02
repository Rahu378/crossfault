package sim

import (
	"sort"

	"github.com/Rahu378/crossfault/internal/consensus"
	"github.com/Rahu378/crossfault/internal/crypt"
)

// LinkState is the ground-truth condition of one directed edge, plus what the
// source node *believes* about it.
//
// Exposing both is the pedagogical point of the whole dashboard: the gap
// between truth and belief is where partial partitions live. A visitor can see
// a link that is really down while the node at one end still thinks it is fine.
type LinkState struct {
	From      crypt.NodeID `json:"from"`
	To        crypt.NodeID `json:"to"`
	Down      bool         `json:"down"`
	Corrupt   bool         `json:"corrupt"`
	Believed  bool         `json:"believed"`
	Asymmetry bool         `json:"asymmetry"`
}

// State is everything the UI renders in one frame.
type State struct {
	Tick   uint64               `json:"tick"`
	Mode   string               `json:"mode"`
	Nodes  []consensus.Snapshot `json:"nodes"`
	Links  []LinkState          `json:"links"`
	Events []consensus.Event    `json:"events"`
	Leader crypt.NodeID         `json:"leader"`
	Stable bool                 `json:"stable"`

	Delivered int `json:"delivered"`
	Dropped   int `json:"dropped"`
	Corrupted int `json:"corrupted"`
	Relayed   int `json:"relayed"`

	// TotalTermBumps is the headline metric. Under a one-way partition it
	// climbs without bound in baseline mode and flattens in the others.
	TotalTermBumps int `json:"totalTermBumps"`
	// TotalRejected counts forged messages refused at the signature check.
	TotalRejected int `json:"totalRejected"`
	// MaxCommit is the highest commit index any node has reached — the plain
	// measure of whether the cluster is doing useful work at all.
	MaxCommit uint64 `json:"maxCommit"`
}

// State captures the whole simulation for rendering.
//
// Every slice is initialised to a non-nil empty slice rather than left nil.
// encoding/json marshals a nil slice as `null`, not `[]`, so a nil Events field
// reaches JavaScript as null and the first `.slice()` call on it throws. That
// exception then propagates back across the WASM boundary and terminates the Go
// program — the whole engine dies because one list happened to be empty on the
// first frame. Cheap insurance for an expensive failure.
func (n *Network) State(mode consensus.Mode) State {
	s := State{
		Tick:      n.tick,
		Mode:      mode.String(),
		Delivered: n.Delivered,
		Dropped:   n.Dropped,
		Corrupted: n.Corrupted,
		Relayed:   n.Relayed,
		Nodes:     []consensus.Snapshot{},
		Links:     []LinkState{},
		Events:    []consensus.Event{},
	}

	for _, node := range n.Nodes() {
		snap := node.Snapshot()
		s.Nodes = append(s.Nodes, snap)
		s.TotalTermBumps += snap.TermBumps
		s.TotalRejected += snap.DroppedBadSig
		if snap.CommitIndex > s.MaxCommit {
			s.MaxCommit = snap.CommitIndex
		}
		s.Events = append(s.Events, node.Events()...)
	}

	if id, ok := n.Leader(); ok {
		s.Leader, s.Stable = id, true
	}

	for _, from := range n.order {
		for _, to := range n.order {
			if from == to {
				continue
			}
			down := n.down[edge{from, to}]
			s.Links = append(s.Links, LinkState{
				From:      from,
				To:        to,
				Down:      down,
				Corrupt:   n.corrupt[edge{from, to}],
				Believed:  n.nodes[from].View().CanSend(from, to),
				Asymmetry: down != n.down[edge{to, from}],
			})
		}
	}

	// Newest events last, capped so the browser is not asked to render
	// thousands of rows each frame.
	sort.SliceStable(s.Events, func(a, b int) bool { return s.Events[a].Tick < s.Events[b].Tick })
	if len(s.Events) > 120 {
		s.Events = s.Events[len(s.Events)-120:]
	}
	return s
}
