package consensus

import "github.com/Rahu378/crossfault/internal/crypt"

// Event is one entry in a node's human-readable activity log.
//
// This exists for the dashboard rather than for the protocol. The value of the
// demo is not that a graph animates; it is that a visitor can read *why* a node
// did what it did — "declined to campaign: no bidirectional quorum" is the
// whole thesis in one line.
type Event struct {
	Tick uint64       `json:"tick"`
	Node crypt.NodeID `json:"node"`
	Term uint64       `json:"term"`
	Kind string       `json:"kind"`
	Text string       `json:"text"`
}

// maxEvents caps per-node retention. The browser holds the whole simulation in
// memory, and an unbounded slice in a long-running tab is a leak.
const maxEvents = 400

func (n *Node) logEvent(kind, text string) {
	n.events = append(n.events, Event{
		Tick: n.tick,
		Node: n.ID,
		Term: n.currentTerm,
		Kind: kind,
		Text: text,
	})
	if len(n.events) > maxEvents {
		n.events = n.events[len(n.events)-maxEvents:]
	}
}

// Snapshot is the serialisable state the UI renders each frame.
type Snapshot struct {
	ID          crypt.NodeID `json:"id"`
	Cloud       string       `json:"cloud"`
	Role        string       `json:"role"`
	Term        uint64       `json:"term"`
	Leader      crypt.NodeID `json:"leader"`
	CommitIndex uint64       `json:"commitIndex"`
	LogLen      uint64       `json:"logLen"`
	Commands    []string     `json:"commands"`

	TermBumps        int `json:"termBumps"`
	ElectionsStarted int `json:"electionsStarted"`
	DroppedBadSig    int `json:"droppedBadSig"`
	DroppedChain     int `json:"droppedChain"`
	DroppedReplay    int `json:"droppedReplay"`
	DeclinedToRun    int `json:"declinedToRun"`

	// HasQuorum reports whether this node currently believes it can both reach
	// and be reached by a majority.
	HasQuorum bool `json:"hasQuorum"`
}

// Snapshot captures the node's current state for rendering.
func (n *Node) Snapshot() Snapshot {
	return Snapshot{
		ID:               n.ID,
		Cloud:            n.Cloud,
		Role:             n.role.String(),
		Term:             n.currentTerm,
		Leader:           n.leaderID,
		CommitIndex:      n.commitIndex,
		LogLen:           n.log.LastIndex(),
		Commands:         n.log.Commands(),
		TermBumps:        n.TermBumps,
		ElectionsStarted: n.ElectionsStarted,
		DroppedBadSig:    n.DroppedBadSig,
		DroppedChain:     n.DroppedChain,
		DroppedReplay:    n.DroppedReplay,
		DeclinedToRun:    n.DeclinedToRun,
		HasQuorum:        n.view.HasBidirectionalQuorum(n.ID),
	}
}
