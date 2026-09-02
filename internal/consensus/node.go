package consensus

import (
	"errors"
	"fmt"
	"math/rand"

	"github.com/Rahu378/crossfault/internal/crypt"
	"github.com/Rahu378/crossfault/internal/netmatrix"
)

// Mode selects which protections are active.
//
// All three modes share this one implementation. That is deliberate: if the
// baseline were a separate, deliberately-crippled program, a comparison against
// it would prove nothing. Here the only differences are the guards switched on
// below, so any divergence in behaviour is attributable to those guards alone.
type Mode int

const (
	// ModeBaseline is Raft as published: no pre-vote, no quorum check, and no
	// model of directed connectivity. This is what most textbook
	// implementations do, and it livelocks under a one-way partition.
	ModeBaseline Mode = iota

	// ModePreVote adds the two mitigations etcd ships: the non-binding pre-vote
	// straw poll (Ongaro thesis §9.6) and CheckQuorum, which makes a leader
	// step down once it stops hearing from a majority.
	ModePreVote

	// ModeCrossFault adds the directed reachability matrix, so a node with
	// one-way connectivity declines to campaign, and relaying, so a partial
	// partition is routed around instead of tolerated.
	ModeCrossFault
)

func (m Mode) String() string {
	switch m {
	case ModeBaseline:
		return "baseline"
	case ModePreVote:
		return "prevote"
	case ModeCrossFault:
		return "crossfault"
	}
	return "unknown"
}

// Role is a node's current Raft role.
type Role int

const (
	Follower Role = iota
	PreCandidate
	Candidate
	Leader
)

func (r Role) String() string {
	switch r {
	case Follower:
		return "follower"
	case PreCandidate:
		return "precandidate"
	case Candidate:
		return "candidate"
	case Leader:
		return "leader"
	}
	return "unknown"
}

// Node is one replica.
type Node struct {
	ID    crypt.NodeID
	Cloud string // "aws" / "gcp" — cosmetic, but it makes the demo legible
	Mode  Mode

	ident *crypt.Identity
	ring  *crypt.Keyring
	view  *netmatrix.View
	log   *Log

	role        Role
	currentTerm uint64
	votedFor    crypt.NodeID
	leaderID    crypt.NodeID
	commitIndex uint64

	nextIndex  map[crypt.NodeID]uint64
	matchIndex map[crypt.NodeID]uint64

	electionElapsed  int
	electionTimeout  int
	heartbeatElapsed int
	probeElapsed     int

	votes    map[crypt.NodeID]bool
	preVotes map[crypt.NodeID]bool

	// heardFrom drives CheckQuorum: cleared each election interval, populated
	// by any inbound traffic from a peer.
	heardFrom map[crypt.NodeID]bool
	// inboundUp is the first-hand observation set gossiped in probes.
	inboundUp map[crypt.NodeID]bool
	// lastHeard records the tick each peer was last verified-heard from. This is
	// the only clock a node has for deciding an inbound edge has failed.
	lastHeard map[crypt.NodeID]uint64

	sendTr map[crypt.NodeID]*crypt.Transcript
	recvTr map[crypt.NodeID]*crypt.Transcript

	rng    *rand.Rand
	outbox []*crypt.Envelope
	events []Event
	tick   uint64

	heartbeatInterval int
	baseElection      int
	probeInterval     int

	// Counters the dashboard graphs. TermBumps is the headline number: under a
	// one-way partition it climbs without bound in baseline mode and stays flat
	// in crossfault mode.
	TermBumps        int
	ElectionsStarted int
	DroppedBadSig    int
	DroppedChain     int
	DroppedReplay    int
	Committed        int
	RelayedMessages  int
	DeclinedToRun    int
}

// Config describes a node at construction time.
type Config struct {
	ID       crypt.NodeID
	Cloud    string
	Mode     Mode
	Members  []crypt.NodeID
	Identity *crypt.Identity
	Keyring  *crypt.Keyring
	Seed     int64

	// ElectionTimeout is the base timeout in ticks; the actual value is
	// randomised in [T, 2T) per the Raft paper, to break election ties.
	ElectionTimeout int
	// HeartbeatInterval must be comfortably below ElectionTimeout.
	HeartbeatInterval int
	// ProbeInterval controls connectivity gossip (crossfault mode only).
	ProbeInterval int
}

// NewNode builds a replica.
func NewNode(cfg Config) *Node {
	if cfg.ElectionTimeout <= 0 {
		cfg.ElectionTimeout = 10
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 3
	}
	if cfg.ProbeInterval <= 0 {
		cfg.ProbeInterval = 2
	}

	n := &Node{
		ID:         cfg.ID,
		Cloud:      cfg.Cloud,
		Mode:       cfg.Mode,
		ident:      cfg.Identity,
		ring:       cfg.Keyring,
		view:       netmatrix.NewView(cfg.ID, cfg.Members),
		log:        NewLog(),
		role:       Follower,
		nextIndex:  make(map[crypt.NodeID]uint64),
		matchIndex: make(map[crypt.NodeID]uint64),
		votes:      make(map[crypt.NodeID]bool),
		preVotes:   make(map[crypt.NodeID]bool),
		heardFrom:  make(map[crypt.NodeID]bool),
		inboundUp:  make(map[crypt.NodeID]bool),
		lastHeard:  make(map[crypt.NodeID]uint64),
		sendTr:     make(map[crypt.NodeID]*crypt.Transcript),
		recvTr:     make(map[crypt.NodeID]*crypt.Transcript),
		rng:        rand.New(rand.NewSource(cfg.Seed)),

		heartbeatInterval: cfg.HeartbeatInterval,
		baseElection:      cfg.ElectionTimeout,
		probeInterval:     cfg.ProbeInterval,
	}
	for _, m := range cfg.Members {
		if m == cfg.ID {
			continue
		}
		n.sendTr[m] = crypt.NewTranscript(m)
		n.recvTr[m] = crypt.NewTranscript(m)
		n.inboundUp[m] = true
	}
	n.resetElectionTimer()
	return n
}

// Members returns the cluster roster.
func (n *Node) Members() []crypt.NodeID { return n.view.Members() }

// Role, Term, CommitIndex and Log expose state for the UI and tests.
func (n *Node) Role() Role            { return n.role }
func (n *Node) Term() uint64          { return n.currentTerm }
func (n *Node) CommitIndex() uint64   { return n.commitIndex }
func (n *Node) Log() *Log             { return n.log }
func (n *Node) View() *netmatrix.View { return n.view }
func (n *Node) Leader() crypt.NodeID  { return n.leaderID }
func (n *Node) Events() []Event       { return n.events }
func (n *Node) IsLeader() bool        { return n.role == Leader }

// resetElectionTimer randomises the timeout in [T, 2T) so that two followers
// rarely campaign on the same tick.
func (n *Node) resetElectionTimer() {
	n.electionElapsed = 0
	n.electionTimeout = n.baseElection + n.rng.Intn(n.baseElection)
}

// Tick advances the node's clock by one unit and returns any messages it wants
// to send. The simulation is entirely tick-driven, which is what makes runs
// reproducible from a seed.
func (n *Node) Tick() []*crypt.Envelope {
	n.tick++
	n.outbox = nil

	n.view.Tick()
	n.electionElapsed++

	switch n.role {
	case Leader:
		n.heartbeatElapsed++
		if n.heartbeatElapsed >= n.heartbeatInterval {
			n.heartbeatElapsed = 0
			n.broadcastAppend()
		}
		// CheckQuorum: a leader that cannot hear a majority must step down,
		// otherwise it keeps accepting writes it can never commit.
		if n.Mode != ModeBaseline && n.electionElapsed >= n.electionTimeout {
			n.electionElapsed = 0
			if !n.hasHeardFromQuorum() {
				n.logEvent("step-down", "lost contact with a majority (CheckQuorum)")
				n.becomeFollower(n.currentTerm, "")
			}
			n.clearHeard()
		}

	case Follower, PreCandidate, Candidate:
		if n.electionElapsed >= n.electionTimeout {
			n.beginElection()
		}
	}

	if n.Mode == ModeCrossFault {
		n.detectSilence()
		n.probeElapsed++
		if n.probeElapsed >= n.probeInterval {
			n.probeElapsed = 0
			n.broadcastProbe()
		}
	}

	return n.outbox
}

// silenceWindow is how long a peer may be quiet before we conclude its inbound
// edge to us is down.
//
// The value is a trade-off, not a constant of nature. Too short and normal
// jitter flaps the matrix, causing a node to refuse to campaign when it should.
// Too long and a real one-way failure goes undetected for seconds. One election
// timeout is the natural scale: it is already the interval at which the cluster
// decides a leader is gone.
func (n *Node) silenceWindow() uint64 { return uint64(n.baseElection) }

// detectSilence marks inbound edges down when a peer goes quiet.
//
// This is the other half of the matrix, and the half that is easy to forget:
// hearing from a peer proves an edge is UP, but only the *absence* of traffic
// can suggest one is down. Without this, a node's view stays optimistic
// forever, HasBidirectionalQuorum never goes false, and the guard that is
// supposed to stop a one-way node from campaigning never fires.
func (n *Node) detectSilence() {
	for _, m := range n.Members() {
		if m == n.ID {
			continue
		}
		last, seen := n.lastHeard[m]
		if !seen {
			// Never heard from at all: give one full window from startup before
			// concluding anything, so a slow start is not read as a failure.
			if n.tick > n.silenceWindow() {
				n.inboundUp[m] = false
				n.view.ObserveSilence(m)
			}
			continue
		}
		if n.tick-last > n.silenceWindow() {
			n.inboundUp[m] = false
			n.view.ObserveSilence(m)
		}
	}
}

// beginElection decides whether and how to campaign. This is where the three
// modes visibly diverge.
func (n *Node) beginElection() {
	// The crossfault guard. A node that cannot both send to and hear from a
	// majority cannot win a useful election, so it must not start one. In
	// baseline Raft this check does not exist, and its absence is the whole
	// livelock: the node campaigns, hears nothing, times out, bumps its term,
	// and disrupts the real leader — forever.
	if n.Mode == ModeCrossFault && !n.view.HasBidirectionalQuorum(n.ID) {
		n.DeclinedToRun++
		n.logEvent("declined", "no bidirectional quorum — standing down instead of campaigning")
		n.resetElectionTimer()
		return
	}

	n.ElectionsStarted++

	if n.Mode == ModeBaseline {
		// Straight to a real campaign: term is incremented immediately, which
		// is exactly what disrupts a healthy leader.
		n.currentTerm++
		n.TermBumps++
		n.role = Candidate
		n.votedFor = n.ID
		n.votes = map[crypt.NodeID]bool{n.ID: true}
		n.logEvent("campaign", fmt.Sprintf("candidate at term %d", n.currentTerm))
		n.resetElectionTimer()
		n.broadcastVoteReq(false)
		return
	}

	// PreVote: a non-binding straw poll at term+1 that does NOT increment our
	// term. If we cannot win, nothing was disturbed.
	n.role = PreCandidate
	n.preVotes = map[crypt.NodeID]bool{n.ID: true}
	n.logEvent("pre-campaign", fmt.Sprintf("pre-vote straw poll for term %d", n.currentTerm+1))
	n.resetElectionTimer()
	n.broadcastVoteReq(true)
}

// promoteToCandidate converts a won pre-vote into a real campaign.
func (n *Node) promoteToCandidate() {
	n.currentTerm++
	n.TermBumps++
	n.role = Candidate
	n.votedFor = n.ID
	n.votes = map[crypt.NodeID]bool{n.ID: true}
	n.logEvent("campaign", fmt.Sprintf("pre-vote carried; candidate at term %d", n.currentTerm))
	n.resetElectionTimer()
	n.broadcastVoteReq(false)
}

func (n *Node) becomeLeader() {
	n.role = Leader
	n.leaderID = n.ID
	n.heartbeatElapsed = 0
	n.clearHeard()
	for _, m := range n.Members() {
		if m == n.ID {
			continue
		}
		n.nextIndex[m] = n.log.LastIndex() + 1
		n.matchIndex[m] = 0
	}
	n.logEvent("elected", fmt.Sprintf("leader for term %d", n.currentTerm))
	n.broadcastAppend()
}

func (n *Node) becomeFollower(term uint64, leader crypt.NodeID) {
	n.role = Follower
	n.currentTerm = term
	n.votedFor = ""
	n.leaderID = leader
	n.resetElectionTimer()
}

func (n *Node) quorum() int { return len(n.Members())/2 + 1 }

func (n *Node) hasHeardFromQuorum() bool {
	count := 1 // self
	for _, ok := range n.heardFrom {
		if ok {
			count++
		}
	}
	return count >= n.quorum()
}

func (n *Node) clearHeard() {
	n.heardFrom = make(map[crypt.NodeID]bool)
}

var errNoTranscript = errors.New("consensus: no transcript for peer")

// send seals a payload into an authenticated envelope and queues it.
func (n *Node) send(to crypt.NodeID, kind crypt.Kind, payload []byte) error {
	tr, ok := n.sendTr[to]
	if !ok {
		return errNoTranscript
	}
	env := &crypt.Envelope{To: to, Kind: kind, Term: n.currentTerm, Payload: payload}
	tr.Next(env, n.ident)
	n.outbox = append(n.outbox, env)
	return nil
}
