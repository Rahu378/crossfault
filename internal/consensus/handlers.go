package consensus

import (
	"errors"
	"fmt"
	"sort"

	"github.com/Rahu378/crossfault/internal/crypt"
)

// Deliver processes one inbound envelope and returns any replies.
//
// Every inbound message passes through transcript verification first. That
// single choke point is what makes the security argument work: a payload
// rewritten in transit fails here and is dropped, so it never reaches the state
// machine below. The node treats it as a message that never arrived.
func (n *Node) Deliver(env *crypt.Envelope) []*crypt.Envelope {
	n.outbox = nil

	tr, ok := n.recvTr[env.From]
	if !ok {
		return nil // not a cluster member
	}

	if err := tr.Accept(env, n.ring); err != nil {
		switch {
		case errors.Is(err, crypt.ErrBadSignature), errors.Is(err, crypt.ErrUnknownSender):
			// The security-critical path. An adversary who fully controls the
			// wire gets exactly this outcome and no other: the message is
			// destroyed. That is an omission, not a Byzantine fault.
			n.DroppedBadSig++
			n.logEvent("drop-forged", fmt.Sprintf("rejected tampered %s from %s", env.Kind, env.From))
		case errors.Is(err, crypt.ErrReplay):
			n.DroppedReplay++
		}
		return nil
	}

	// Verified. Only now may it influence anything — including our beliefs
	// about connectivity. Recording an unverified message as evidence of
	// reachability would let an off-path attacker forge the matrix.
	n.heardFrom[env.From] = true
	n.inboundUp[env.From] = true
	n.lastHeard[env.From] = n.tick
	n.view.ObserveInbound(env.From)

	// A gap means the path lost something. Not fatal on its own — see the note
	// on Transcript.Accept — but it is the raw signal the accountability layer
	// correlates across peers.
	if g := tr.Gaps(); g > n.DroppedChain {
		n.DroppedChain = g
	}

	switch env.Kind {
	case crypt.KindAppendEntries:
		if m, ok := decodeAppendReq(env.Payload); ok {
			n.handleAppendReq(env.From, m)
		}
	case crypt.KindAppendResp:
		if m, ok := decodeAppendResp(env.Payload); ok {
			n.handleAppendResp(env.From, m)
		}
	case crypt.KindRequestVote, crypt.KindPreVote:
		if m, ok := decodeVoteReq(env.Payload); ok {
			n.handleVoteReq(env.From, m)
		}
	case crypt.KindVoteResp, crypt.KindPreVoteResp:
		if m, ok := decodeVoteResp(env.Payload); ok {
			n.handleVoteResp(env.From, m)
		}
	case crypt.KindProbe:
		if m, ok := decodeProbeReq(env.Payload); ok {
			n.handleProbeReq(env.From, m)
		}
	case crypt.KindProbeResp:
		if m, ok := decodeProbeResp(env.Payload); ok {
			n.handleProbeResp(env.From, m)
		}
	}
	return n.outbox
}

// ---------- AppendEntries ----------

func (n *Node) broadcastAppend() {
	for _, m := range n.Members() {
		if m == n.ID {
			continue
		}
		next := n.nextIndex[m]
		if next == 0 {
			next = n.log.LastIndex() + 1
			n.nextIndex[m] = next
		}
		prevIndex := next - 1
		prevTerm, _ := n.log.TermAt(prevIndex)

		n.send(m, crypt.KindAppendEntries, encode(AppendReq{
			Term:         n.currentTerm,
			Leader:       string(n.ID),
			PrevIndex:    prevIndex,
			PrevTerm:     prevTerm,
			Entries:      n.log.Slice(next),
			LeaderCommit: n.commitIndex,
		}))
	}
}

func (n *Node) handleAppendReq(from crypt.NodeID, m AppendReq) {
	if m.Term < n.currentTerm {
		n.send(from, crypt.KindAppendResp, encode(AppendResp{Term: n.currentTerm, Success: false}))
		return
	}
	// A valid leader at >= our term: adopt it and stand down.
	if m.Term > n.currentTerm || n.role != Follower {
		n.becomeFollower(m.Term, from)
	}
	n.leaderID = from
	n.resetElectionTimer()

	if !n.log.Matches(m.PrevIndex, m.PrevTerm) {
		// Tell the leader where we diverge so it can back up in one round trip
		// instead of decrementing nextIndex one entry at a time.
		conflict := n.log.LastIndex() + 1
		if m.PrevIndex < conflict {
			conflict = m.PrevIndex
		}
		n.send(from, crypt.KindAppendResp, encode(AppendResp{
			Term: n.currentTerm, Success: false, ConflictIndex: conflict,
		}))
		return
	}

	n.log.AppendFromLeader(m.PrevIndex, m.Entries)

	if m.LeaderCommit > n.commitIndex {
		n.commitIndex = min64(m.LeaderCommit, n.log.LastIndex())
		n.Committed = int(n.commitIndex)
	}

	n.send(from, crypt.KindAppendResp, encode(AppendResp{
		Term: n.currentTerm, Success: true, MatchIndex: n.log.LastIndex(),
	}))
}

func (n *Node) handleAppendResp(from crypt.NodeID, m AppendResp) {
	if m.Term > n.currentTerm {
		n.becomeFollower(m.Term, "")
		return
	}
	if n.role != Leader || m.Term < n.currentTerm {
		return
	}

	if m.Success {
		n.matchIndex[from] = m.MatchIndex
		n.nextIndex[from] = m.MatchIndex + 1
		n.advanceCommit()
		return
	}

	next := m.ConflictIndex
	if next == 0 {
		next = 1
	}
	n.nextIndex[from] = next
}

// advanceCommit implements Raft §5.3/§5.4: commit index N only when a majority
// has replicated it AND N is from the current term. Committing an entry from a
// previous term on majority replication alone is the classic Raft bug that
// loses committed data.
func (n *Node) advanceCommit() {
	matches := []uint64{n.log.LastIndex()} // the leader itself
	for _, m := range n.Members() {
		if m != n.ID {
			matches = append(matches, n.matchIndex[m])
		}
	}
	sort.Slice(matches, func(a, b int) bool { return matches[a] > matches[b] })

	candidate := matches[n.quorum()-1]
	if candidate <= n.commitIndex {
		return
	}
	if term, ok := n.log.TermAt(candidate); !ok || term != n.currentTerm {
		return
	}
	n.commitIndex = candidate
	n.Committed = int(candidate)
	n.logEvent("commit", fmt.Sprintf("committed through index %d", candidate))
}

// ---------- Elections ----------

func (n *Node) broadcastVoteReq(pre bool) {
	kind := crypt.KindRequestVote
	term := n.currentTerm
	if pre {
		kind = crypt.KindPreVote
		term = n.currentTerm + 1 // straw poll for the *next* term
	}
	for _, m := range n.Members() {
		if m == n.ID {
			continue
		}
		n.send(m, kind, encode(VoteReq{
			Term:      term,
			Candidate: string(n.ID),
			LastIndex: n.log.LastIndex(),
			LastTerm:  n.log.LastTerm(),
			PreVote:   pre,
		}))
	}
}

func (n *Node) handleVoteReq(from crypt.NodeID, m VoteReq) {
	if m.PreVote {
		// A pre-vote never changes our term or our vote. We grant it only if
		// the candidate's log could actually win AND we do not currently
		// believe in a live leader. That second condition is what stops a
		// flapping node from disturbing a healthy cluster.
		granted := m.Term > n.currentTerm &&
			n.log.UpToDate(m.LastTerm, m.LastIndex) &&
			!n.believesLeaderIsLive()

		n.send(from, crypt.KindPreVoteResp, encode(VoteResp{
			Term: n.currentTerm, Granted: granted, PreVote: true,
		}))
		return
	}

	if m.Term > n.currentTerm {
		n.becomeFollower(m.Term, "")
	}

	granted := m.Term == n.currentTerm &&
		(n.votedFor == "" || n.votedFor == crypt.NodeID(m.Candidate)) &&
		n.log.UpToDate(m.LastTerm, m.LastIndex)

	if granted {
		n.votedFor = crypt.NodeID(m.Candidate)
		n.resetElectionTimer()
	}
	n.send(from, crypt.KindVoteResp, encode(VoteResp{
		Term: n.currentTerm, Granted: granted,
	}))
}

// believesLeaderIsLive reports whether we have heard from a leader recently
// enough to still trust it.
func (n *Node) believesLeaderIsLive() bool {
	return n.leaderID != "" && n.electionElapsed < n.electionTimeout
}

func (n *Node) handleVoteResp(from crypt.NodeID, m VoteResp) {
	if m.PreVote {
		if n.role != PreCandidate || !m.Granted {
			return
		}
		n.preVotes[from] = true
		if len(n.preVotes) >= n.quorum() {
			n.promoteToCandidate()
		}
		return
	}

	if m.Term > n.currentTerm {
		n.becomeFollower(m.Term, "")
		return
	}
	if n.role != Candidate || m.Term != n.currentTerm || !m.Granted {
		return
	}
	n.votes[from] = true
	if len(n.votes) >= n.quorum() {
		n.becomeLeader()
	}
}

// ---------- Connectivity probes (crossfault mode) ----------

func (n *Node) broadcastProbe() {
	up := make([]crypt.NodeID, 0, len(n.inboundUp))
	for id, ok := range n.inboundUp {
		if ok {
			up = append(up, id)
		}
	}
	sort.Slice(up, func(a, b int) bool { return up[a] < up[b] })

	for _, m := range n.Members() {
		if m == n.ID {
			continue
		}
		n.send(m, crypt.KindProbe, encode(ProbeReq{
			Term: n.currentTerm, From: string(n.ID), InboundUp: toStrings(up),
		}))
	}
}

func (n *Node) handleProbeReq(from crypt.NodeID, m ProbeReq) {
	n.mergeInbound(from, toNodeIDs(m.InboundUp))

	up := make([]crypt.NodeID, 0, len(n.inboundUp))
	for id, ok := range n.inboundUp {
		if ok {
			up = append(up, id)
		}
	}
	sort.Slice(up, func(a, b int) bool { return up[a] < up[b] })

	n.send(from, crypt.KindProbeResp, encode(ProbeResp{
		Term: n.currentTerm, From: string(n.ID), InboundUp: toStrings(up),
	}))
}

func (n *Node) handleProbeResp(from crypt.NodeID, m ProbeResp) {
	n.mergeInbound(from, toNodeIDs(m.InboundUp))
}

// mergeInbound folds a peer's first-hand inbound observations into our view.
//
// peer reporting "I can hear X" establishes the directed edge X -> peer. We
// accept that because peer observed it directly. We do NOT accept peer's
// opinions about edges between two other nodes.
func (n *Node) mergeInbound(peer crypt.NodeID, up []crypt.NodeID) {
	reachable := make(map[crypt.NodeID]bool, len(up))
	for _, id := range up {
		reachable[id] = true
	}
	for _, m := range n.Members() {
		if m == peer {
			continue
		}
		if reachable[m] {
			n.view.SetEdge(m, peer, true)
		} else {
			n.view.SetEdge(m, peer, false)
		}
	}
}

// ---------- Client interface ----------

// ErrNotLeader is returned when a write is offered to a non-leader.
var ErrNotLeader = errors.New("consensus: not the leader")

// Propose submits a command. Only the leader accepts writes.
func (n *Node) Propose(cmd string) error {
	if n.role != Leader {
		return ErrNotLeader
	}
	n.log.Append(n.currentTerm, cmd)
	n.logEvent("propose", cmd)
	n.broadcastAppend()
	return nil
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
