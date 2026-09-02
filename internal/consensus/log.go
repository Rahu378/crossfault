package consensus

import (
	"crypto/sha256"
	"encoding/binary"
)

// Entry is one replicated command.
//
// Hash chains every entry to its predecessor. Raft already detects divergence
// via the (term, index) match property, so the chain is not needed for
// consistency — it is needed for *attribution*. Two entries at the same index
// with the same term but different hashes are proof that some node fabricated
// one of them, and that proof is transferable: any third party can check it
// without trusting the accuser.
type Entry struct {
	Term    uint64 `json:"term"`
	Index   uint64 `json:"index"`
	Command string `json:"cmd"`

	// PrevHash links to Entry[Index-1]. Zero at index 1.
	PrevHash [32]byte `json:"prev"`
	// Hash is derived, never trusted from the wire — recomputed on receipt.
	Hash [32]byte `json:"hash"`
}

// computeHash derives an entry's hash from its contents and its predecessor.
// Receivers always recompute rather than believing the sender's claim; a hash
// you did not compute yourself proves nothing.
func computeHash(term, index uint64, cmd string, prev [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("crossfault/v1/entry\x00"))

	var b [8]byte
	binary.BigEndian.PutUint64(b[:], term)
	h.Write(b[:])
	binary.BigEndian.PutUint64(b[:], index)
	h.Write(b[:])

	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(cmd)))
	h.Write(l[:])
	h.Write([]byte(cmd))
	h.Write(prev[:])

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Log is a node's replicated log. Index is 1-based, matching the Raft paper;
// index 0 is the implicit empty entry before the log starts.
type Log struct {
	entries []Entry
}

// NewLog returns an empty log.
func NewLog() *Log { return &Log{} }

// Len is the index of the last entry (0 when empty).
func (l *Log) Len() uint64 { return uint64(len(l.entries)) }

// LastIndex is an alias for Len, spelled the way the Raft paper spells it.
func (l *Log) LastIndex() uint64 { return l.Len() }

// LastTerm is the term of the final entry, or 0 for an empty log.
func (l *Log) LastTerm() uint64 {
	if len(l.entries) == 0 {
		return 0
	}
	return l.entries[len(l.entries)-1].Term
}

// LastHash is the chain head, or the zero hash for an empty log.
func (l *Log) LastHash() [32]byte {
	if len(l.entries) == 0 {
		return [32]byte{}
	}
	return l.entries[len(l.entries)-1].Hash
}

// At returns the entry at a 1-based index.
func (l *Log) At(index uint64) (Entry, bool) {
	if index == 0 || index > l.Len() {
		return Entry{}, false
	}
	return l.entries[index-1], true
}

// TermAt returns the term at an index; index 0 yields term 0 so that the Raft
// consistency check works uniformly at the start of the log.
func (l *Log) TermAt(index uint64) (uint64, bool) {
	if index == 0 {
		return 0, true
	}
	e, ok := l.At(index)
	if !ok {
		return 0, false
	}
	return e.Term, true
}

// Append adds a command produced by this node as leader, chaining it.
func (l *Log) Append(term uint64, cmd string) Entry {
	idx := l.Len() + 1
	prev := l.LastHash()
	e := Entry{
		Term:     term,
		Index:    idx,
		Command:  cmd,
		PrevHash: prev,
		Hash:     computeHash(term, idx, cmd, prev),
	}
	l.entries = append(l.entries, e)
	return e
}

// Matches implements the Raft log-consistency check: does this log contain an
// entry at prevIndex whose term is prevTerm?
func (l *Log) Matches(prevIndex, prevTerm uint64) bool {
	term, ok := l.TermAt(prevIndex)
	return ok && term == prevTerm
}

// TruncateFrom discards everything at and after index. Used when a leader's log
// diverges from ours and Raft says the leader wins.
func (l *Log) TruncateFrom(index uint64) {
	if index == 0 || index > l.Len() {
		return
	}
	l.entries = l.entries[:index-1]
}

// AppendFromLeader splices replicated entries in after prevIndex, recomputing
// every hash locally.
//
// Recomputation is the point: the leader's claimed hashes are ignored. If a
// leader sends an entry whose contents do not produce the hash it claimed, the
// mismatch surfaces here rather than propagating silently.
func (l *Log) AppendFromLeader(prevIndex uint64, entries []Entry) (conflict bool) {
	for i, incoming := range entries {
		idx := prevIndex + uint64(i) + 1

		if existing, ok := l.At(idx); ok {
			if existing.Term == incoming.Term {
				continue // already have it
			}
			l.TruncateFrom(idx) // conflict: leader wins
			conflict = true
		}

		prev := l.LastHash()
		l.entries = append(l.entries, Entry{
			Term:     incoming.Term,
			Index:    idx,
			Command:  incoming.Command,
			PrevHash: prev,
			Hash:     computeHash(incoming.Term, idx, incoming.Command, prev),
		})
	}
	return conflict
}

// Slice returns entries from index through the end, for a leader building an
// AppendEntries.
func (l *Log) Slice(from uint64) []Entry {
	if from == 0 {
		from = 1
	}
	if from > l.Len() {
		return nil
	}
	out := make([]Entry, l.Len()-from+1)
	copy(out, l.entries[from-1:])
	return out
}

// UpToDate implements Raft's election restriction (§5.4.1): a candidate may
// only win if its log is at least as current as the voter's. Without this, a
// node with a stale log can be elected and silently erase committed entries.
func (l *Log) UpToDate(candidateTerm, candidateIndex uint64) bool {
	myTerm, myIndex := l.LastTerm(), l.LastIndex()
	if candidateTerm != myTerm {
		return candidateTerm > myTerm
	}
	return candidateIndex >= myIndex
}

// Commands returns the log as plain strings, for display and for comparing two
// nodes' state machines in tests.
func (l *Log) Commands() []string {
	out := make([]string, 0, len(l.entries))
	for _, e := range l.entries {
		out = append(out, e.Command)
	}
	return out
}

// Entries exposes a copy of the whole log for the UI.
func (l *Log) Entries() []Entry {
	return append([]Entry(nil), l.entries...)
}
