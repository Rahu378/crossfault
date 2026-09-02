package crypt

import (
	"crypto/ed25519"
	"fmt"
)

// verify wraps ed25519.Verify. Kept in one place so that swapping the signature
// scheme (for a post-quantum one, say) touches exactly one function.
func verify(pub ed25519.PublicKey, digest, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, digest, sig)
}

// Transcript is a node's tamper-evident record of what it has said to, and
// heard from, one peer.
//
// This is the PeerReview idea (Haeberlen, Kouznetsov & Druschel, SOSP 2007)
// reduced to the minimum that consensus needs. PeerReview keeps a full signed
// log and replays it against a reference implementation to catch any deviation;
// that is strictly more powerful and strictly more expensive. Here we keep only
// the chain head, which is enough to detect the specific fault that breaks
// consensus safety: a node telling two peers incompatible stories.
type Transcript struct {
	peer NodeID

	sendHead [32]byte
	sendSeq  uint64

	recvHead [32]byte
	recvSeq  uint64
	started  bool

	gaps                   int
	lastGapFrom, lastGapTo uint64
}

// NewTranscript starts an empty chain with a peer. The zero PrevHash is the
// genesis link; both sides agree on it implicitly.
func NewTranscript(peer NodeID) *Transcript {
	return &Transcript{peer: peer}
}

// Next stamps an outbound envelope with the next sequence number and the
// current chain head, then seals it. After this returns, the envelope is ready
// for the network and the local chain has advanced.
func (t *Transcript) Next(env *Envelope, id *Identity) {
	t.sendSeq++
	env.Seq = t.sendSeq
	env.PrevHash = t.sendHead
	env.Seal(id)
	t.sendHead = env.Hash()
}

// Accept verifies an inbound envelope and advances the receive chain.
//
// Two of the three failure modes are fatal to the message; the third is not,
// and getting that distinction wrong is a trap worth spelling out.
//
//	ErrBadSignature — the path is hostile, or a bit flipped. Drop and continue.
//	                  This is the omission that makes the whole design work.
//	ErrReplay       — a stale or duplicated message. Drop; harmless.
//
// A chain GAP is different. A receiver cannot tell, on its own, whether a
// missing sequence number means "the network dropped a message" (routine, and
// guaranteed to happen under exactly the partial partitions this project is
// about) or "the sender skipped one" (evidence of misbehaviour). They look
// identical from one side.
//
// An earlier version of this code rejected every message after a gap. That
// turned a single lost packet into a permanently severed link — a self-inflicted
// partition strictly worse than the fault being modelled. So a gap now resyncs
// and is *recorded* rather than enforced: Gaps() feeds the accountability layer,
// which decides misbehaviour by comparing what a node told DIFFERENT peers.
// One peer's gap is not evidence; two peers holding incompatible transcripts
// from the same sender is.
//
// This mirrors why PeerReview needs a full log and a challenge protocol rather
// than a single hash comparison.
func (t *Transcript) Accept(env *Envelope, k *Keyring) error {
	if err := env.Open(k); err != nil {
		return err
	}
	if env.Seq <= t.recvSeq {
		return fmt.Errorf("%w: from=%s seq=%d already at %d",
			ErrReplay, env.From, env.Seq, t.recvSeq)
	}
	if t.started && (env.PrevHash != t.recvHead || env.Seq != t.recvSeq+1) {
		t.gaps++
		// Record the endpoints, do not format them. Gaps are attacker-triggered:
		// anyone who can drop packets on this link controls how often this runs,
		// so formatting a string here hands them a free allocation per dropped
		// message. Cheap to get wrong, cheap to get right.
		t.lastGapFrom, t.lastGapTo = t.recvSeq, env.Seq
	}
	t.recvHead = env.Hash()
	t.recvSeq = env.Seq
	t.started = true
	return nil
}

// Gaps counts discontinuities observed in this peer's stream. A steadily
// climbing count means the path is lossy; a gap that coincides with a
// contradictory claim elsewhere is the start of a fraud case.
func (t *Transcript) Gaps() int { return t.gaps }

// LastGap describes the most recent discontinuity, for display. Formatted on
// read rather than on receipt, so a lossy or hostile link cannot make a node
// allocate once per dropped message.
func (t *Transcript) LastGap() string {
	if t.gaps == 0 {
		return ""
	}
	return fmt.Sprintf("seq %d->%d", t.lastGapFrom, t.lastGapTo)
}

// RecvHead exposes the current inbound chain head so that the accountability
// layer can compare what a node claims to have told different peers.
func (t *Transcript) RecvHead() [32]byte { return t.recvHead }

// SendHead exposes the outbound chain head, used when a node must prove what it
// actually said.
func (t *Transcript) SendHead() [32]byte { return t.sendHead }

// Peer returns the far side of this transcript.
func (t *Transcript) Peer() NodeID { return t.peer }
