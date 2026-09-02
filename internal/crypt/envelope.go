package crypt

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Kind distinguishes message types inside the signed domain. It is part of the
// digest so that a signature harvested from one message type can never be
// replayed as another — a real attack against protocols that sign bare payloads.
type Kind uint8

const (
	KindAppendEntries Kind = 1
	KindAppendResp    Kind = 2
	KindRequestVote   Kind = 3
	KindVoteResp      Kind = 4
	KindPreVote       Kind = 5
	KindPreVoteResp   Kind = 6
	KindProbe         Kind = 7
	KindProbeResp     Kind = 8
)

func (k Kind) String() string {
	switch k {
	case KindAppendEntries:
		return "AppendEntries"
	case KindAppendResp:
		return "AppendResp"
	case KindRequestVote:
		return "RequestVote"
	case KindVoteResp:
		return "VoteResp"
	case KindPreVote:
		return "PreVote"
	case KindPreVoteResp:
		return "PreVoteResp"
	case KindProbe:
		return "Probe"
	case KindProbeResp:
		return "ProbeResp"
	}
	return "Unknown"
}

var (
	// ErrBadSignature means the payload did not verify against the sender's key.
	// The caller MUST drop the message and continue. Dropping is what converts a
	// hostile transit path into a plain omission fault.
	ErrBadSignature = errors.New("crypt: signature verification failed")

	// ErrChainBreak means the sender's claimed transcript hash does not follow
	// from what we previously received from them. Unlike a bad signature, this
	// is evidence about the *node*, not the path: a correct node's transcript is
	// append-only. See package accountability.
	ErrChainBreak = errors.New("crypt: transcript hash chain broken")

	// ErrReplay means we have already seen this sequence number from this sender.
	ErrReplay = errors.New("crypt: sequence number replayed")
)

// Envelope is the unit of authenticated communication. Every field that any
// receiver relies on is inside the signed digest; nothing security-relevant
// travels outside it.
//
// PrevHash is what makes this more than plain message signing. Each node's
// outbound stream is a hash chain, so a receiver can detect not only "this
// message was altered" but "this node is telling me a different story than it
// told someone else" — which is the raw material for a fraud certificate.
type Envelope struct {
	From     NodeID
	To       NodeID
	Kind     Kind
	Term     uint64
	Seq      uint64 // per-(sender,receiver) monotonic counter; kills replay
	PrevHash [32]byte
	Payload  []byte
	Sig      []byte
}

// digest computes the canonical bytes that get signed.
//
// Canonical encoding is load-bearing. If two correct nodes serialise the same
// logical message differently, signatures stop verifying and honest nodes start
// looking Byzantine to one another — an own-goal that has sunk real protocols.
// Fixed-width big-endian fields and length-prefixed strings avoid it.
func (e *Envelope) digest() []byte {
	h := sha256.New()

	// Domain separator: prevents a digest from this protocol ever colliding with
	// a digest from some other protocol that reuses the same node keys.
	h.Write([]byte("crossfault/v1/envelope\x00"))

	writeLenPrefixed(h, []byte(e.From))
	writeLenPrefixed(h, []byte(e.To))

	var scratch [8]byte
	scratch[0] = byte(e.Kind)
	h.Write(scratch[:1])

	binary.BigEndian.PutUint64(scratch[:], e.Term)
	h.Write(scratch[:])
	binary.BigEndian.PutUint64(scratch[:], e.Seq)
	h.Write(scratch[:])

	h.Write(e.PrevHash[:])
	writeLenPrefixed(h, e.Payload)

	return h.Sum(nil)
}

// Hash is the envelope's position in the sender's transcript chain: the value
// the sender will quote as PrevHash on its next message to the same peer.
func (e *Envelope) Hash() [32]byte {
	var out [32]byte
	copy(out[:], e.digest())
	return out
}

// writeLenPrefixed appends a 4-byte big-endian length followed by the bytes, so
// that ("ab","c") and ("a","bc") can never produce the same digest.
func writeLenPrefixed(h interface{ Write([]byte) (int, error) }, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	h.Write(l[:])
	h.Write(b)
}

// Seal signs the envelope in place. Called once, by the sender, immediately
// before handing the envelope to the network.
func (e *Envelope) Seal(id *Identity) {
	e.From = id.ID
	e.Sig = id.sign(e.digest())
}

// Open verifies the envelope against the keyring.
//
// This is the single choke point that converts transit tampering into an
// omission: every inbound message goes through here, and anything that fails is
// dropped before it can touch consensus state.
func (e *Envelope) Open(k *Keyring) error {
	pub, err := k.Lookup(e.From)
	if err != nil {
		return err
	}
	if !verify(pub, e.digest(), e.Sig) {
		return fmt.Errorf("%w: from=%s kind=%s seq=%d", ErrBadSignature, e.From, e.Kind, e.Seq)
	}
	return nil
}

// Tamper flips bits in the payload without touching the signature. It exists
// only so the simulator can model a hostile transit path; a real attacker on
// the wire has exactly this capability and no more.
//
// The point of the demo is that this is *always* caught: the signature no
// longer matches the digest, Open fails, the message is dropped.
func (e *Envelope) Tamper(mutate func([]byte) []byte) {
	e.Payload = mutate(e.Payload)
}
