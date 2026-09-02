package crypt

import (
	"bytes"
	"errors"
	"testing"
)

// cluster builds n deterministic identities plus a shared keyring.
func cluster(t *testing.T, ids ...NodeID) (map[NodeID]*Identity, *Keyring) {
	t.Helper()
	idents := make(map[NodeID]*Identity, len(ids))
	ring := NewKeyring()
	for i, id := range ids {
		ident, err := NewIdentityFromSeed(id, []byte{byte(i + 1)})
		if err != nil {
			t.Fatalf("NewIdentityFromSeed(%s): %v", id, err)
		}
		idents[id] = ident
		ring.Add(id, ident.Public())
	}
	return idents, ring
}

// TestTamperedPayloadIsRejected is the load-bearing test of this whole project.
//
// It encodes the claim that justifies not using BFT: an attacker who fully
// controls the transit path — reading and rewriting bytes at a terminating
// gateway — cannot get a single forged byte into consensus state. The best they
// can do is destroy the message, which is an omission.
func TestTamperedPayloadIsRejected(t *testing.T) {
	idents, ring := cluster(t, "aws-a", "gcp-b")

	env := &Envelope{To: "gcp-b", Kind: KindAppendEntries, Term: 7, Payload: []byte("commit x=1")}
	tr := NewTranscript("gcp-b")
	tr.Next(env, idents["aws-a"])

	// Sanity: untouched, it verifies.
	if err := env.Open(ring); err != nil {
		t.Fatalf("clean envelope must verify: %v", err)
	}

	// A hostile gateway rewrites the payload. It cannot re-sign: it has no key.
	env.Tamper(func(b []byte) []byte { return bytes.Replace(b, []byte("x=1"), []byte("x=9"), 1) })

	err := env.Open(ring)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered payload must fail with ErrBadSignature, got %v", err)
	}
}

// TestTamperOfEveryFieldIsRejected checks that the signed domain really covers
// every field a receiver acts on. A field left outside the digest is a silent
// hole — this is where signing schemes usually go wrong.
func TestTamperOfEveryFieldIsRejected(t *testing.T) {
	idents, ring := cluster(t, "aws-a", "gcp-b")

	build := func() *Envelope {
		e := &Envelope{To: "gcp-b", Kind: KindAppendEntries, Term: 7, Payload: []byte("payload")}
		NewTranscript("gcp-b").Next(e, idents["aws-a"])
		return e
	}

	mutations := map[string]func(*Envelope){
		"term":     func(e *Envelope) { e.Term = 99 },
		"kind":     func(e *Envelope) { e.Kind = KindRequestVote },
		"seq":      func(e *Envelope) { e.Seq = 42 },
		"to":       func(e *Envelope) { e.To = "gcp-c" },
		"from":     func(e *Envelope) { e.From = "gcp-b" },
		"prevhash": func(e *Envelope) { e.PrevHash[0] ^= 0xff },
		"payload":  func(e *Envelope) { e.Payload = []byte("different") },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			e := build()
			mutate(e)
			if err := e.Open(ring); err == nil {
				t.Fatalf("mutating %q was not detected — field is outside the signed digest", name)
			}
		})
	}
}

// TestReplayIsRejected: a captured valid message replayed later must not be
// re-applied. Signatures alone do not give you this; sequence numbers do.
func TestReplayIsRejected(t *testing.T) {
	idents, ring := cluster(t, "aws-a", "gcp-b")

	send := NewTranscript("gcp-b")
	recv := NewTranscript("aws-a")

	first := &Envelope{To: "gcp-b", Kind: KindAppendEntries, Payload: []byte("one")}
	send.Next(first, idents["aws-a"])
	if err := recv.Accept(first, ring); err != nil {
		t.Fatalf("first message must be accepted: %v", err)
	}

	second := &Envelope{To: "gcp-b", Kind: KindAppendEntries, Payload: []byte("two")}
	send.Next(second, idents["aws-a"])
	if err := recv.Accept(second, ring); err != nil {
		t.Fatalf("second message must be accepted: %v", err)
	}

	// Attacker replays the first message verbatim. Signature is genuine.
	if err := recv.Accept(first, ring); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed message must fail with ErrReplay, got %v", err)
	}
}

// TestChainGapIsRecordedNotFatal encodes a hard-won design decision.
//
// A gap must be *observed* but must not sever the link. A receiver cannot tell
// a network drop from a sender omission, and rejecting everything after a gap
// turns one lost packet into a permanent self-inflicted partition — worse than
// the fault being defended against. So the message is accepted, the chain
// resyncs, and the gap is counted as evidence for the accountability layer.
func TestChainGapIsRecordedNotFatal(t *testing.T) {
	idents, ring := cluster(t, "aws-a", "gcp-b")

	send := NewTranscript("gcp-b")
	recv := NewTranscript("aws-a")

	m1 := &Envelope{To: "gcp-b", Kind: KindAppendEntries, Payload: []byte("one")}
	send.Next(m1, idents["aws-a"])
	if err := recv.Accept(m1, ring); err != nil {
		t.Fatalf("m1: %v", err)
	}

	// m2 is produced but the hostile path swallows it.
	m2 := &Envelope{To: "gcp-b", Kind: KindAppendEntries, Payload: []byte("two")}
	send.Next(m2, idents["aws-a"])

	m3 := &Envelope{To: "gcp-b", Kind: KindAppendEntries, Payload: []byte("three")}
	send.Next(m3, idents["aws-a"])

	if err := recv.Accept(m3, ring); err != nil {
		t.Fatalf("a gap must not reject the message, got %v", err)
	}
	if recv.Gaps() != 1 {
		t.Fatalf("gap should have been recorded once, got %d", recv.Gaps())
	}

	// Critically: the link must still work afterwards.
	m4 := &Envelope{To: "gcp-b", Kind: KindAppendEntries, Payload: []byte("four")}
	send.Next(m4, idents["aws-a"])
	if err := recv.Accept(m4, ring); err != nil {
		t.Fatalf("link must recover after a gap, got %v", err)
	}
	if recv.Gaps() != 1 {
		t.Fatalf("a clean message after resync must not add a gap, got %d", recv.Gaps())
	}
}

// TestUnknownSenderIsRejected: a node not in the keyring cannot participate,
// however well-formed its messages are.
func TestUnknownSenderIsRejected(t *testing.T) {
	_, ring := cluster(t, "aws-a", "gcp-b")

	outsider, err := NewIdentityFromSeed("attacker", []byte{9})
	if err != nil {
		t.Fatal(err)
	}
	env := &Envelope{To: "gcp-b", Kind: KindAppendEntries, Payload: []byte("hello")}
	NewTranscript("gcp-b").Next(env, outsider)

	if err := env.Open(ring); !errors.Is(err, ErrUnknownSender) {
		t.Fatalf("unknown sender must be rejected, got %v", err)
	}
}

// TestDeterministicIdentities guards the reproducibility property the simulator
// depends on: same seed, same keys, same run.
func TestDeterministicIdentities(t *testing.T) {
	a, _ := NewIdentityFromSeed("n1", []byte{4})
	b, _ := NewIdentityFromSeed("n1", []byte{4})
	if !bytes.Equal(a.Public(), b.Public()) {
		t.Fatal("same seed must produce the same keypair")
	}
	c, _ := NewIdentityFromSeed("n1", []byte{5})
	if bytes.Equal(a.Public(), c.Public()) {
		t.Fatal("different seeds must produce different keypairs")
	}
}

// TestMembersAreSorted guards deterministic quorum arithmetic.
func TestMembersAreSorted(t *testing.T) {
	_, ring := cluster(t, "gcp-c", "aws-a", "gcp-b")
	got := ring.Members()
	want := []NodeID{"aws-a", "gcp-b", "gcp-c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Members() = %v, want %v", got, want)
		}
	}
}
