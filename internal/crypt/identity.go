// Package crypt provides the end-to-end authentication layer.
//
// The threat model this package addresses: the transit path between two nodes
// is hostile. Cloud load balancers, API gateways and peering points terminate
// hop-by-hop TLS, so a compromised intermediary sees and can rewrite plaintext.
// Google's ALTS exists for the same reason — authenticate at the application
// layer, not at the hop.
//
// The consequence is the whole point of the design: a payload that fails
// verification is *dropped*, which turns "an adversary rewrote our replication
// traffic" into "a message did not arrive". Omission is a fault class that
// crash-fault-tolerant consensus already handles. No BFT required.
//
// What this package does NOT do is defend against a compromised node. A node
// that holds a valid signing key can sign whatever it likes. That is the
// accountability package's problem, not this one.
package crypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// NodeID identifies a replica. In a real deployment this would be bound to a
// workload identity (SPIFFE, IAM role); here it is a stable string.
type NodeID string

// Identity is a node's own keypair. The private half never leaves the node.
type Identity struct {
	ID   NodeID
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewIdentity generates a fresh Ed25519 identity from the system CSPRNG.
func NewIdentity(id NodeID) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key for %s: %w", id, err)
	}
	return &Identity{ID: id, priv: priv, pub: pub}, nil
}

// NewIdentityFromSeed builds a deterministic identity. Used only by tests and
// by the browser simulator, where reproducible runs matter more than secrecy.
// Never use this for a real deployment.
func NewIdentityFromSeed(id NodeID, seed []byte) (*Identity, error) {
	if len(seed) < ed25519.SeedSize {
		padded := make([]byte, ed25519.SeedSize)
		copy(padded, seed)
		seed = padded
	}
	priv := ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
	return &Identity{
		ID:   id,
		priv: priv,
		pub:  priv.Public().(ed25519.PublicKey),
	}, nil
}

// Public returns the verifying half of the identity, safe to distribute.
func (i *Identity) Public() ed25519.PublicKey {
	out := make(ed25519.PublicKey, len(i.pub))
	copy(out, i.pub)
	return out
}

// Fingerprint is a short human-readable form of the public key, for logs and UI.
func (i *Identity) Fingerprint() string {
	return hex.EncodeToString(i.pub[:6])
}

// sign produces a detached Ed25519 signature. Unexported: callers sign
// envelopes, never raw bytes, so that the signed domain is always the
// transcript hash and never something an attacker chose.
func (i *Identity) sign(digest []byte) []byte {
	return ed25519.Sign(i.priv, digest)
}

// Keyring maps node IDs to the public keys used to verify their messages.
//
// Distribution of this keyring is out of scope and deliberately so: in
// production it comes from the same place your mTLS trust bundle does (SPIFFE,
// a CA, or a sealed config). Getting it wrong is a real problem, but it is a
// key-management problem and not a consensus problem.
type Keyring struct {
	keys map[NodeID]ed25519.PublicKey
}

// NewKeyring builds an empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{keys: make(map[NodeID]ed25519.PublicKey)}
}

// Add registers a node's public key.
func (k *Keyring) Add(id NodeID, pub ed25519.PublicKey) {
	cp := make(ed25519.PublicKey, len(pub))
	copy(cp, pub)
	k.keys[id] = cp
}

// ErrUnknownSender means the sender is not in the keyring at all. Treated the
// same as a bad signature: the message is dropped.
var ErrUnknownSender = errors.New("crypt: sender not in keyring")

// Lookup returns the public key for a node.
func (k *Keyring) Lookup(id NodeID) (ed25519.PublicKey, error) {
	pub, ok := k.keys[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownSender, id)
	}
	return pub, nil
}

// Members returns every known node ID in sorted order, so that quorum
// arithmetic and iteration are deterministic across runs.
func (k *Keyring) Members() []NodeID {
	out := make([]NodeID, 0, len(k.keys))
	for id := range k.keys {
		out = append(out, id)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// Size is the number of nodes in the cluster.
func (k *Keyring) Size() int { return len(k.keys) }
