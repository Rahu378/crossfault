package consensus

import (
	"encoding/json"

	"github.com/Rahu378/crossfault/internal/crypt"
)

// Wire payloads. These are JSON-encoded into the Payload field of a signed
// crypt.Envelope, so every field below is inside the signature.
//
// JSON is used deliberately: Go marshals struct fields in declaration order, so
// the encoding is deterministic, and being able to read the bytes in a browser
// devtools panel is worth more here than the handful of bytes a binary format
// would save. A production build would swap in protobuf without touching the
// signing logic, because the signed domain is the digest of whatever bytes the
// payload happens to be.

// AppendReq is the leader's replication RPC and heartbeat.
type AppendReq struct {
	Term         uint64  `json:"term"`
	Leader       string  `json:"leader"`
	PrevIndex    uint64  `json:"prevIndex"`
	PrevTerm     uint64  `json:"prevTerm"`
	Entries      []Entry `json:"entries"`
	LeaderCommit uint64  `json:"leaderCommit"`
}

// AppendResp answers an AppendReq.
type AppendResp struct {
	Term       uint64 `json:"term"`
	Success    bool   `json:"success"`
	MatchIndex uint64 `json:"matchIndex"`
	// ConflictIndex lets a leader back up faster than one index per round trip.
	ConflictIndex uint64 `json:"conflictIndex"`
}

// VoteReq requests a vote. PreVote distinguishes a real campaign from the
// non-binding straw poll described in Ongaro's Raft thesis §9.6: a pre-vote
// does not increment anyone's term, so a node with broken connectivity can
// probe its prospects without disrupting a healthy leader.
type VoteReq struct {
	Term      uint64 `json:"term"`
	Candidate string `json:"candidate"`
	LastIndex uint64 `json:"lastIndex"`
	LastTerm  uint64 `json:"lastTerm"`
	PreVote   bool   `json:"preVote"`
}

// VoteResp answers a VoteReq.
type VoteResp struct {
	Term    uint64 `json:"term"`
	Granted bool   `json:"granted"`
	PreVote bool   `json:"preVote"`
}

// ProbeReq carries a node's first-hand connectivity observations to a peer.
// This is the gossip that populates the directed reachability matrix; it is
// what standard Raft has no equivalent of.
type ProbeReq struct {
	Term uint64 `json:"term"`
	From string `json:"from"`
	// InboundUp lists the peers this node has heard from recently. Only
	// first-hand observations travel; opinions about third parties do not.
	InboundUp []string `json:"inboundUp"`
}

// ProbeResp acknowledges a probe, which is itself the evidence that the reverse
// edge works.
type ProbeResp struct {
	Term      uint64   `json:"term"`
	From      string   `json:"from"`
	InboundUp []string `json:"inboundUp"`
}

// encode marshals a payload. Marshalling a plain struct cannot fail in practice;
// returning nil on error keeps call sites readable and the envelope will simply
// fail to carry meaning rather than panicking a node.
func encode(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func decodeAppendReq(b []byte) (AppendReq, bool) {
	var m AppendReq
	return m, json.Unmarshal(b, &m) == nil
}

func decodeAppendResp(b []byte) (AppendResp, bool) {
	var m AppendResp
	return m, json.Unmarshal(b, &m) == nil
}

func decodeVoteReq(b []byte) (VoteReq, bool) {
	var m VoteReq
	return m, json.Unmarshal(b, &m) == nil
}

func decodeVoteResp(b []byte) (VoteResp, bool) {
	var m VoteResp
	return m, json.Unmarshal(b, &m) == nil
}

func decodeProbeReq(b []byte) (ProbeReq, bool) {
	var m ProbeReq
	return m, json.Unmarshal(b, &m) == nil
}

func decodeProbeResp(b []byte) (ProbeResp, bool) {
	var m ProbeResp
	return m, json.Unmarshal(b, &m) == nil
}

func toNodeIDs(ss []string) []crypt.NodeID {
	out := make([]crypt.NodeID, len(ss))
	for i, s := range ss {
		out[i] = crypt.NodeID(s)
	}
	return out
}

func toStrings(ids []crypt.NodeID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}
