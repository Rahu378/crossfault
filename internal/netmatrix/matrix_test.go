package netmatrix

import (
	"testing"

	"github.com/Rahu378/crossfault/internal/crypt"
)

var roster = []crypt.NodeID{"aws-a", "gcp-b", "gcp-c"}

// TestFullConnectivityIsTheDefault: with no evidence of failure, everyone can
// campaign. A view that starts pessimistic would never bootstrap.
func TestFullConnectivityIsTheDefault(t *testing.T) {
	v := NewView("aws-a", roster)
	for _, id := range roster {
		if !v.HasBidirectionalQuorum(id) {
			t.Fatalf("%s should have quorum in a healthy cluster", id)
		}
	}
	if len(v.Asymmetries()) != 0 {
		t.Fatalf("healthy cluster must report no asymmetries, got %v", v.Asymmetries())
	}
}

// TestScenarioFromTheProblemStatement encodes the exact fault described in the
// brief this project was built from:
//
//	aws-a -> gcp-b   works
//	gcp-b -> gcp-c   works
//	gcp-c -> aws-a   BROKEN (one direction only)
//
// The link between gcp-c and aws-a is up in one direction and down in the
// other. Every conventional health check passes, because from aws-a's side the
// path to gcp-c is fine. The damage is invisible until leader election stalls.
func TestScenarioFromTheProblemStatement(t *testing.T) {
	v := NewView("observer", roster)
	v.setEdge("gcp-c", "aws-a", false)

	if v.CanSend("gcp-c", "aws-a") {
		t.Fatal("gcp-c -> aws-a must be down")
	}
	if !v.CanSend("aws-a", "gcp-c") {
		t.Fatal("aws-a -> gcp-c must still be up: that is what makes this asymmetric")
	}

	asym := v.Asymmetries()
	if len(asym) != 1 {
		t.Fatalf("expected exactly one asymmetric pair, got %v", asym)
	}
	if asym[0] != [2]crypt.NodeID{"aws-a", "gcp-c"} {
		t.Fatalf("asymmetry should be reported in the working direction, got %v", asym[0])
	}

	// aws-a and gcp-c are no longer bidirectional, so neither can count the
	// other toward a quorum. In a 3-node cluster that leaves each of them with
	// only itself and gcp-b — exactly 2, which IS a majority of 3.
	if v.Bidirectional("aws-a", "gcp-c") {
		t.Fatal("aws-a and gcp-c must not be considered bidirectional")
	}
	if !v.HasBidirectionalQuorum("gcp-b") {
		t.Fatal("gcp-b reaches everyone both ways and must be electable")
	}
}

// TestOneWayNodeIsNotElectable is the core guard.
//
// A node whose outbound works but whose inbound is dead looks healthy to
// itself: it can send heartbeats to everyone. Under stock Raft it will campaign,
// fail to collect votes it can never hear, time out, bump its term, and repeat
// forever — livelocking the cluster. The bidirectional check stops it from
// campaigning at all.
func TestOneWayNodeIsNotElectable(t *testing.T) {
	v := NewView("observer", roster)
	// Nobody can reach aws-a, but aws-a can still reach everybody.
	v.setEdge("gcp-b", "aws-a", false)
	v.setEdge("gcp-c", "aws-a", false)

	if !v.CanSend("aws-a", "gcp-b") {
		t.Fatal("aws-a outbound must still work — that is the trap")
	}
	if v.HasBidirectionalQuorum("aws-a") {
		t.Fatal("aws-a must NOT be electable: it can never hear the votes it needs")
	}
	if !v.HasBidirectionalQuorum("gcp-b") {
		t.Fatal("gcp-b still has a healthy two-way majority and must remain electable")
	}
}

// TestRelayRoutesAroundABrokenEdge: the OSDI '20 result. A partial partition
// leaves an indirect path, so liveness is recoverable without touching the
// consensus protocol.
func TestRelayRoutesAroundABrokenEdge(t *testing.T) {
	v := NewView("observer", roster)
	v.setEdge("gcp-c", "aws-a", false)

	via, ok := v.Relay("gcp-c", "aws-a")
	if !ok {
		t.Fatal("a relay must exist: gcp-c -> gcp-b -> aws-a is intact")
	}
	if via != "gcp-b" {
		t.Fatalf("relay should be gcp-b, got %s", via)
	}
}

// TestRelayFailsUnderTotalPartition: when a node really is cut off, the
// honest answer is "no path", not an invented one.
func TestRelayFailsUnderTotalPartition(t *testing.T) {
	v := NewView("observer", roster)
	v.setEdge("gcp-c", "aws-a", false)
	v.setEdge("gcp-b", "aws-a", false)

	if _, ok := v.Relay("gcp-c", "aws-a"); ok {
		t.Fatal("no relay should be found when every path to aws-a is down")
	}
}

// TestDirectPathPreferredOverRelay: relaying costs an extra hop of latency, so
// it must only happen when the direct edge is actually broken.
func TestDirectPathPreferredOverRelay(t *testing.T) {
	v := NewView("observer", roster)
	via, ok := v.Relay("gcp-c", "aws-a")
	if !ok || via != "aws-a" {
		t.Fatalf("healthy direct edge must be used, got via=%s ok=%v", via, ok)
	}
}

// TestMergeTrustsOnlyFirstHandEdges: gossip must not let one node's opinion
// about a third party overwrite that third party's own observation.
func TestMergeTrustsOnlyFirstHandEdges(t *testing.T) {
	mine := NewView("aws-a", roster)

	// gcp-b reports, correctly and first-hand, that it cannot hear gcp-c.
	theirs := NewView("gcp-b", roster)
	theirs.setEdge("gcp-c", "gcp-b", false)
	// It also asserts something about an edge it cannot observe. We must ignore it.
	theirs.setEdge("gcp-c", "aws-a", false)

	mine.Merge(theirs)

	if mine.CanSend("gcp-c", "gcp-b") {
		t.Fatal("first-hand report from gcp-b about its own inbound must be accepted")
	}
	if !mine.CanSend("gcp-c", "aws-a") {
		t.Fatal("second-hand claim about the gcp-c -> aws-a edge must be ignored")
	}
}

// TestObserveInboundAndSilence covers the only edges a node knows firsthand.
func TestObserveInboundAndSilence(t *testing.T) {
	v := NewView("aws-a", roster)

	v.ObserveSilence("gcp-c")
	if v.CanSend("gcp-c", "aws-a") {
		t.Fatal("silence must mark the inbound edge down")
	}
	v.ObserveInbound("gcp-c")
	if !v.CanSend("gcp-c", "aws-a") {
		t.Fatal("hearing from gcp-c must restore the inbound edge")
	}
}

// TestQuorumArithmetic sanity-checks majority sizes.
func TestQuorumArithmetic(t *testing.T) {
	for _, tc := range []struct{ n, want int }{{3, 2}, {5, 3}, {4, 3}, {7, 4}} {
		members := make([]crypt.NodeID, tc.n)
		for i := range members {
			members[i] = crypt.NodeID(rune('a' + i))
		}
		if got := NewView(members[0], members).Quorum(); got != tc.want {
			t.Fatalf("Quorum() for n=%d = %d, want %d", tc.n, got, tc.want)
		}
	}
}

// TestSnapshotIsSortedAndSquare guards the shape the UI consumes.
func TestSnapshotIsSortedAndSquare(t *testing.T) {
	v := NewView("aws-a", []crypt.NodeID{"gcp-c", "aws-a", "gcp-b"})
	members, grid := v.Snapshot()

	want := []crypt.NodeID{"aws-a", "gcp-b", "gcp-c"}
	for i := range want {
		if members[i] != want[i] {
			t.Fatalf("snapshot members = %v, want sorted %v", members, want)
		}
	}
	if len(grid) != 3 {
		t.Fatalf("grid must have one row per member, got %d", len(grid))
	}
	for _, row := range grid {
		if len(row) != 3 {
			t.Fatalf("grid must be square, got row of %d", len(row))
		}
	}
}
