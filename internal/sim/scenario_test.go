package sim

import (
	"testing"

	"github.com/Rahu378/crossfault/internal/consensus"
	"github.com/Rahu378/crossfault/internal/crypt"
)

func newNet(t *testing.T, mode consensus.Mode) *Network {
	t.Helper()
	n, err := New(DefaultCluster(), Options{
		Mode:              mode,
		Seed:              42,
		BaseDelay:         1,
		CrossCloudDelay:   2,
		ElectionTimeout:   10,
		HeartbeatInterval: 3,
		ProbeInterval:     2,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return n
}

// run advances the simulation, returning the tick at which a stable leader
// first appeared (0 if none ever did).
func run(n *Network, ticks int) uint64 {
	var firstLeader uint64
	for i := 0; i < ticks; i++ {
		n.Step()
		if firstLeader == 0 {
			if _, ok := n.Leader(); ok {
				firstLeader = n.Tick()
			}
		}
	}
	return firstLeader
}

// TestHealthyClusterElectsAndCommits is the control. If this fails, nothing
// else in this file means anything.
func TestHealthyClusterElectsAndCommits(t *testing.T) {
	for _, mode := range []consensus.Mode{consensus.ModeBaseline, consensus.ModePreVote, consensus.ModeCrossFault} {
		t.Run(mode.String(), func(t *testing.T) {
			n := newNet(t, mode)
			if at := run(n, 60); at == 0 {
				t.Fatal("no leader elected in a healthy cluster")
			}
			if err := n.Propose("set x=1"); err != nil {
				t.Fatalf("propose: %v", err)
			}
			run(n, 40)

			leader, ok := n.Leader()
			if !ok {
				t.Fatal("leader lost after proposing")
			}
			if n.Node(leader).CommitIndex() == 0 {
				t.Fatal("leader never committed the entry")
			}
		})
	}
}

// TestTamperedLinkNeverCorruptsState is the security claim, end to end.
//
// A hostile intermediary rewrites every payload crossing one link. The cluster
// must keep working (via the remaining links) and must never apply a forged
// entry. Every corrupted message should be counted as rejected.
func TestTamperedLinkNeverCorruptsState(t *testing.T) {
	n := newNet(t, consensus.ModeCrossFault)
	run(n, 60)

	n.CorruptLink("gcp-b", "gcp-c")
	run(n, 60)

	if n.Corrupted == 0 {
		t.Fatal("test did not actually corrupt anything — scenario is not exercising the path")
	}

	victim := n.Node("gcp-c")
	if victim.Snapshot().DroppedBadSig == 0 {
		t.Fatal("corrupted messages were not rejected: the signature check is not doing its job")
	}

	// Whatever gcp-c holds must be a prefix-consistent view, never forged data.
	for _, e := range victim.Log().Entries() {
		if e.Command == "" {
			t.Fatal("a forged/empty entry reached the log")
		}
	}
}

// TestAsymmetricPartitionBaselineVsCrossFault is the headline experiment.
//
// aws-a can send to everyone but hear from no one. Under baseline Raft this is
// the "disruptive server" livelock: aws-a campaigns, bumps its term, deposes a
// healthy leader, hears no votes, times out, and repeats without bound.
//
// The metric is TermBumps across the cluster. A healthy cluster settles at a
// low, stable term. A livelocked one climbs forever.
func TestAsymmetricPartitionBaselineVsCrossFault(t *testing.T) {
	measure := func(mode consensus.Mode) (termBumps int, committed uint64, hadLeader bool) {
		n := newNet(t, mode)
		run(n, 60) // settle

		// Break every inbound edge to aws-a. Its outbound still works — that is
		// what makes this asymmetric and what makes it dangerous.
		n.CutLink("gcp-b", "aws-a")
		n.CutLink("gcp-c", "aws-a")

		run(n, 300)

		for _, node := range n.Nodes() {
			termBumps += node.Snapshot().TermBumps
		}
		if id, ok := n.Leader(); ok {
			hadLeader = true
			committed = n.Node(id).CommitIndex()
		}
		return
	}

	baseBumps, _, _ := measure(consensus.ModeBaseline)
	preBumps, _, preLeader := measure(consensus.ModePreVote)
	xfBumps, _, xfLeader := measure(consensus.ModeCrossFault)

	t.Logf("term bumps after 300 ticks under a one-way partition:")
	t.Logf("  baseline   = %d", baseBumps)
	t.Logf("  prevote    = %d (leader present: %v)", preBumps, preLeader)
	t.Logf("  crossfault = %d (leader present: %v)", xfBumps, xfLeader)

	if baseBumps <= preBumps {
		t.Errorf("expected baseline to churn more than prevote; baseline=%d prevote=%d",
			baseBumps, preBumps)
	}
	if !xfLeader {
		t.Error("crossfault must keep a stable leader through a one-way partition")
	}
}

// TestPartitionedNodeDeclinesToCampaign checks the specific mechanism, not just
// the aggregate outcome. A node that cannot hear a majority should stand down
// rather than campaign.
func TestPartitionedNodeDeclinesToCampaign(t *testing.T) {
	n := newNet(t, consensus.ModeCrossFault)
	run(n, 60)

	n.CutLink("gcp-b", "aws-a")
	n.CutLink("gcp-c", "aws-a")
	run(n, 200)

	snap := n.Node("aws-a").Snapshot()
	if snap.DeclinedToRun == 0 {
		t.Fatalf("aws-a should have declined to campaign; snapshot=%+v", snap)
	}
	if snap.HasQuorum {
		t.Error("aws-a should not believe it has a bidirectional quorum")
	}
}

// TestSafetyNeverTwoLeadersInSameTerm is the property that must hold under
// every fault this simulator can inject. Liveness is negotiable; safety is not.
func TestSafetyNeverTwoLeadersInSameTerm(t *testing.T) {
	for _, mode := range []consensus.Mode{consensus.ModeBaseline, consensus.ModePreVote, consensus.ModeCrossFault} {
		t.Run(mode.String(), func(t *testing.T) {
			n := newNet(t, mode)

			for i := 0; i < 400; i++ {
				switch i {
				case 50:
					n.CutLink("gcp-c", "aws-a")
				case 120:
					n.CorruptLink("aws-a", "gcp-b")
				case 200:
					n.CutLink("gcp-b", "aws-a")
				case 280:
					n.HealLink("gcp-c", "aws-a")
				case 340:
					n.HealLink("gcp-b", "aws-a")
				}
				n.Step()

				leadersByTerm := map[uint64][]crypt.NodeID{}
				for _, node := range n.Nodes() {
					if node.IsLeader() {
						leadersByTerm[node.Term()] = append(leadersByTerm[node.Term()], node.ID)
					}
				}
				for term, ids := range leadersByTerm {
					if len(ids) > 1 {
						t.Fatalf("SAFETY VIOLATION at tick %d: two leaders in term %d: %v", i, term, ids)
					}
				}
			}
		})
	}
}

// TestRelayRoutesAroundOneWayCut verifies the relay actually fires and that
// messages still land.
func TestRelayRoutesAroundOneWayCut(t *testing.T) {
	n := newNet(t, consensus.ModeCrossFault)
	run(n, 60)

	n.CutLink("gcp-c", "aws-a")
	run(n, 150)

	if n.Relayed == 0 {
		t.Fatal("no message was relayed around the broken edge")
	}
	t.Logf("relayed %d messages around the cut; dropped %d", n.Relayed, n.Dropped)
}

// TestDeterminism guards reproducibility: the same seed must produce the same
// run. Without this a failure found in the browser could never be reproduced.
func TestDeterminism(t *testing.T) {
	fingerprint := func() []uint64 {
		n := newNet(t, consensus.ModeCrossFault)
		run(n, 100)
		n.CutLink("gcp-c", "aws-a")
		run(n, 100)

		var out []uint64
		for _, node := range n.Nodes() {
			out = append(out, node.Term(), node.CommitIndex(), uint64(node.Snapshot().TermBumps))
		}
		return out
	}
	a, b := fingerprint(), fingerprint()
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("same seed produced different runs at position %d: %v vs %v", i, a, b)
		}
	}
}
