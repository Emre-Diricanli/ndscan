package sweep

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Early abandonment, end to end through Run: with several targets in play, a
// target whose every address stays silent through round 1 never gets its
// remaining ports probed. The listener here sits on a LATE port, so if round 2
// ran for its group the sweep would find it — zero results proves the group
// was abandoned.
//
// This also documents the accepted cost: a host that answers only on ports
// beyond round 1, in an otherwise silent subnet, is missed by a multi-target
// sweep. That is the tradeoff Config.NoEarlyAbandon opts out of, and it is why
// round 1 widens to abandonRound1Ports ports when abandonment is in play.
func TestRun_MultiTargetAbandonsSilentTarget(t *testing.T) {
	late := listenerOn(t)
	dead1, dead2, dead3 := deadPort(t), deadPort(t), deadPort(t)
	ports := []int{dead1, dead2, dead3, late}

	// Concurrency 1 forces the staged path: abandonment lives behind the same
	// threshold as staging, because below it everything is already in flight
	// and there is nothing left to save. The short timeout keeps the test fast
	// on systems where sibling loopback addresses blackhole instead of
	// refusing — either answer reads as "silent", which is all the test needs.
	cfg := Config{
		Ports:       ports,
		Timeout:     200 * time.Millisecond,
		Concurrency: 1,
	}
	got := Run(context.Background(), []string{"127.0.0.1", "127.0.0.2"}, cfg)
	if len(got) != 0 {
		t.Fatalf("got %+v, want nothing — a target silent through round 1 should be abandoned", got)
	}

	// Control: the same sweep with the optimisation off must find the listener,
	// proving it was reachable all along and only abandonment skipped it.
	cfg.NoEarlyAbandon = true
	got = Run(context.Background(), []string{"127.0.0.1", "127.0.0.2"}, cfg)
	if len(got) != 1 || got[0].OpenPort != late {
		t.Fatalf("NoEarlyAbandon: got %+v, want the listener on %d", got, late)
	}
}

// A single named target is an explicit request for a thorough scan: the sweep
// must probe every port even when round 1 comes back empty. Same setup as the
// multi-target case above, opposite outcome.
func TestRun_SingleTargetIsNeverAbandoned(t *testing.T) {
	late := listenerOn(t)
	dead1, dead2, dead3 := deadPort(t), deadPort(t), deadPort(t)

	got := Run(context.Background(), []string{"127.0.0.1"}, Config{
		Ports:       []int{dead1, dead2, dead3, late},
		Timeout:     time.Second,
		Concurrency: 1,
	})
	if len(got) != 1 || got[0].OpenPort != late {
		t.Fatalf("got %+v, want the listener on %d — a lone target is never abandoned", got, late)
	}
}

// A group that showed life in round 1 keeps its full port sweep; only the
// genuinely silent sibling is abandoned. The probe count is the witness:
// round 1 is 3 addresses x 3 ports, round 2 should run for exactly one address
// (the live group's silent member) x the remaining 3 ports — 12 progress calls
// plus the forced terminal one. Wrongly abandoning the live group would stop
// at 10, sparing the dead one would reach 16.
func TestStagedSweep_LiveGroupIsNotAbandoned(t *testing.T) {
	open := listenerOn(t)
	ports := []int{open}
	for i := 0; i < 5; i++ {
		ports = append(ports, deadPort(t))
	}

	addrs := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}
	groups := [][]string{addrs[:2], addrs[2:]}

	var mu sync.Mutex
	calls := 0
	cfg := withDefaults(Config{
		Ports:       ports,
		Timeout:     200 * time.Millisecond,
		Concurrency: 1,
		Progress: func(done, total int) {
			mu.Lock()
			calls++
			mu.Unlock()
		},
	})

	hits := stagedSweep(context.Background(), addrs, groups, cfg)
	if len(hits) != 1 || hits[0].port != open {
		t.Fatalf("hits = %+v, want the round-1 listener on %d", hits, open)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 13 {
		t.Errorf("progress fired %d times, want 13 (9 round-1 + 3 round-2 + terminal)", calls)
	}
}

// Abandonment is a verdict on a COMPLETED round 1, never on a cancelled one:
// a cancelled context must short-circuit the sweep without consulting group
// liveness at all, and must return promptly rather than waiting out timeouts.
func TestRun_CancelledMultiTargetSweepAbandonsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	start := time.Now()
	got := Run(ctx, []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}, Config{
		Ports:       DefaultPorts,
		Timeout:     5 * time.Second,
		Concurrency: 1,
	})
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("cancelled sweep took %s, should abort quickly", elapsed)
	}
	if len(got) != 0 {
		t.Errorf("cancelled sweep returned %+v, want nothing", got)
	}
}

// Grouping is what ties addresses back to the target that produced them;
// targets that expand to nothing must not become groups of their own, or one
// real subnet plus a typo would look like "sweeping many".
func TestExpandTargetGroups(t *testing.T) {
	groups := expandTargetGroups([]string{"192.168.5.0/30", "garbage", "10.9.9.9"})
	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2 (unparseable target dropped)", len(groups))
	}
	if len(groups[0]) != 2 || groups[0][0] != "192.168.5.1" {
		t.Errorf("group 0 = %v, want the /30's two host addresses", groups[0])
	}
	if len(groups[1]) != 1 || groups[1][0] != "10.9.9.9" {
		t.Errorf("group 1 = %v, want the bare address", groups[1])
	}
}
