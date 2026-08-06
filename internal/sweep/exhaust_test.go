package sweep

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// The whole point of tracking fd exhaustion is that it must not look like a
// closed port. A wrapped EMFILE arrives the same way a refusal does — as a
// non-nil error from Dial — so the classifier is the only thing standing
// between "we ran out of descriptors" and "nothing is listening there".
func TestIsResourceExhausted_DistinguishesFromClosedPort(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"emfile bare", syscall.EMFILE, true},
		{"enfile bare", syscall.ENFILE, true},
		{"emfile wrapped in OpError", &net.OpError{
			Op: "socket", Net: "tcp", Err: syscall.EMFILE,
		}, true},
		{"emfile double-wrapped", &net.OpError{
			Op: "dial", Net: "tcp",
			Err: &net.OpError{Op: "socket", Err: syscall.EMFILE},
		}, true},

		// The failures that legitimately mean "no open port here".
		{"connection refused", syscall.ECONNREFUSED, false},
		{"refused wrapped", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, false},
		{"timeout", context.DeadlineExceeded, false},
		{"host unreachable", syscall.EHOSTUNREACH, false},
		{"network unreachable", syscall.ENETUNREACH, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isResourceExhausted(tc.err); got != tc.want {
				t.Errorf("isResourceExhausted(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// A scan that completed without starving must not claim it was incomplete —
// a spurious warning trains users to ignore the real one.
func TestScanPorts_NoIncompleteCallbackOnCleanScan(t *testing.T) {
	open := listenerOn(t)
	called := false
	ScanPorts(context.Background(), []string{"127.0.0.1"}, PortConfig{
		Ports:        []int{open},
		Timeout:      time.Second,
		OnIncomplete: func(int) { called = true },
	})
	if called {
		t.Error("OnIncomplete fired on a scan that never ran out of descriptors")
	}
}

// The budget must stay inside the engine's own bounds whatever the OS reports,
// including the pathological ends of the range.
func TestConcurrencyBudgetForLimit_StaysWithinBounds(t *testing.T) {
	cases := []struct {
		name string
		soft uint64
	}{
		{"tiny limit", 8},
		{"typical macOS", 61440},
		{"typical container", 1024},
		{"enormous", 1 << 40},
		{"zero", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := concurrencyBudgetForLimit(tc.soft)
			if got < minFDConcurrency {
				t.Errorf("budget(%d) = %d, below floor %d", tc.soft, got, minFDConcurrency)
			}
			if got > maxConcurrency {
				t.Errorf("budget(%d) = %d, above ceiling %d", tc.soft, got, maxConcurrency)
			}
		})
	}
}

// A low descriptor limit must actually lower the concurrency, otherwise the
// budget is decorative.
func TestConcurrencyBudgetForLimit_ScalesWithLimit(t *testing.T) {
	low := concurrencyBudgetForLimit(1024)
	high := concurrencyBudgetForLimit(1 << 20)
	if low >= high {
		t.Errorf("budget did not scale with the fd limit: 1024 -> %d, 1M -> %d", low, high)
	}
}

// withDefaults must derive concurrency from the fd budget rather than a
// constant, but still honour an explicit caller-supplied value.
func TestWithDefaults_UsesFDBudgetButRespectsExplicitConcurrency(t *testing.T) {
	if got := withDefaults(Config{}).Concurrency; got != fdConcurrencyBudget() {
		t.Errorf("default concurrency = %d, want the fd budget %d", got, fdConcurrencyBudget())
	}
	if got := withDefaults(Config{Concurrency: 7}).Concurrency; got != 7 {
		t.Errorf("explicit concurrency = %d, want 7 — the caller's choice must win", got)
	}
	if got := withDefaults(Config{Concurrency: maxConcurrency * 10}).Concurrency; got != maxConcurrency {
		t.Errorf("oversized concurrency = %d, want clamp to %d", got, maxConcurrency)
	}
}

// Guard the string fallback: it exists for resolvers that drop the errno, but
// must not fire on unrelated errors that merely mention files.
func TestIsResourceExhausted_StringFallbackIsNarrow(t *testing.T) {
	if !isResourceExhausted(errors.New("socket: too many open files")) {
		t.Error("string fallback should catch an errno-less EMFILE")
	}
	if isResourceExhausted(errors.New("no such file or directory")) {
		t.Error("string fallback matched an unrelated file error")
	}
}
