package sweep

import (
	"errors"
	"strings"
	"syscall"
)

const (
	minFDConcurrency = 32
	fdBudgetFraction = 4
)

// fdConcurrencyBudget returns the maximum number of simultaneous dials the
// native scanners should use when the caller did not provide a lower limit.
// Keeping three quarters of the descriptor table free matters because scans
// share the process with listeners, subprocess pipes, and unrelated UI work.
// Failure to inspect the limit is not fatal: the historical default is safer
// than refusing to scan on a platform that does not expose RLIMIT_NOFILE.
func fdConcurrencyBudget() int {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil || limit.Cur == ^uint64(0) {
		return defaultConcurrency
	}
	return concurrencyBudgetForLimit(limit.Cur)
}

func concurrencyBudgetForLimit(soft uint64) int {
	budget := soft / fdBudgetFraction
	if budget < minFDConcurrency {
		budget = minFDConcurrency
	}
	if budget > maxConcurrency {
		budget = maxConcurrency
	}
	return int(budget)
}

// isResourceExhausted reports whether a failed dial reflects exhaustion of
// this machine's descriptor capacity rather than evidence that the remote port
// is closed. Callers must not silently classify these failures as closed ports;
// they should retry at lower concurrency or surface an incomplete scan.
func isResourceExhausted(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
		return true
	}
	// A few resolver and dialer implementations discard the errno while
	// preserving its text. Keep this as a fallback, never the primary test.
	return strings.Contains(strings.ToLower(err.Error()), "too many open files")
}
