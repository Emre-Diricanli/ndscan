// Package lockfile serialises writes to ndscan's shared state between
// processes.
//
// The CLI, the TUI and the web server all record a finished scan into the same
// files under the config directory, and each recording is a read-modify-write:
// load the previous history, diff against it, save the new one; load the device
// store, apply this scan's sightings, save it back. Two ndscan processes
// finishing at once can interleave those steps and lose one scan's update
// entirely.
//
// That window was known and deliberately left open — the destructive version of
// the bug was fixed when a corrupt store stopped reading as empty, leaving a
// rare lost update that the next scan repairs. This closes the remainder, and
// closes it before anything long-running is added that would widen it.
package lockfile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ErrUnsupported is returned on platforms with no advisory file locking.
//
// It is distinct from a lock that is merely held: the caller must be able to
// tell "someone else is writing" from "this machine cannot lock at all", since
// only the first is worth waiting for.
var ErrUnsupported = errors.New("advisory file locking is not supported on this platform")

// name is the lock file, kept beside the state it guards.
const name = "ndscan.lock"

// pollInterval is how often a waiting process retries.
//
// Deliberately a poll of the non-blocking flock rather than a blocking one: a
// blocking LOCK_EX cannot be timed out or cancelled, so a wedged holder would
// hang every other ndscan process on the machine indefinitely.
const pollInterval = 25 * time.Millisecond

// Acquire takes the exclusive state-write lock, waiting up to timeout.
//
// The three outcomes are distinct and callers must treat them differently:
//
//   - ok, nil error: the lock is held; call release when the write is done.
//   - !ok, nil error: another process holds it and the timeout expired. The
//     caller must not write shared state.
//   - non-nil error: locking itself failed — an unwritable config directory, a
//     filesystem with no lock support. This says nothing about whether another
//     writer exists, and the caller decides what to do about it.
//
// dir is the directory to lock in; it is created if missing.
func Acquire(dir string, timeout time.Duration) (release func(), ok bool, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, false, err
	}
	// O_CREATE, never O_TRUNC: the file's contents are irrelevant — the lock
	// lives on the open file description, not on any bytes inside it.
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, false, err
	}

	deadline := time.Now().Add(timeout)
	for {
		err := flock(f)
		if err == nil {
			return releaseFunc(f), true, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			// A real failure, not contention.
			_ = f.Close()
			return nil, false, err
		}
		if !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, false, nil // held elsewhere
		}
		time.Sleep(pollInterval)
	}
}

// releaseFunc returns an idempotent unlock.
//
// The lock file is never removed. Unlinking it would let a second process
// create a fresh file at the same path and lock that instead — two processes
// holding flocks on different inodes, both believing they are exclusive.
// Closing the descriptor releases the lock; the empty file is left behind on
// purpose.
func releaseFunc(f *os.File) func() {
	done := false
	return func() {
		if done {
			return
		}
		done = true
		_ = funlock(f)
		_ = f.Close()
	}
}
