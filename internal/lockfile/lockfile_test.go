package lockfile

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquire_ReleaseAllowsReacquire(t *testing.T) {
	dir := t.TempDir()
	release, ok, err := Acquire(dir, time.Second)
	if err != nil || !ok {
		t.Fatalf("Acquire() = ok %v, err %v; want the lock", ok, err)
	}
	release()

	release2, ok, err := Acquire(dir, time.Second)
	if err != nil || !ok {
		t.Fatalf("re-Acquire() = ok %v, err %v; want the lock after release", ok, err)
	}
	release2()
}

// Releasing twice must not unlock a lock someone else has since taken. The
// engine calls release through defer, and an early return could otherwise pair
// with an explicit call.
func TestRelease_IsIdempotent(t *testing.T) {
	dir := t.TempDir()
	release, ok, _ := Acquire(dir, time.Second)
	if !ok {
		t.Fatal("Acquire() did not get the lock")
	}
	release()
	release()
}

// The lock file survives release. Unlinking it would let another process create
// a fresh file at the same path and lock that instead, leaving two processes
// holding flocks on different inodes and both believing they were exclusive.
func TestRelease_LeavesTheLockFileInPlace(t *testing.T) {
	dir := t.TempDir()
	release, ok, _ := Acquire(dir, time.Second)
	if !ok {
		t.Fatal("Acquire() did not get the lock")
	}
	release()

	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatalf("lock file should outlive the lock: %v", err)
	}
}

// Acquire creates the directory rather than failing: the first scan on a fresh
// install persists into a config directory that does not exist yet.
func TestAcquire_CreatesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not", "created", "yet")
	release, ok, err := Acquire(dir, time.Second)
	if err != nil || !ok {
		t.Fatalf("Acquire() = ok %v, err %v; want it to create the directory", ok, err)
	}
	release()
}

// A path that cannot hold a directory is a lock *error*, not contention. The
// engine treats the two differently — it records anyway on an error and skips
// on contention — so they must not be conflated here.
func TestAcquire_ReportsSetupFailureAsError(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "file")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, ok, err := Acquire(filepath.Join(blocker, "sub"), time.Second)
	if err == nil {
		t.Fatal("want an error when the lock directory cannot exist")
	}
	if ok {
		t.Fatal("want ok=false when locking failed")
	}
}

// The one test that proves the package does its job.
//
// It must spawn a real process: flock is held per open file description, and
// two goroutines in one process do not reliably contend, so an in-process test
// would pass while proving nothing about the case this exists for.
func TestAcquire_ContendsAcrossProcesses(t *testing.T) {
	dir := t.TempDir()

	helper := exec.Command(os.Args[0], "-test.run=TestHelperHoldsLock", "-test.v")
	helper.Env = append(os.Environ(), "NDSCAN_LOCK_HELPER=1", "NDSCAN_LOCK_DIR="+dir)
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	if err := helper.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() { _ = helper.Wait() }()

	// Wait for the child to report that it holds the lock, rather than sleeping
	// a guessed interval and hoping.
	buf := make([]byte, 64)
	deadline := time.Now().Add(10 * time.Second)
	held := false
	for time.Now().Before(deadline) && !held {
		n, err := stdout.Read(buf)
		if n > 0 && contains(string(buf[:n]), "LOCKED") {
			held = true
		}
		if err != nil {
			break
		}
	}
	if !held {
		t.Skip("helper never reported holding the lock; cannot test contention")
	}

	// The lock is held elsewhere: this must report contention, not an error.
	start := time.Now()
	_, ok, err := Acquire(dir, 200*time.Millisecond)
	waited := time.Since(start)
	if err != nil {
		t.Fatalf("Acquire() error = %v; contention is not an error", err)
	}
	if ok {
		t.Fatal("Acquire() got the lock while another process held it")
	}
	if waited < 150*time.Millisecond {
		t.Errorf("Acquire() waited %v; want it to use its timeout before giving up", waited)
	}
}

// TestHelperHoldsLock is not a test. It is the child process for the contention
// test above, and does nothing unless that test invokes it.
func TestHelperHoldsLock(t *testing.T) {
	if os.Getenv("NDSCAN_LOCK_HELPER") != "1" {
		t.Skip("helper process; run only by TestAcquire_ContendsAcrossProcesses")
	}
	release, ok, err := Acquire(os.Getenv("NDSCAN_LOCK_DIR"), 2*time.Second)
	if err != nil || !ok {
		os.Exit(1)
	}
	defer release()
	os.Stdout.WriteString("LOCKED\n")
	time.Sleep(2 * time.Second)
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
