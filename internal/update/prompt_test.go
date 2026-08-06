package update

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// slowReader makes the user "think" for d before answering, like a human
// reading the prompt before typing.
type slowReader struct {
	d time.Duration
}

func (r *slowReader) Read(p []byte) (int, error) {
	time.Sleep(r.d)
	return copy(p, "y\n"), nil
}

func TestMaybeUpdateSlowAnswerStillUpdates(t *testing.T) {
	// Regression: the version-check context used to span the interactive
	// prompt, so anyone who took longer than the check window to answer got
	// a spurious "Update failed" on an already-expired context.
	old := checkTimeout
	checkTimeout = 100 * time.Millisecond
	t.Cleanup(func() { checkTimeout = old })

	srv, exe, newBin := promptTestSetup(t)
	var out bytes.Buffer
	MaybeUpdate(context.Background(), Options{
		In: &slowReader{d: 300 * time.Millisecond}, Out: &out, Current: "0.1.0",
		Interactive: true, ExePath: exe,
		Checker: &Checker{BaseURL: srv.URL, CachePath: filepath.Join(t.TempDir(), "c.json")},
		Exec:    func() error { return nil },
	})
	if strings.Contains(out.String(), "Update failed") {
		t.Fatalf("update failed after a slow answer: %q", out.String())
	}
	got, _ := os.ReadFile(exe)
	if !bytes.Equal(got, newBin) {
		t.Errorf("exe content = %q, want %q", got, newBin)
	}
}

func TestReplaceExecutableWritesIntactBinary(t *testing.T) {
	// The fsync-before-rename ordering can't be observed directly, but the
	// write/sync/close/rename path must leave the target intact and the
	// temp file gone.
	dir := t.TempDir()
	exe := filepath.Join(dir, "ndscan")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	newBin := []byte("new binary")
	if err := replaceExecutable(exe, newBin); err != nil {
		t.Fatalf("replaceExecutable: %v", err)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newBin) {
		t.Errorf("exe content = %q, want %q", got, newBin)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("exe is not executable after replace (mode %v)", info.Mode().Perm())
	}
	leftover, err := filepath.Glob(filepath.Join(dir, ".ndscan-new-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftover) != 0 {
		t.Errorf("temp files left behind: %v", leftover)
	}
}
