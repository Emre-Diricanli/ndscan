package update

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A root-owned cache file (left behind by one sudo run) must not be able to
// answer for the checker forever. If we cannot refresh it, we ignore it.
func TestReadCache_IgnoresUnwritableCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-check.json")
	body := `{"checked_at":"` + time.Now().Format(time.RFC3339) + `","latest":"v9.9.9"}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &Checker{CachePath: path}
	if got := c.readCache().Latest; got != "v9.9.9" {
		t.Fatalf("writable cache should be used, got %q", got)
	}

	// Make it unreadable-for-write the way a root-owned file would be.
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not restrict writes")
	}
	if got := c.readCache().Latest; got != "" {
		t.Errorf("unwritable cache = %q, want it ignored so the check still runs", got)
	}
}

// A missing cache is the normal first-run case and must not be treated as
// unwritable — that would skip the cache write on every fresh install.
func TestCacheWritable_MissingFileIsFine(t *testing.T) {
	c := &Checker{CachePath: filepath.Join(t.TempDir(), "nope.json")}
	if !c.cacheWritable() {
		t.Error("a not-yet-created cache should count as writable")
	}
}
