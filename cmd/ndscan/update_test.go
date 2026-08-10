package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// primeUpdateCache writes a cached "latest release" lookup into an isolated
// config dir, standing in for a check an earlier command already made.
func primeUpdateCache(t *testing.T, latest string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("NDSCAN_CONFIG_DIR", dir)
	body := `{"checked_at":"2999-01-01T00:00:00Z","latest":"` + latest + `"}`
	if err := os.WriteFile(filepath.Join(dir, "update-check.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("write cache: %v", err)
	}
}

// The bug this fixes: cobra answers --version before PersistentPreRun, so the
// startup hook never ran for it and the one command people use to ask "am I
// current?" could not say.
func TestUpdateHint_NamesANewerCachedRelease(t *testing.T) {
	primeUpdateCache(t, "v0.2.15")
	orig := ui.Interactive
	ui.Interactive = true
	defer func() { ui.Interactive = orig }()

	got := updateHint("0.2.14")
	if !strings.Contains(got, "v0.2.15") || !strings.Contains(got, "ndscan update") {
		t.Fatalf("expected the hint to name the release and the command, got %q", got)
	}
}

// Scripts parse `ndscan --version`. The hint must never appear when stderr is
// not a terminal, or piping the output changes what it says.
func TestUpdateHint_SilentWhenNotInteractive(t *testing.T) {
	primeUpdateCache(t, "v0.2.15")
	orig := ui.Interactive
	ui.Interactive = false
	defer func() { ui.Interactive = orig }()

	if got := updateHint("0.2.14"); got != "" {
		t.Fatalf("expected no hint for a non-terminal session, got %q", got)
	}
}

// Nothing cached means nothing known. Staying silent is required: printing
// "you are current" from an empty cache would assert something never checked.
func TestUpdateHint_SilentWithNoCachedCheck(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	orig := ui.Interactive
	ui.Interactive = true
	defer func() { ui.Interactive = orig }()

	if got := updateHint("0.2.14"); got != "" {
		t.Fatalf("expected no hint without a cached check, got %q", got)
	}
}

// Running the newest release must add nothing to --version.
func TestUpdateHint_SilentWhenCurrent(t *testing.T) {
	primeUpdateCache(t, "v0.2.15")
	orig := ui.Interactive
	ui.Interactive = true
	defer func() { ui.Interactive = orig }()

	if got := updateHint("0.2.15"); got != "" {
		t.Fatalf("expected no hint when already current, got %q", got)
	}
}

// The opt-out has to cover this path too, or setting it still changes output.
func TestUpdateHint_RespectsOptOut(t *testing.T) {
	primeUpdateCache(t, "v0.2.15")
	t.Setenv("NDSCAN_NO_UPDATE_CHECK", "1")
	orig := ui.Interactive
	ui.Interactive = true
	defer func() { ui.Interactive = orig }()

	if got := updateHint("0.2.14"); got != "" {
		t.Fatalf("expected no hint when update checks are disabled, got %q", got)
	}
}
