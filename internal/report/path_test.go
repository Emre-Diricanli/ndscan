package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExportPath_DatedFolderAndCreate(t *testing.T) {
	base := t.TempDir()
	t.Setenv("NDSCAN_EXPORT_DIR", base)

	at := time.Date(2026, 6, 10, 14, 22, 5, 0, time.UTC)
	path, err := ExportPath(at, "html")
	if err != nil {
		t.Fatalf("ExportPath: %v", err)
	}

	wantDir := filepath.Join(base, "2026-06-10")
	if filepath.Dir(path) != wantDir {
		t.Errorf("dir = %q, want %q", filepath.Dir(path), wantDir)
	}
	if got := filepath.Base(path); got != "ndscan-142205.html" {
		t.Errorf("name = %q, want ndscan-142205.html", got)
	}
	// the dated directory must have been created
	if fi, err := os.Stat(wantDir); err != nil || !fi.IsDir() {
		t.Errorf("dated dir not created: err=%v", err)
	}
}

func TestExportDir_DefaultsToDownloads(t *testing.T) {
	os.Unsetenv("NDSCAN_EXPORT_DIR")
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	dir := ExportDir(at)
	if !strings.Contains(filepath.ToSlash(dir), "Downloads/ndscan/2026-01-02") {
		t.Errorf("default dir = %q, want .../Downloads/ndscan/2026-01-02", dir)
	}
}
