package report

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ExportDir returns the directory exports are written to for a given time:
// ~/Downloads/ndscan/<YYYY-MM-DD>. NDSCAN_EXPORT_DIR overrides the base
// (~/Downloads/ndscan) — used by tests and for a custom location.
func ExportDir(at time.Time) string {
	base := os.Getenv("NDSCAN_EXPORT_DIR")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		base = filepath.Join(home, "Downloads", "ndscan")
	}
	return filepath.Join(base, at.Format("2006-01-02"))
}

// ExportPath builds the full path for an export of the given format at time
// `at`, creating the dated directory if needed. It returns the path to write.
func ExportPath(at time.Time, format string) (string, error) {
	dir := ExportDir(at)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("ndscan-%s.%s", at.Format("150405"), format)
	return filepath.Join(dir, name), nil
}
