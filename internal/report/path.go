package report

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/userenv"
)

// ExportDir returns the directory exports are written to for a given time:
// ~/Downloads/ndscan/<YYYY-MM-DD>. NDSCAN_EXPORT_DIR overrides the base
// (~/Downloads/ndscan) — used by tests and for a custom location.
func ExportDir(at time.Time) string {
	base := os.Getenv("NDSCAN_EXPORT_DIR")
	if base == "" {
		home := userenv.Home()
		if home == "" {
			home = "."
		}
		base = filepath.Join(home, "Downloads", "ndscan")
	}
	return filepath.Join(base, at.Format("2006-01-02"))
}

// ExportPath builds the full path for an export of the given format at time
// `at`, creating the dated directory if needed. It returns the path to write.
//
// Names are second-resolution, so two exports of the same format within one
// second would collide; the second and later get a "-2", "-3", … suffix rather
// than silently overwriting the earlier file.
func ExportPath(at time.Time, format string) (string, error) {
	dir := ExportDir(at)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	_ = userenv.Chown(filepath.Dir(dir))
	_ = userenv.Chown(dir)
	stamp := at.Format("150405")
	path := filepath.Join(dir, fmt.Sprintf("ndscan-%s.%s", stamp, format))
	// Bounded probe: give up and reuse the base name rather than spin forever
	// if something is creating files as fast as we can test for them.
	for n := 2; n < 1000; n++ {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			break
		}
		path = filepath.Join(dir, fmt.Sprintf("ndscan-%s-%d.%s", stamp, n, format))
	}
	return path, nil
}
