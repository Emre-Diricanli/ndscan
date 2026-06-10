package report

import (
	"os"
	"os/exec"
	"runtime"
)

// CanOpen reports whether opening a file in the desktop default app is
// supported and enabled. Setting NDSCAN_NO_OPEN disables it (for headless
// runs, CI, and tests).
func CanOpen() bool {
	if os.Getenv("NDSCAN_NO_OPEN") != "" {
		return false
	}
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	case "linux":
		_, err := exec.LookPath("xdg-open")
		return err == nil
	default:
		return false
	}
}

// Open launches path in the OS default application (e.g. a browser for HTML).
// It is best-effort: when unsupported or disabled it returns nil without doing
// anything, so callers never need to special-case the environment.
func Open(path string) error {
	if !CanOpen() {
		return nil
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	default: // linux and other xdg-based desktops
		cmd = exec.Command("xdg-open", path)
	}
	return cmd.Start() // Start, not Run: don't block on the browser process
}
