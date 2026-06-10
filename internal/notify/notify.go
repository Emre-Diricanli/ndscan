// Package notify sends native desktop notifications, used by watch mode to
// alert on network changes (new/gone hosts, newly opened ports). It degrades
// to a no-op on platforms without a supported notifier so callers never need
// to special-case the environment.
package notify

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Notification is a single desktop alert.
type Notification struct {
	Title    string
	Message  string
	Subtitle string // shown on macOS; ignored elsewhere
}

// Available reports whether a desktop notifier is usable on this system.
func Available() bool {
	switch runtime.GOOS {
	case "darwin":
		_, err := exec.LookPath("osascript")
		return err == nil
	case "linux":
		_, err := exec.LookPath("notify-send")
		return err == nil
	default:
		return false
	}
}

// Send posts a desktop notification, returning nil if delivered (or quietly if
// no notifier exists). It is best-effort: a missing notifier is not an error.
func Send(n Notification) error {
	if !Available() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	switch runtime.GOOS {
	case "darwin":
		return exec.CommandContext(ctx, "osascript", "-e", appleScript(n)).Run()
	case "linux":
		args := []string{"-a", "ndscan"}
		if n.Subtitle != "" {
			args = append(args, n.Title+" — "+n.Subtitle, n.Message)
		} else {
			args = append(args, n.Title, n.Message)
		}
		return exec.CommandContext(ctx, "notify-send", args...).Run()
	default:
		return nil
	}
}

// appleScript builds an AppleScript `display notification` command, escaping
// any embedded double quotes so titles/messages can't break out of the string.
func appleScript(n Notification) string {
	var b strings.Builder
	b.WriteString(`display notification "`)
	b.WriteString(esc(n.Message))
	b.WriteString(`" with title "`)
	b.WriteString(esc(n.Title))
	b.WriteString(`"`)
	if n.Subtitle != "" {
		b.WriteString(` subtitle "`)
		b.WriteString(esc(n.Subtitle))
		b.WriteString(`"`)
	}
	return b.String()
}

func esc(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	// AppleScript strings can't contain raw newlines; flatten to spaces.
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
