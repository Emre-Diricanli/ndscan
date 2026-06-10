package notify

import (
	"os"
	"testing"
)

// TestManualSend fires a real notification when NDSCAN_NOTIFY_DEMO=1 so we can
// eyeball it. Skipped by default.
func TestManualSend(t *testing.T) {
	if os.Getenv("NDSCAN_NOTIFY_DEMO") != "1" {
		t.Skip("set NDSCAN_NOTIFY_DEMO=1 to fire a real notification")
	}
	if err := Send(Notification{
		Title:    "ndscan",
		Subtitle: "New host: 192.168.86.42 (Espressif)",
		Message:  "+ 192.168.86.42 (Espressif) · 2 port(s) opened",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
}
