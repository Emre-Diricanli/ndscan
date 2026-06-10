package tui

import (
	"strings"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

func TestNotifySummary_NoChange(t *testing.T) {
	if _, _, ok := notifySummary(nil, nil); ok {
		t.Error("nil diff should produce no notification")
	}
	// A diff map with only empty entries also shouldn't alert.
	empty := map[string]config.HostDiff{"1.2.3.4": {}}
	if _, _, ok := notifySummary(empty, nil); ok {
		t.Error("empty diff entry should produce no notification")
	}
}

func TestNotifySummary_SingleNewHostUsesVendor(t *testing.T) {
	diff := map[string]config.HostDiff{
		"192.168.86.42": {New: true},
	}
	rows := []ui.Row{{IP: "192.168.86.42", Vendor: "Espressif"}}
	title, body, ok := notifySummary(diff, rows)
	if !ok {
		t.Fatal("expected a notification")
	}
	if title != "New host: 192.168.86.42 (Espressif)" {
		t.Errorf("title = %q", title)
	}
	if !strings.Contains(body, "+ 192.168.86.42 (Espressif)") {
		t.Errorf("body = %q, want new-host line", body)
	}
}

func TestNotifySummary_MixedChanges(t *testing.T) {
	diff := map[string]config.HostDiff{
		"10.0.0.1": {New: true},
		"10.0.0.2": {Gone: true},
		"10.0.0.3": {PortsOpened: []string{"22", "80"}, PortsClosed: []string{"443"}},
	}
	title, body, ok := notifySummary(diff, nil)
	if !ok {
		t.Fatal("expected a notification")
	}
	// New hosts take title priority.
	if !strings.Contains(title, "new host") {
		t.Errorf("title = %q, want new-host priority", title)
	}
	for _, want := range []string{"+ 10.0.0.1", "- 10.0.0.2", "2 port(s) opened", "1 port(s) closed"} {
		if !strings.Contains(body, want) {
			t.Errorf("body %q missing %q", body, want)
		}
	}
}

func TestClip(t *testing.T) {
	got := clip([]string{"a", "b", "c", "d", "e"}, 3)
	if len(got) != 4 || got[3] != "+2 more" {
		t.Errorf("clip = %v, want a,b,c,+2 more", got)
	}
	if got := clip([]string{"a", "b"}, 3); len(got) != 2 {
		t.Errorf("clip under cap = %v, want unchanged", got)
	}
}
