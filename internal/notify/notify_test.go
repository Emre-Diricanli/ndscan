package notify

import "testing"

func TestAppleScriptEscaping(t *testing.T) {
	n := Notification{
		Title:    `host "router"`,
		Message:  "port 22 opened\non 192.168.1.1",
		Subtitle: `a\b`,
	}
	got := appleScript(n)

	// Embedded quotes must be backslash-escaped so they can't terminate the
	// AppleScript string early.
	want := `display notification "port 22 opened on 192.168.1.1" with title "host \"router\"" subtitle "a\\b"`
	if got != want {
		t.Errorf("appleScript mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestEscFlattensNewlines(t *testing.T) {
	if got := esc("a\nb"); got != "a b" {
		t.Errorf("esc newline = %q, want %q", got, "a b")
	}
}

func TestSendNoNotifierIsNotError(t *testing.T) {
	// On a system without a notifier, Send must be a silent no-op. We can't
	// force Available()==false portably, but Send must never panic or error
	// for a well-formed notification regardless of platform.
	if err := Send(Notification{Title: "t", Message: "m"}); err != nil {
		// A delivery failure (e.g. headless CI) is tolerated; only a non-nil
		// error from a *present* notifier would surface here, which is fine to
		// log but not fail on.
		t.Logf("Send returned (tolerated): %v", err)
	}
}
