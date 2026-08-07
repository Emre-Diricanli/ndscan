package tui

import (
	"testing"
	"time"
)

// Drives the real TUI scan path end to end against localhost, asserting the
// Bubbletea message protocol still holds after the engine port.
func TestRunScanEndToEnd(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	ch, cancel := runScan(scanParams{
		targets: []string{"127.0.0.1"}, preset: "quick",
		concurrency: 32, hostTimeout: 10 * time.Second,
	})
	defer cancel()

	var phases, rowMsgs int
	var done *doneMsg
	for msg := range ch {
		switch m := msg.(type) {
		case phaseMsg:
			phases++
		case hostRowMsg:
			rowMsgs += len(m.rows)
		case doneMsg:
			d := m
			done = &d
		case errMsg:
			t.Fatalf("scan errored: %v", m.err)
		}
	}
	if done == nil {
		t.Fatal("scan never produced a doneMsg")
	}
	if phases == 0 {
		t.Error("no phase messages: progress reporting is broken")
	}
	if len(done.rows) == 0 {
		t.Error("scanning 127.0.0.1 should find localhost")
	}
	if done.cancelled {
		t.Error("an uninterrupted scan must not report cancelled")
	}
	if done.timings.discovery == 0 && done.timings.ports == 0 {
		t.Error("timings were not populated")
	}
	// Rows must not be double-counted once hostname enrichment revises them.
	if rowMsgs > len(done.rows) {
		t.Errorf("streamed %d rows but final set has %d: revisions are being appended", rowMsgs, len(done.rows))
	}
	t.Logf("phases=%d streamed=%d final=%d timings=%+v", phases, rowMsgs, len(done.rows), done.timings)
}
