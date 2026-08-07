package tui

import (
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/engine"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// The running screen appends the rows it is sent, so a revision must not arrive
// looking like an arrival — otherwise every host is drawn twice once hostname
// enrichment finishes.
func TestScanAdapterIgnoresRowRevisions(t *testing.T) {
	ch := make(chan interface{}, 8)
	rows := []ui.Row{{IP: "192.0.2.1", Up: true}}

	// Mirror the adapter's event handling.
	handle := func(e engine.Event) {
		switch e.Kind {
		case engine.EventRows:
			ch <- e.Rows
		case engine.EventRowsUpdated:
			// dropped on purpose
		}
	}
	handle(engine.Event{Kind: engine.EventRows, Rows: rows})
	handle(engine.Event{Kind: engine.EventRowsUpdated, Rows: rows})
	close(ch)

	got := 0
	for range ch {
		got++
	}
	if got != 1 {
		t.Errorf("forwarded %d row batches, want 1 (revisions must not be appended)", got)
	}
}
