package web

import (
	"sync"
	"time"
)

// phaseThrottle coalesces per-probe progress callbacks into SSE "phase"
// events. A /16 sweep fires on the order of a million callbacks, and each
// publish costs a json.Marshal plus a fan-out under the bus lock — nearly all
// of which slow clients drop anyway. Capping progress at ~10Hz keeps the UI
// live without letting progress reporting tax the scan itself.
//
// The tail of a phase is never throttled: an update that reaches the total
// publishes immediately, and flush delivers the newest throttled update when
// a phase ends. A swallowed final event would leave the progress bar stuck
// just short of 100% forever, which is a correctness bug, not a cosmetic one.
type phaseThrottle struct {
	bus   *eventBus
	phase string
	min   time.Duration

	mu      sync.Mutex
	lastPub time.Time
	pending *phaseProgress // newest throttled update, delivered by flush
}

type phaseProgress struct {
	done  int
	total int
}

func newPhaseThrottle(bus *eventBus, phase string, minInterval time.Duration) *phaseThrottle {
	return &phaseThrottle{bus: bus, phase: phase, min: minInterval}
}

// update records progress. It publishes immediately when the interval has
// elapsed or the phase has reached its total; otherwise it keeps only the
// newest value for flush. Safe to call from the many goroutines a scan fans
// out to.
func (t *phaseThrottle) update(done, total int) {
	p := phaseProgress{done: done, total: total}

	t.mu.Lock()
	terminal := total > 0 && done >= total
	if !terminal && time.Since(t.lastPub) < t.min {
		t.pending = &p
		t.mu.Unlock()
		return
	}
	t.lastPub = time.Now()
	t.pending = nil
	t.mu.Unlock()

	t.publish(p)
}

// flush publishes the newest throttled update, if any. Call it when a phase
// ends so a final burst shorter than the interval cannot swallow the tail.
func (t *phaseThrottle) flush() {
	t.mu.Lock()
	p := t.pending
	t.pending = nil
	t.mu.Unlock()
	if p != nil {
		t.publish(*p)
	}
}

func (t *phaseThrottle) publish(p phaseProgress) {
	t.bus.publish("phase", map[string]any{"phase": t.phase, "done": p.done, "total": p.total})
}
