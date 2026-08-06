package web

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

type phaseEvent struct {
	Phase string `json:"phase"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
}

// drainEvents collects everything a subscriber has received so far without
// blocking. Anything still in flight is simply not asserted on.
func drainEvents(ch <-chan sseMessage) []phaseEvent {
	var out []phaseEvent
	for {
		select {
		case msg := <-ch:
			var ev phaseEvent
			if err := json.Unmarshal(msg.data, &ev); err != nil {
				continue
			}
			out = append(out, ev)
		default:
			return out
		}
	}
}

// The final update of a phase must reach subscribers even when it lands at the
// end of a burst far shorter than the throttle interval — otherwise the UI's
// progress bar sticks just short of 100% forever.
func TestPhaseThrottle_TerminalBypassesRateLimit(t *testing.T) {
	bus := newEventBus()
	id, ch := bus.subscribe()
	defer bus.unsubscribe(id)

	th := newPhaseThrottle(bus, "scan", time.Hour)
	const total = 1000
	for done := 1; done <= total; done++ {
		th.update(done, total)
	}

	events := drainEvents(ch)
	if len(events) == 0 {
		t.Fatal("no events published")
	}
	last := events[len(events)-1]
	if last.Done != total || last.Total != total {
		t.Errorf("final event = %+v, want done=%d total=%d", last, total, total)
	}
	if len(events) >= total {
		t.Errorf("throttle published %d of %d updates, want heavy coalescing", len(events), total)
	}
}

// A phase that ends without ever hitting done == total (e.g. a cancelled
// discovery) must still deliver its newest update via flush.
func TestPhaseThrottle_FlushDeliversNewestPending(t *testing.T) {
	bus := newEventBus()
	id, ch := bus.subscribe()
	defer bus.unsubscribe(id)

	th := newPhaseThrottle(bus, "discover", time.Hour)
	th.update(1, 10) // publishes: first update, interval since zero time
	th.update(7, 10) // throttled, becomes pending
	th.update(9, 10) // throttled, replaces pending
	th.flush()

	events := drainEvents(ch)
	if len(events) != 2 {
		t.Fatalf("events = %+v, want exactly the first and the flushed newest", events)
	}
	if events[1].Done != 9 {
		t.Errorf("flushed event = %+v, want done=9 (the newest, not a stale one)", events[1])
	}

	// A second flush with nothing pending must not republish.
	th.flush()
	if got := drainEvents(ch); len(got) != 0 {
		t.Errorf("second flush republished %+v", got)
	}
}

// Within one interval only the leading update may publish; the rest coalesce.
func TestPhaseThrottle_CoalescesBurst(t *testing.T) {
	bus := newEventBus()
	id, ch := bus.subscribe()
	defer bus.unsubscribe(id)

	th := newPhaseThrottle(bus, "scan", time.Hour)
	for done := 1; done <= 500; done++ {
		th.update(done, 1000)
	}

	if got := drainEvents(ch); len(got) != 1 {
		t.Errorf("burst published %d events, want 1", len(got))
	}
}

// Progress callbacks arrive from many scan worker goroutines at once; run with
// -race. The terminal update must still win afterwards.
func TestPhaseThrottle_ConcurrentUpdates(t *testing.T) {
	bus := newEventBus()
	id, ch := bus.subscribe()
	defer bus.unsubscribe(id)

	th := newPhaseThrottle(bus, "scan", time.Millisecond)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 1; i <= 250; i++ {
				th.update(i, 2000)
			}
		}(w)
	}
	wg.Wait()
	th.update(2000, 2000)

	events := drainEvents(ch)
	if len(events) == 0 {
		t.Fatal("no events published")
	}
	if last := events[len(events)-1]; last.Done != 2000 {
		t.Errorf("final event = %+v, want done=2000", last)
	}
}
