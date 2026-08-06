package web

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Watch mode re-runs the last scan on an interval and reports what changed.
//
// It lives on the server rather than in the browser deliberately: the loop then
// survives a closed tab, a reload, or a laptop lid, and every connected client
// sees the same history instead of each maintaining its own timer.

// minWatchInterval bounds how often a rescan can fire. Watch mode exists to
// notice changes, not to hammer the network — and a scan that overlaps the next
// tick would queue work faster than it drains.
const minWatchInterval = 15 * time.Second

// watchState is the server's watch-loop bookkeeping.
type watchState struct {
	enabled  bool
	interval time.Duration
	targets  []string
	fast     bool
	preset   string
	nextAt   time.Time
	cancel   context.CancelFunc
	// gen invalidates a running loop when settings change, so a stale
	// goroutine can't fire a rescan after the user turned watch off.
	gen int
}

type watchRequest struct {
	Enabled     bool     `json:"enabled"`
	IntervalSec int      `json:"intervalSec"`
	Targets     []string `json:"targets"`
	Fast        *bool    `json:"fast"`
	Preset      string   `json:"preset"`
}

type watchResponse struct {
	Enabled     bool   `json:"enabled"`
	IntervalSec int    `json:"intervalSec"`
	NextAt      string `json:"nextAt,omitempty"`
}

func (s *Server) handleWatch(w http.ResponseWriter, r *http.Request) {
	var req watchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if !req.Enabled {
		s.stopWatch()
		writeJSON(w, http.StatusOK, watchResponse{Enabled: false})
		return
	}

	// Enabling requires the same validation a manual scan gets: watch mode is
	// just a scan on a timer, and a bad target must not be accepted here only
	// to fail silently every interval.
	targets := req.Targets
	if len(targets) == 0 {
		s.mu.RLock()
		targets = s.targets
		s.mu.RUnlock()
	}
	if err := validateTargets(targets); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	preset := req.Preset
	if preset == "" {
		preset = "quick"
	}
	if !validPreset(preset) {
		writeErr(w, http.StatusBadRequest, "invalid preset "+preset)
		return
	}

	interval := time.Duration(req.IntervalSec) * time.Second
	if interval < minWatchInterval {
		interval = minWatchInterval
	}
	fast := true
	if req.Fast != nil {
		fast = *req.Fast
	}

	next := s.startWatch(targets, preset, fast, interval)
	writeJSON(w, http.StatusOK, watchResponse{
		Enabled:     true,
		IntervalSec: int(interval.Seconds()),
		NextAt:      next.UTC().Format(time.RFC3339),
	})
}

// startWatch begins (or restarts) the watch loop and returns the next fire time.
func (s *Server) startWatch(targets []string, preset string, fast bool, interval time.Duration) time.Time {
	s.mu.Lock()
	if s.watch.cancel != nil {
		s.watch.cancel()
	}
	s.watch.gen++
	gen := s.watch.gen
	ctx, cancel := context.WithCancel(context.Background())
	next := time.Now().Add(interval)
	s.watch = watchState{
		enabled: true, interval: interval, targets: targets,
		fast: fast, preset: preset, nextAt: next, cancel: cancel, gen: gen,
	}
	s.mu.Unlock()

	go s.watchLoop(ctx, gen)
	return next
}

func (s *Server) stopWatch() {
	s.mu.Lock()
	if s.watch.cancel != nil {
		s.watch.cancel()
	}
	s.watch = watchState{gen: s.watch.gen + 1}
	s.mu.Unlock()
	s.bus.publish("watch", map[string]any{"enabled": false})
}

// watchLoop rescans on the configured interval until cancelled. A tick that
// lands while a scan is already running is skipped rather than queued, so a
// slow scan can never cause ticks to pile up.
func (s *Server) watchLoop(ctx context.Context, gen int) {
	for {
		s.mu.RLock()
		st := s.watch
		s.mu.RUnlock()
		if !st.enabled || st.gen != gen {
			return // superseded or turned off
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(st.nextAt)):
		}

		s.mu.RLock()
		stale := s.watch.gen != gen || !s.watch.enabled
		s.mu.RUnlock()
		if stale {
			return
		}
		// startScan owns the idle-to-scanning transition, so a manual request
		// cannot enter between a separate watch check and state update.
		//
		// It starts the scan in its own goroutine, but the interval is meant to
		// be the gap *between* scans: scheduling the next tick while this one is
		// still running would let a scan slower than the interval be woken every
		// interval, each wake bouncing off the busy check. Waiting keeps the
		// documented "skipped rather than queued" behaviour.
		if done, started := s.startScanDone(st.targets, st.preset, st.fast); started {
			s.bus.publish("watch", map[string]any{"enabled": true, "rescanning": true})
			select {
			case <-ctx.Done():
				return
			case <-done:
			}
		}

		s.mu.Lock()
		if s.watch.gen == gen && s.watch.enabled {
			s.watch.nextAt = time.Now().Add(s.watch.interval)
		}
		next := s.watch.nextAt
		s.mu.Unlock()
		s.bus.publish("watch", map[string]any{
			"enabled": true, "nextAt": next.UTC().Format(time.RFC3339),
		})
	}
}

func validPreset(p string) bool {
	switch p {
	case "quick", "smart", "default", "udp", "deep":
		return true
	}
	return false
}
