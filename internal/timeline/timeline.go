// Package timeline keeps the durable, longitudinal record of facts observed by
// ndscan. Device keys are deliberately opaque; deciding identity belongs to the
// caller rather than the persistence layer.
package timeline

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/userenv"
)

// EventType identifies the fact recorded by an Event.
type EventType string

const (
	EventHostSeen   EventType = "host_seen"
	EventHostGone   EventType = "host_gone"
	EventPortOpened EventType = "port_opened"
	EventPortClosed EventType = "port_closed"
)

// Event is one immutable fact. Fields not relevant to an event type are
// omitted, allowing later versions to add optional fields without invalidating
// records written by older versions.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Type      EventType `json:"type"`
	DeviceKey string    `json:"device_key"`
	IP        string    `json:"ip"`
	Port      int       `json:"port,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	// Scope identifies which scan signature produced this event, so a query
	// can be restricted to the network it asked about.
	//
	// Without it the log is a single undifferentiated stream, and a caller
	// asking "what changed on 10.0.0.0/24" gets whatever was scanned most
	// recently — which is exactly what `ndscan diff` did: it reported hosts
	// from an entirely different subnet, confidently, in a command documented
	// as safe for cron.
	//
	// Empty means the event predates scoping. Such events are real history and
	// are kept, but they cannot be attributed to any signature, so a
	// scope-filtered query must exclude rather than guess at them.
	Scope string `json:"scope,omitempty"`
	// Run groups the events of one scan. Timestamp equality is not a sound
	// batch boundary: two scans can finish in the same instant, and the events
	// of a single scan need not share a timestamp exactly.
	Run string `json:"run,omitempty"`
}

// Scoped reports whether this event can be attributed to a scan signature.
// Events written before scoping existed cannot be, and saying so is better than
// silently folding them into someone else's network.
func (e Event) Scoped() bool { return e.Scope != "" }

var appendMu sync.Mutex

func timelineDir() string { return filepath.Join(config.Dir(), "timeline") }

// Daily files make retention predictable without producing enough files to
// matter for the expected few thousand records.
func eventPath(t time.Time) string {
	return filepath.Join(timelineDir(), t.UTC().Format("2006-01-02")+".jsonl")
}

// Append durably adds an event to the timeline.
//
// The mutex covers goroutines in this process. Cross-process locking is out of
// scope; callers must not run multiple writers against the same config dir.
func Append(event Event) error {
	if event.Timestamp.IsZero() {
		return errors.New("timeline: event timestamp is required")
	}
	event.Timestamp = event.Timestamp.UTC()
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	appendMu.Lock()
	defer appendMu.Unlock()

	if err := os.MkdirAll(timelineDir(), 0o755); err != nil {
		return err
	}
	_ = userenv.Chown(timelineDir())

	path := eventPath(event.Timestamp)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := userenv.Chown(path); err != nil {
		return err
	}
	// A crash can leave only the final record torn. Remove that incomplete
	// suffix before adding another event so it can never become corrupt middle
	// data on the next process start; complete records are never rewritten.
	if err := discardTornSuffix(f); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if _, err := f.Write(line); err != nil {
		return err
	}
	return f.Sync()
}

func discardTornSuffix(f *os.File) error {
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return err
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, info.Size()-1); err != nil {
		return err
	}
	if last[0] == '\n' {
		return nil
	}
	const blockSize = int64(4096)
	for end := info.Size(); end > 0; {
		start := end - blockSize
		if start < 0 {
			start = 0
		}
		buf := make([]byte, end-start)
		if _, err := f.ReadAt(buf, start); err != nil {
			return err
		}
		if i := strings.LastIndexByte(string(buf), '\n'); i >= 0 {
			return f.Truncate(start + int64(i) + 1)
		}
		end = start
	}
	return f.Truncate(0)
}

func files() ([]string, error) {
	entries, err := os.ReadDir(timelineDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".jsonl") {
			paths = append(paths, filepath.Join(timelineDir(), entry.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func allEvents() ([]Event, error) {
	paths, err := files()
	if err != nil {
		return nil, err
	}
	var events []Event
	for _, path := range paths {
		loaded, err := readFile(path)
		if err != nil {
			return nil, err
		}
		events = append(events, loaded...)
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	return events, nil
}

func readFile(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var events []Event
	for {
		line, readErr := r.ReadBytes('\n')
		if len(line) > 0 {
			if readErr == io.EOF {
				break // A final line without a newline may be a torn append.
			}
			var event Event
			if err := json.Unmarshal(line, &event); err != nil {
				return nil, fmt.Errorf("timeline: read %s: %w", path, err)
			}
			events = append(events, event)
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return nil, readErr
		}
	}
	return events, nil
}

// History returns all events for deviceKey in timestamp order.
func History(deviceKey string) ([]Event, error) {
	events, err := allEvents()
	if err != nil {
		return nil, err
	}
	return filter(events, func(e Event) bool { return e.DeviceKey == deviceKey }), nil
}

// PortHistory returns open and close events for a port on a device.
func PortHistory(deviceKey string, port int) ([]Event, error) {
	events, err := allEvents()
	if err != nil {
		return nil, err
	}
	return filter(events, func(e Event) bool {
		return e.DeviceKey == deviceKey && e.Port == port && (e.Type == EventPortOpened || e.Type == EventPortClosed)
	}), nil
}

// Recent returns events at or after since in timestamp order, across every
// scan. Callers that mean "this network" want Select with a Scope instead.
func Recent(since time.Time) ([]Event, error) {
	return Select(Query{Since: since})
}

// Query narrows a timeline read. The zero value matches everything.
type Query struct {
	// Scope restricts results to one scan signature (config.ScanKey.Scope()).
	// Empty means every scope.
	//
	// Events written before scoping existed carry no scope and are excluded
	// whenever a Scope is given: they are real history, but attributing them to
	// a signature we cannot verify is how the unscoped log came to report one
	// network's changes as another's.
	Scope string
	// Run restricts results to a single scan run.
	Run string
	// Since keeps events at or after this time. Zero keeps everything.
	Since time.Time
	// DeviceKey restricts results to one device.
	DeviceKey string
}

func (q Query) matches(e Event) bool {
	if q.Scope != "" && e.Scope != q.Scope {
		return false
	}
	if q.Run != "" && e.Run != q.Run {
		return false
	}
	if q.DeviceKey != "" && e.DeviceKey != q.DeviceKey {
		return false
	}
	return !e.Timestamp.Before(q.Since)
}

// Select returns the events matching q, in timestamp order.
func Select(q Query) ([]Event, error) {
	events, err := allEvents()
	if err != nil {
		return nil, err
	}
	return filter(events, q.matches), nil
}

// LatestRun returns the events of the most recent run within a scope, and that
// run's identifier.
//
// Grouping by run rather than by timestamp is what makes this correct: two
// scans can finish in the same instant, and one scan's events need not share a
// timestamp exactly, so timestamp equality is not a batch boundary.
func LatestRun(scope string) ([]Event, string, error) {
	events, err := Select(Query{Scope: scope})
	if err != nil || len(events) == 0 {
		return nil, "", err
	}
	// allEvents is timestamp-ordered, so the last run to appear is the latest.
	run := events[len(events)-1].Run
	if run == "" {
		// Pre-run-ID events: fall back to the old timestamp grouping rather
		// than returning nothing, since that is the best this data supports.
		last := events[len(events)-1].Timestamp
		return filter(events, func(e Event) bool { return e.Timestamp.Equal(last) }), "", nil
	}
	return filter(events, func(e Event) bool { return e.Run == run }), run, nil
}

func filter(events []Event, keep func(Event) bool) []Event {
	result := make([]Event, 0)
	for _, event := range events {
		if keep(event) {
			result = append(result, event)
		}
	}
	return result
}

// FirstSeen returns the earliest observation of an up device.
func FirstSeen(deviceKey string) (time.Time, bool, error) { return seenBound(deviceKey, false) }

// LastSeen returns the latest observation of an up device.
func LastSeen(deviceKey string) (time.Time, bool, error) { return seenBound(deviceKey, true) }

func seenBound(deviceKey string, last bool) (time.Time, bool, error) {
	events, err := History(deviceKey)
	if err != nil {
		return time.Time{}, false, err
	}
	var found time.Time
	for _, event := range events {
		if event.Type == EventHostSeen && (found.IsZero() || last) {
			found = event.Timestamp
		}
	}
	return found, !found.IsZero(), nil
}

// Devices returns every known opaque device key in lexical order.
func Devices() ([]string, error) {
	events, err := allEvents()
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{})
	for _, event := range events {
		set[event.DeviceKey] = struct{}{}
	}
	devices := make([]string, 0, len(set))
	for device := range set {
		devices = append(devices, device)
	}
	sort.Strings(devices)
	return devices, nil
}

// Prune removes only day files whose entire UTC day precedes olderThan.
func Prune(olderThan time.Time) error {
	appendMu.Lock()
	defer appendMu.Unlock()
	paths, err := files()
	if err != nil {
		return err
	}
	cutoff := olderThan.UTC()
	for _, path := range paths {
		day, err := time.Parse("2006-01-02", strings.TrimSuffix(filepath.Base(path), ".jsonl"))
		if err != nil {
			continue
		}
		if !day.Add(24 * time.Hour).After(cutoff) {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
	}
	return nil
}
