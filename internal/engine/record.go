package engine

import (
	"crypto/sha1"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/alert"
	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/device"
	"github.com/Emre-Diricanli/ndscan/internal/timeline"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

// Record is what a finished scan changed about what we know.
//
// It is returned rather than merely written so a front end can render the
// consequences of a scan — what changed, what is new — without repeating the
// work or reaching for the store itself.
type Record struct {
	// Diff is the per-host change set against the previous comparable scan.
	// Nil when this run was not eligible to be compared, which is not the same
	// as "nothing changed" and must not be rendered as if it were.
	Diff map[string]config.HostDiff
	// Previous is the snapshot this run was compared against, if any.
	Previous []config.HostSnapshot
	// Devices is every device we know about, updated with this run.
	Devices map[string]device.Record
	// NewDevices are keys seen for the first time in this run. Worth surfacing
	// on its own: it is the fact a person actually wants to be told, and it is
	// unrecoverable later, since by the next scan they look like any other
	// device with a first-seen date.
	NewDevices []string
	// Events are the timeline facts this run appended.
	Events []timeline.Event
	// Alerts are the changes worth telling a person about, already filtered by
	// the user's rules and by the suppressor that keeps watch mode from saying
	// the same thing every interval.
	Alerts []alert.Alert
	// Warnings are non-fatal persistence problems. A failed write is not fatal
	// to the scan but it silently disables change detection for every future
	// one, so it has to be said out loud rather than swallowed.
	Warnings []string
}

// timelineRetention is how far back the event log is kept. Long enough that
// "when did this first appear" stays answerable across a season, short enough
// that an always-on watcher does not accumulate forever.
const timelineRetention = 90 * 24 * time.Hour

// Comparable reports whether this run updated the baseline.
func (r Record) Comparable() bool { return r.Diff != nil }

// Persist folds a finished run into ndscan's durable state: scan history,
// the device set, and the timeline.
//
// All three front ends previously did the history half of this themselves,
// which is how the web came to save cancelled scans while the TUI did not.
// Putting it here means an incomplete run is rejected once, for everyone —
// and it is the reason the device and timeline stores can be added without
// inventing a third copy of the same decision.
//
// now is a parameter so a caller can attribute a run to when it started rather
// than when it finished writing, and so tests are not at the mercy of a clock.
func (e *Engine) Persist(out Outcome, p Plan, now time.Time, oui vendor.DB) Record {
	return e.PersistWithGateway(out, p, now, oui, "")
}

// PersistWithGateway is Persist plus the gateway address this scan ran behind,
// which the ARP-spoof canary needs in order to notice the hardware answering
// for it changing.
func (e *Engine) PersistWithGateway(out Outcome, p Plan, now time.Time, oui vendor.DB, gatewayIP string) Record {
	rec := Record{}
	key := out.ScanKey(p)
	prev := config.LoadHistory(key)
	rec.Previous = prev

	// An incomplete run looks exactly like a network where everything
	// disappeared. Recording it would report the whole network as gone now and
	// as new next time — one interruption corrupting change detection twice.
	if !out.Comparable() {
		return rec
	}

	cur := out.Snapshots()
	rec.Diff = config.Diff(prev, cur)
	if err := config.SaveHistory(key, cur); err != nil {
		rec.Warnings = append(rec.Warnings,
			"scan history could not be saved, so changes since this scan will not be detected: "+err.Error())
	}

	// Device identity before the timeline, because timeline events are keyed by
	// device: a host has to have an identity before anything can be recorded
	// against it.
	//
	// firstInventory records whether we knew of any device at all before this
	// scan. On a fresh install every host on the network is "new", which is an
	// artefact of having just started looking rather than an event — a small
	// home network produced four notifications on its first run, which is how
	// a person learns to turn alerting off.
	// LoadChecked: a corrupt store must not read as "no devices known", which
	// is what let a later Save overwrite it and destroy user-assigned names.
	// The scan still completes — losing identity tracking for one run is better
	// than failing a scan that otherwise worked — but the user is told.
	known, err := device.LoadChecked()
	if err != nil {
		rec.Warnings = append(rec.Warnings,
			"device records could not be read, so identity tracking is paused for this scan: "+err.Error())
	}
	firstInventory := len(known) == 0
	devices, added := device.Apply(known, device.FromRows(out.Rows, out.MACs, now), oui)
	rec.Devices, rec.NewDevices = devices, added
	if err := device.Save(devices); err != nil {
		rec.Warnings = append(rec.Warnings, "device records could not be saved: "+err.Error())
	}

	rec.Events = e.appendTimeline(rec, out, now, key.Scope())

	// Retention. Nothing pruned the log before, so a watch-mode user accrued
	// events indefinitely — the cost fell hardest on whoever adopted the
	// feature most enthusiastically. Failure here is not worth reporting: the
	// scan succeeded, and the next one tries again.
	_ = timeline.Prune(now.Add(-timelineRetention))

	// Alerting last: it reads the diff and the device set this run produced, so
	// it has to come after both. The suppressor is per-Engine, which is what
	// makes watch mode report a new device once rather than every interval.
	for _, a := range e.evaluateAlerts(&rec, out, gatewayIP, now, firstInventory) {
		if e.suppressor().Allow(a) {
			rec.Alerts = append(rec.Alerts, a)
		}
	}
	return rec
}

// suppressor returns the process-wide alert suppressor, built on first use.
func (e *Engine) suppressor() *alert.Suppressor {
	e.alertMu.Lock()
	defer e.alertMu.Unlock()
	if e.alertSup == nil {
		e.alertSup = alert.NewSuppressor(alertCooldown)
	}
	return e.alertSup
}

// appendTimeline turns this run's diff into durable facts.
//
// Events come from the diff rather than from the rows, so the log records what
// *changed* rather than restating the whole network on every scan. A watch loop
// running every minute would otherwise write thousands of identical "still
// here" records a day and bury the events that matter.
func (e *Engine) appendTimeline(rec Record, out Outcome, now time.Time, scope string) []timeline.Event {
	// The first comparable scan of a signature has no previous snapshot, so
	// every host would read as new. That is an artefact of having just started
	// watching, not an event: recording it would date every device's arrival to
	// whenever ndscan was installed.
	if len(rec.Previous) == 0 {
		return nil
	}

	// One run identifier for every event this scan writes. Timestamp equality
	// cannot serve as the batch boundary: two scans can finish in the same
	// instant, and a scan's own events need not share a timestamp exactly.
	run := runID(scope, now)

	keyFor := deviceKeys(out)
	var events []timeline.Event
	for ip, d := range rec.Diff {
		key := keyFor[ip]
		if key == "" {
			key = "ip:" + ip // a departed host has no row to identify it
		}
		switch {
		case d.New:
			events = append(events, timeline.Event{
				Type: timeline.EventHostSeen, Timestamp: now, DeviceKey: key, IP: ip,
				Scope: scope, Run: run,
			})
		case d.Gone:
			events = append(events, timeline.Event{
				Type: timeline.EventHostGone, Timestamp: now, DeviceKey: key, IP: ip,
				Scope: scope, Run: run,
			})
		}
		for _, port := range d.PortsOpened {
			events = append(events, portEvent(timeline.EventPortOpened, now, key, ip, port, scope, run))
		}
		for _, port := range d.PortsClosed {
			events = append(events, portEvent(timeline.EventPortClosed, now, key, ip, port, scope, run))
		}
	}

	written := events[:0]
	for _, ev := range events {
		// A failed append costs this one fact, not the run. Dropping the rest
		// because one write failed would lose more than it protects.
		if err := timeline.Append(ev); err == nil {
			written = append(written, ev)
		}
	}
	return written
}

// deviceKeys maps each scanned address to the device identity behind it, so a
// timeline event survives the host changing address later.
func deviceKeys(out Outcome) map[string]string {
	keys := make(map[string]string, len(out.Rows))
	for _, r := range out.Rows {
		mac := r.MAC
		if mac == "" {
			mac = out.MACs[r.IP]
		}
		keys[r.IP] = device.KeyFor(r.IP, mac).ID
	}
	return keys
}

func portEvent(kind timeline.EventType, now time.Time, key, ip, port, scope, run string) timeline.Event {
	n, proto := splitPort(port)
	return timeline.Event{
		Type: kind, Timestamp: now, DeviceKey: key, IP: ip, Port: n, Protocol: proto,
		Scope: scope, Run: run,
	}
}

// runID derives a stable per-run identifier from the scan signature and the
// moment the run is attributed to.
//
// It is a hash rather than a counter so it needs no shared state and no
// coordination between processes: a CLI scan and the web server watching can
// both write without agreeing on anything first.
func runID(scope string, at time.Time) string {
	h := sha1.Sum([]byte(scope + "|" + at.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h[:8])
}

// splitPort reads a port number and protocol out of a diff entry.
//
// config.Diff reduces port labels to bare numbers ("22/tcp ssh" becomes "22"),
// so the protocol is usually absent and recorded empty rather than guessed —
// writing "tcp" for a UDP port would put a wrong fact in an append-only log,
// which is worse than an incomplete one. The slashed form is still handled so
// this keeps working if the diff ever stops discarding it.
func splitPort(label string) (int, string) {
	num, proto, _ := strings.Cut(label, "/")
	if i := strings.IndexByte(proto, ' '); i >= 0 {
		proto = proto[:i] // "tcp ssh" -> "tcp"
	}
	n, err := strconv.Atoi(strings.TrimSpace(num))
	if err != nil {
		return 0, ""
	}
	return n, strings.TrimSpace(proto)
}
