package alert

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/device"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
)

// Alert is one change judged worth a human's attention. Title and Body are
// short enough to drop straight into a desktop notification; Subject is the
// device key or IP the alert concerns and, together with Rule, is what the
// suppressor keys on.
type Alert struct {
	Rule     string
	Severity string // scan's vocabulary: "", "info", "warn", "high"
	Title    string
	Body     string
	Subject  string // device key or IP
	At       time.Time
}

// Evaluate applies rules to one scan's worth of changes and returns the
// alerts to raise, most severe first.
//
// It is pure: no I/O, no notifications, no clock reads — the caller injects
// the time. That is what makes it testable, and what leaves the notify/log/
// both decision to the caller. Inputs it does not mutate: newDeviceKeys and
// the maps are read-only here.
//
// gatewayMAC and previousGatewayMAC are compared empty-safely: a first run
// that learns the gateway's MAC for the first time must not cry ARP spoof.
func Evaluate(rules []Rule, diff map[string]config.HostDiff, devices map[string]device.Record, newDeviceKeys []string, gatewayMAC, previousGatewayMAC string, now time.Time) []Alert {
	var out []Alert
	for _, r := range rules {
		switch r.Kind {
		case KindNewDevice:
			out = append(out, evalNewDevice(r, devices, newDeviceKeys, now)...)
		case KindPortOpened:
			out = append(out, evalPortOpened(r, diff, now)...)
		case KindHostGone:
			out = append(out, evalHostGone(r, diff, now)...)
		case KindGatewayMACChanged:
			if a, ok := evalGatewayMAC(r, gatewayMAC, previousGatewayMAC, now); ok {
				out = append(out, a)
			}
		}
	}
	sortAlerts(out)
	return out
}

func evalNewDevice(r Rule, devices map[string]device.Record, keys []string, now time.Time) []Alert {
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	var out []Alert
	for _, key := range sorted {
		rec, known := devices[key]
		if r.StableOnly {
			// A randomized MAC yields an ephemeral key per visit; without this
			// check a privacy-conscious phone alerts every single day.
			stable := known && rec.Confidence == device.Stable.String()
			if !stable {
				continue
			}
		}
		ids := []string{key}
		if known {
			ids = append(ids, rec.Addresses...)
			if rec.MAC != "" {
				ids = append(ids, rec.MAC)
			}
		}
		if r.ignored(ids...) {
			continue
		}
		label := key
		if known {
			label = rec.Label()
		}
		out = append(out, Alert{
			Rule:     r.Name,
			Severity: severityOr(r.Severity, "info"),
			Title:    "New device on the network",
			Body:     fmt.Sprintf("%s appeared for the first time (%s)", label, key),
			Subject:  key,
			At:       now,
		})
	}
	return out
}

func evalPortOpened(r Rule, diff map[string]config.HostDiff, now time.Time) []Alert {
	threshold := parseSeverity(r.MinSeverity)
	var out []Alert
	for _, ip := range sortedKeys(diff) {
		d := diff[ip]
		if d.Gone {
			continue // a vanished host's "opened" ports are meaningless
		}
		ports := append([]string(nil), d.PortsOpened...)
		sort.Strings(ports)
		for _, ps := range ports {
			port, err := strconv.Atoi(ps)
			if err != nil {
				continue
			}
			if len(r.Ports) > 0 && !portListed(r.Ports, port) {
				continue
			}
			risk := scan.ClassifyPort(port, "")
			if threshold > scan.SevNone && risk.Severity < threshold {
				continue
			}
			if r.ignored(ip) {
				continue
			}
			// A classified port's own risk severity beats the rule's static
			// one: Telnet opening is "high" no matter what the rule says.
			sev := risk.Severity.String()
			if sev == "" {
				sev = severityOr(r.Severity, "info")
			}
			body := fmt.Sprintf("%s now accepts connections on port %d", ip, port)
			if risk.Reason != "" {
				body += " — " + risk.Reason
			}
			out = append(out, Alert{
				Rule:     r.Name,
				Severity: sev,
				Title:    fmt.Sprintf("Port %d opened on %s", port, ip),
				Body:     body,
				Subject:  ip,
				At:       now,
			})
		}
	}
	return out
}

func evalHostGone(r Rule, diff map[string]config.HostDiff, now time.Time) []Alert {
	var out []Alert
	for _, ip := range sortedKeys(diff) {
		if !diff[ip].Gone || r.ignored(ip) {
			continue
		}
		out = append(out, Alert{
			Rule:     r.Name,
			Severity: severityOr(r.Severity, "info"),
			Title:    "Host disappeared",
			Body:     fmt.Sprintf("%s was present in the previous scan but is gone", ip),
			Subject:  ip,
			At:       now,
		})
	}
	return out
}

func evalGatewayMAC(r Rule, gatewayMAC, previousGatewayMAC string, now time.Time) (Alert, bool) {
	cur, prev := normalizeMAC(gatewayMAC), normalizeMAC(previousGatewayMAC)
	// Either side empty means we have no basis for comparison — most commonly
	// the first run after the feature lands, which must not alert.
	if cur == "" || prev == "" || cur == prev {
		return Alert{}, false
	}
	if r.ignored(cur, prev, gatewayMAC, previousGatewayMAC) {
		return Alert{}, false
	}
	return Alert{
		Rule:     r.Name,
		Severity: severityOr(r.Severity, "high"),
		Title:    "Gateway MAC address changed",
		Body:     fmt.Sprintf("gateway hardware address changed from %s to %s — possible ARP spoofing", previousGatewayMAC, gatewayMAC),
		Subject:  "gateway",
		At:       now,
	}, true
}

// normalizeMAC reduces a hardware address to bare lowercase hex so formatting
// differences between tools (colons, dashes, case) never read as a change.
func normalizeMAC(mac string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r + ('a' - 'A')
		}
		return -1
	}, mac)
}

func sortedKeys(m map[string]config.HostDiff) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func portListed(list []int, port int) bool {
	for _, p := range list {
		if p == port {
			return true
		}
	}
	return false
}

// sortAlerts orders alerts most-severe-first with deterministic tiebreaks, so
// the same inputs always produce byte-identical output.
func sortAlerts(alerts []Alert) {
	sort.SliceStable(alerts, func(i, j int) bool {
		a, b := alerts[i], alerts[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.Title < b.Title
	})
}

// Suppressor stops watch mode from re-alerting the same fact every interval.
// A "new device" is new once; without suppression, a 60-second watch loop
// would notify for it 60 times an hour.
//
// It reads no clock: every decision is made against the timestamp the caller
// carries on the alert, which keeps it testable and consistent with Evaluate.
type Suppressor struct {
	cooldown time.Duration
	mu       sync.Mutex
	last     map[string]time.Time
}

// NewSuppressor returns a Suppressor that re-alerts on the same rule+subject
// only after cooldown has elapsed. A non-positive cooldown suppresses
// nothing.
func NewSuppressor(cooldown time.Duration) *Suppressor {
	return &Suppressor{cooldown: cooldown, last: map[string]time.Time{}}
}

// Allow reports whether this alert should be raised now. The first occurrence
// of a rule+subject always passes; a repeat within the cooldown window is
// dropped, and one after the window passes — a device that left and genuinely
// returned alerts again.
func (s *Suppressor) Allow(a Alert) bool {
	if s.cooldown <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := a.Rule + "\x00" + a.Subject
	if t, ok := s.last[key]; ok && a.At.Before(t.Add(s.cooldown)) {
		return false
	}
	s.last[key] = a.At
	return true
}

// Filter drops suppressed alerts, returning the ones worth raising.
func (s *Suppressor) Filter(alerts []Alert) []Alert {
	out := alerts[:0]
	for _, a := range alerts {
		if s.Allow(a) {
			out = append(out, a)
		}
	}
	return out
}
