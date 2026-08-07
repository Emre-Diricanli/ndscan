// Package alert decides which network changes are worth telling a human
// about.
//
// The diff (internal/config) and device identity (internal/device) layers can
// say *what* changed; this package says *whether anyone should care*. Rules
// are user-editable JSON at config.Dir()/rules.json, evaluation is a pure
// function so the caller decides whether an alert becomes a desktop
// notification, a log line, or both.
package alert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
)

// Rule kinds. Unknown kinds in a rules file simply never fire — a typo'd rule
// is inert rather than a load error, because silently dropping a user's whole
// rule set over one bad entry is the worse failure.
const (
	// KindNewDevice fires when a device key never seen before appears.
	KindNewDevice = "new-device"
	// KindPortOpened fires when a port opens on a host.
	KindPortOpened = "port-opened"
	// KindHostGone fires when a previously-seen host disappears.
	KindHostGone = "host-gone"
	// KindGatewayMACChanged fires when the gateway's MAC differs from the last
	// one seen. This is an ARP-spoof canary: the gateway's hardware address
	// essentially never legitimately changes on a home or office network.
	KindGatewayMACChanged = "gateway-mac-changed"
)

// Rule is one alert condition. The zero-value fields are all meaningful:
// no port filter, no severity threshold, no ignore list.
type Rule struct {
	// Name identifies the rule in alerts and in the suppressor. It should be
	// unique; evaluation does not enforce this, but a duplicate name makes
	// alerts from two rules indistinguishable.
	Name string `json:"name"`
	Kind string `json:"kind"`
	// Severity is the alert severity using scan's vocabulary ("", "info",
	// "warn", "high"). Empty picks the kind's default. For port-opened a
	// classified port's own risk severity always wins over this value.
	Severity string `json:"severity,omitempty"`
	// StableOnly (new-device only) restricts the rule to stable device keys,
	// so a phone re-randomizing its MAC — which produces a fresh ephemeral key
	// every time — does not alert on every visit.
	StableOnly bool `json:"stable_only,omitempty"`
	// Ports (port-opened only) restricts the rule to these port numbers.
	// Empty means every port.
	Ports []int `json:"ports,omitempty"`
	// MinSeverity (port-opened only) drops opened ports whose scan.risk
	// classification is below this level. Empty means no threshold.
	MinSeverity string `json:"min_severity,omitempty"`
	// Ignore silences the rule for these device keys or IPs, so one noisy
	// device does not force the whole rule off.
	Ignore []string `json:"ignore,omitempty"`
}

func rulesPath() string { return filepath.Join(config.Dir(), "rules.json") }

// Defaults is the rule set a fresh install gets. It is deliberately short:
// every default should be something a reasonable user would keep, because
// alert fatigue is the failure mode this package exists to prevent.
func Defaults() []Rule {
	return []Rule{
		// The ARP-spoof canary. Highest severity by default: a changed gateway
		// MAC means traffic may be flowing through an attacker's machine.
		{Name: "gateway-mac-changed", Kind: KindGatewayMACChanged, Severity: "high"},
		// Only stable keys: a genuinely new *device* is worth knowing about,
		// an ephemeral re-keying is not.
		{Name: "new-device", Kind: KindNewDevice, Severity: "info", StableOnly: true},
		// Ports scan considers risky; a port below "info" is unremarkable.
		{Name: "risky-port-opened", Kind: KindPortOpened, MinSeverity: "info"},
		{Name: "host-gone", Kind: KindHostGone, Severity: "info"},
	}
}

// Load reads rules.json, falling back to Defaults when the file is missing or
// unreadable. A fresh install must do something useful out of the box, and a
// corrupt file should degrade to sensible behaviour rather than to silence.
func Load() []Rule {
	b, err := os.ReadFile(rulesPath())
	if err != nil {
		return Defaults()
	}
	var rules []Rule
	if json.Unmarshal(b, &rules) != nil || len(rules) == 0 {
		return Defaults()
	}
	return rules
}

// Save writes rules.json atomically, creating the config directory as needed.
func Save(rules []Rule) error {
	if err := os.MkdirAll(config.Dir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(rulesPath(), b, 0o644)
}

// severityRank orders the severity vocabulary for sorting and threshold
// comparisons. Unknown strings rank as unremarkable.
func severityRank(s string) int {
	switch s {
	case "high":
		return 3
	case "warn":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// parseSeverity converts a rule's severity string to a scan.Severity.
func parseSeverity(s string) scan.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return scan.SevHigh
	case "warn":
		return scan.SevWarn
	case "info":
		return scan.SevInfo
	default:
		return scan.SevNone
	}
}

// severityOr returns the rule's severity, or the kind's fallback when unset.
func severityOr(ruleSeverity, fallback string) string {
	if ruleSeverity != "" {
		return ruleSeverity
	}
	return fallback
}

// ignored reports whether the rule's ignore list covers any of the given
// identifiers (device keys, IPs, or MACs depending on the rule kind).
func (r Rule) ignored(ids ...string) bool {
	for _, ig := range r.Ignore {
		for _, id := range ids {
			if ig != "" && ig == id {
				return true
			}
		}
	}
	return false
}
