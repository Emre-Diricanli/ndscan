package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/device"
	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/timeline"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// Exit codes for --exit-code, documented in the command's Long help. "Changed"
// must be distinct from a real failure: main exits 1 for any returned error,
// so 1 is already spoken for and 2 means "the network changed".
const (
	diffExitUnchanged = 0
	diffExitChanged   = 2
)

// newDiffCmd builds the `ndscan diff` subcommand. It reads recorded state
// only — history, the timeline, and device records — and never probes the
// network, which is what makes it safe to schedule from cron.
func newDiffCmd() *cobra.Command {
	var (
		preset   string
		ports    string
		fast     bool
		since    string
		exitCode bool
		jsonOut  bool
	)
	cmd := &cobra.Command{
		Use:   "diff [CIDR/IP ...]",
		Short: "Show what changed between recorded scans — reads recorded state only, never scans",
		Long: `Show what changed on the network using only ndscan's recorded state: scan
history and the timeline. This command NEVER scans — it sends no traffic,
needs no privileges, and is safe to run from cron.

History is keyed by the exact scan signature (targets, ports, preset, fast),
so --preset, --ports and --fast must match the scan you want to compare
against, exactly as passed to 'ndscan scan' (the defaults match a plain
'ndscan scan <targets>'). A diff against the wrong key is meaningless: with
different flags there is no recorded baseline and nothing to say. Scans run
from the web UI file their history under ports "preset:<name>" — diff against
those with e.g. -P quick -p preset:quick.

With no targets, the first scannable local network is used, the same
suggestion the web UI offers.

By default the output is the change set recorded by the most recent scan that
saw a difference. --since widens the window to every recorded event in that
interval — the right mode for cron/CI: scan on a schedule, then check
'ndscan diff --since 25h --exit-code' between runs.

Exit codes with --exit-code:
  0  no changes recorded
  2  changes recorded
  1  an actual error (bad flags, unreadable state)`,
		Example: `  ndscan diff 192.168.1.0/24
  ndscan diff 192.168.1.0/24 --fast
  ndscan diff --since 24h --exit-code
  ndscan diff 192.168.1.0/24 --json`,
		Args: cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Reject bad values before reading any state, so a typo can't
			// quietly diff against the wrong history key.
			if err := validatePreset(preset); err != nil {
				return err
			}
			if since != "" {
				if _, err := time.ParseDuration(since); err != nil {
					return fmt.Errorf("invalid --since %q: %w", since, err)
				}
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			o := diffOptions{
				targets:  args,
				preset:   preset,
				ports:    ports,
				fast:     fast,
				exitCode: exitCode,
				json:     jsonOut,
			}
			if since != "" {
				d, _ := time.ParseDuration(since) // validated in PreRunE
				o.since, o.sinceSet = d, true
			}
			code, err := runDiff(cmd.OutOrStdout(), o)
			if err != nil {
				return err
			}
			// os.Exit rather than a returned error: main maps every error to
			// exit 1, and 1 must stay reserved for real failures so scripts
			// can tell them apart from "the network changed" (2).
			if o.exitCode && code != diffExitUnchanged {
				os.Exit(code)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&preset, "preset", "P", "quick", "quick|smart|default|udp|deep — part of the history key, must match the recorded scan")
	cmd.Flags().StringVarP(&ports, "ports", "p", "", "ports the recorded scan used (e.g., 1-1024 or 22,80,443) — part of the history key")
	cmd.Flags().BoolVar(&fast, "fast", false, "diff against a native ARP+TCP sweep (--fast scan) — part of the history key")
	cmd.Flags().StringVar(&since, "since", "", "show timeline events in this window (e.g. 24h) instead of the last scan's changes")
	cmd.Flags().BoolVar(&exitCode, "exit-code", false, "exit 2 when changes are recorded, 0 when not (errors still exit 1)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print machine-readable JSON to stdout")
	return cmd
}

// diffOptions carries the resolved flag set into runDiff so the logic is
// testable without a cobra command (and without os.Exit).
type diffOptions struct {
	targets  []string
	preset   string
	ports    string
	fast     bool
	since    time.Duration
	sinceSet bool
	exitCode bool
	json     bool
}

// diffOutput is the machine-readable form of a diff run, printed by --json.
type diffOutput struct {
	Targets []string `json:"targets"`
	Preset  string   `json:"preset"`
	Ports   string   `json:"ports,omitempty"`
	Fast    bool     `json:"fast"`
	// Mode is "last-scan" (the most recent scan that saw a difference) or
	// "since" (every event in a window).
	Mode       string `json:"mode"`
	Since      string `json:"since,omitempty"`
	RecordedAt string `json:"recorded_at,omitempty"`
	// Baseline reports whether a recorded scan exists for this exact
	// signature. Without one there is nothing to diff against.
	Baseline bool          `json:"baseline"`
	Changed  bool          `json:"changed"`
	Changes  []changeEntry `json:"changes"`
}

// changeEntry is one recorded change with the device label resolved.
type changeEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // host_seen | host_gone | port_opened | port_closed
	Device    string    `json:"device"`
	IP        string    `json:"ip"`
	Port      int       `json:"port,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
}

// runDiff renders the recorded changes for o to w and returns the exit code
// the run implies (diffExitUnchanged or diffExitChanged). The caller decides
// whether to act on it — only --exit-code turns it into a process exit.
func runDiff(w io.Writer, o diffOptions) (int, error) {
	targets := o.targets
	if len(targets) == 0 {
		t, err := defaultDiffTargets()
		if err != nil {
			return diffExitUnchanged, err
		}
		targets = t
		ui.Infof("no targets given — using local network %s", strings.Join(targets, ", "))
	}

	key := config.ScanKey{Targets: targets, Ports: o.ports, Preset: o.preset, Fast: o.fast}
	out := diffOutput{
		Targets:  targets,
		Preset:   o.preset,
		Ports:    o.ports,
		Fast:     o.fast,
		Baseline: config.LoadHistory(key) != nil,
		Changes:  []changeEntry{},
	}

	// Every read is scoped to this exact scan signature. Reading the log
	// unscoped is what made this command report one network's changes under
	// another network's name — it asked for "the most recent events" and got
	// whichever network happened to be scanned last.
	scope := key.Scope()

	var events []timeline.Event
	if o.sinceSet {
		out.Mode = "since"
		out.Since = o.since.String()
		ev, err := timeline.Select(timeline.Query{
			Scope: scope,
			Since: time.Now().Add(-o.since),
		})
		if err != nil {
			return diffExitUnchanged, err
		}
		events = ev
	} else {
		out.Mode = "last-scan"
		// Without a baseline for this exact signature there is nothing to
		// diff against; the friendly empty state beats an invented one.
		if out.Baseline {
			ev, _, err := timeline.LatestRun(scope)
			if err != nil {
				return diffExitUnchanged, err
			}
			events = ev
			if len(events) > 0 {
				out.RecordedAt = events[0].Timestamp.Local().Format("2006-01-02 15:04:05")
			}
		}
	}

	out.Changed = len(events) > 0
	out.Changes = changeEntries(events, device.Load())

	if err := printDiff(w, o, out); err != nil {
		return diffExitUnchanged, err
	}
	if out.Changed {
		return diffExitChanged, nil
	}
	return diffExitUnchanged, nil
}

// changeEntries resolves device labels and orders events for display.
func changeEntries(events []timeline.Event, devices map[string]device.Record) []changeEntry {
	out := make([]changeEntry, 0, len(events))
	for _, ev := range events {
		label := ev.IP
		if rec, ok := devices[ev.DeviceKey]; ok {
			// Label falls back to the opaque key when nothing is known; the
			// IP is more useful than that, so only a real label wins.
			if l := rec.Label(); l != "" && l != rec.Key {
				label = l
			}
		}
		out = append(out, changeEntry{
			Timestamp: ev.Timestamp, Type: string(ev.Type), Device: label,
			IP: ev.IP, Port: ev.Port, Protocol: ev.Protocol,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		if a.IP != b.IP {
			return ui.IPLess(a.IP, b.IP)
		}
		return a.Port < b.Port
	})
	return out
}

// printDiff renders the result: JSON when asked, otherwise a short human
// summary. Every empty state is stated explicitly — a blank screen in cron
// output reads as a bug, not as "nothing happened".
func printDiff(w io.Writer, o diffOptions, out diffOutput) error {
	if o.json {
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	}
	targets := strings.Join(out.Targets, " ")
	switch {
	case !out.Baseline && out.Mode == "last-scan":
		fmt.Fprintf(w, "no previous scan recorded for %s — run a scan first:\n  ndscan scan %s\n", targets, targets)
	case !out.Changed && out.Mode == "since":
		fmt.Fprintf(w, "no changes recorded in the last %s\n", out.Since)
	case !out.Changed:
		fmt.Fprintf(w, "no changes recorded for %s\n", targets)
	default:
		if out.Mode == "since" {
			fmt.Fprintf(w, "Changes in the last %s (%d):\n", out.Since, len(out.Changes))
		} else {
			fmt.Fprintf(w, "Changes recorded by the last scan that saw a difference (%s):\n", out.RecordedAt)
		}
		printChangeTable(w, out.Mode == "since", out.Changes)
	}
	return nil
}

// printChangeTable renders the change set in the same rounded-table style the
// scan views use.
func printChangeTable(w io.Writer, showTime bool, changes []changeEntry) {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(table.StyleRounded)
	t.Style().Format.Header = text.FormatDefault
	t.Style().Color.Header = cliTitle
	if showTime {
		t.AppendHeader(table.Row{"Time", "Device", "IP", "Change", "Details"})
	} else {
		t.AppendHeader(table.Row{"Device", "IP", "Change", "Details"})
	}
	for _, c := range changes {
		change, details := describeChange(c)
		row := table.Row{}
		if showTime {
			row = append(row, c.Timestamp.Local().Format("01-02 15:04:05"))
		}
		row = append(row, cliBold.Sprint(c.Device), c.IP, change, details)
		t.AppendRow(row)
	}
	t.Render()
}

// describeChange words one event for the table.
func describeChange(c changeEntry) (change, details string) {
	port := ""
	if c.Port != 0 {
		port = fmt.Sprintf("%d", c.Port)
		if c.Protocol != "" {
			port += "/" + c.Protocol
		}
	}
	switch c.Type {
	case string(timeline.EventHostSeen):
		return cliOK.Sprint("+ appeared"), ""
	case string(timeline.EventHostGone):
		return cliErr.Sprint("- left"), ""
	case string(timeline.EventPortOpened):
		return cliOK.Sprint("+ port opened"), port
	case string(timeline.EventPortClosed):
		return cliErr.Sprint("- port closed"), port
	}
	return c.Type, port
}

// defaultDiffTargets picks the first scannable local network when the user
// gave no targets. The interface filter mirrors web.suggestedNetworks —
// tunnel and link-local interfaces (utun*, awdl*, …) have no neighbours worth
// diffing — and both sit on netinfo.Locals, which is passive: picking a
// suggestion must not probe the network either.
func defaultDiffTargets() ([]string, error) {
	for _, n := range netinfo.Locals() {
		if !scannableIface(n.Interface) {
			continue
		}
		// A /31 or narrower holds no other hosts; typical of VPN links.
		if p, err := netip.ParsePrefix(n.CIDR); err != nil || p.Bits() >= 31 {
			continue
		}
		return []string{n.CIDR}, nil
	}
	return nil, fmt.Errorf("no targets given and no local network could be suggested — pass targets explicitly, e.g. ndscan diff 192.168.1.0/24")
}

// scannableIface reports whether an interface name denotes a real network
// this machine shares with other hosts. Mirrors web.scannableInterface.
func scannableIface(name string) bool {
	for _, prefix := range []string{"utun", "awdl", "llw", "bridge", "gif", "stf", "ap"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}
