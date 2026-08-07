package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"

	"github.com/Emre-Diricanli/ndscan/internal/engine"
	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/report"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/tui"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/update"
	"github.com/Emre-Diricanli/ndscan/internal/userenv"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
	"github.com/Emre-Diricanli/ndscan/internal/web"
)

// version is the app version, overridable at build time via
// -ldflags "-X main.version=v1.2.3".
var version = "0.1.0"

// normalizeArgs turns "-tb"/"-tr" into "--tb"/"--tr" so Cobra can parse them as bool flags.
func normalizeArgs() {
	if len(os.Args) < 2 {
		return
	}
	out := make([]string, 0, len(os.Args))
	out = append(out, os.Args[0])
	for _, a := range os.Args[1:] {
		switch a {
		case "-tb":
			out = append(out, "--tb")
			continue
		case "-tr":
			out = append(out, "--tr")
			continue
		default:
			out = append(out, a)
		}
	}
	os.Args = out
}

func main() {
	// Only the `scan` subcommand needs elevation. --version, --help, and the
	// interactive TUI (bare `ndscan` or `ndscan tui`) must run unprivileged —
	// forcing sudo on those breaks the unprivileged-by-default design and makes
	// the tool unusable without a password.
	if wantsPrivilegedScan(os.Args[1:]) {
		if elevated, err := ensureRoot(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		} else if elevated {
			return
		}
	}
	normalizeArgs()

	var (
		preset         string
		ports          string
		jsonOut        string
		reportOut      string
		noOpen         bool
		discoverOnly   bool
		fastDiscover   bool
		mdns           bool
		tlsID          bool
		showMac        bool
		showVendors    bool
		rootScan       bool
		concurrency    int
		hostTimeoutSec int
		view           string
		flagTB         bool // table alias
		flagTR         bool // tree alias
	)

	root := &cobra.Command{
		Use:     "ndscan",
		Short:   "ndscan — fast, modular network scan CLI/TUI (local or over SSH)",
		Version: version,
		// Offer a self-update before any real work — importantly before the
		// TUI alt-screen starts. Silent and fast when up to date, offline, or
		// non-interactive.
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			update.MaybeUpdate(context.Background(), update.Options{
				In:          os.Stdin,
				Out:         os.Stderr,
				Current:     version,
				Interactive: ui.Interactive,
				Exec:        update.Reexec,
			})
		},
		// Bare `ndscan` launches the interactive TUI.
		RunE: func(cmd *cobra.Command, args []string) error {
			return tui.Run(version)
		},
	}

	tuiCmd := &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive terminal UI",
		RunE: func(cmd *cobra.Command, args []string) error {
			return tui.Run(version)
		},
	}

	scanCmd := &cobra.Command{
		Use:   "scan [user@host] [CIDR/IP ...]",
		Short: "Discover live hosts then scan open ports (locally or via SSH jump host)",
		Long: `If the first argument looks like "user@host", ndscan will run nmap on that remote host over SSH.
Example:
  ndscan scan emre@203.0.113.10 192.168.0.0/24 -tb
Otherwise, nmap runs locally.`,
		Args: cobra.MinimumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// resolve view precedence: explicit tags override --view
			if flagTB && flagTR {
				return fmt.Errorf("choose one: -tb (table) OR -tr (tree), not both")
			}
			if flagTB {
				view = "table"
			}
			if flagTR {
				view = "tree"
			}
			// Reject bad values before doing any work, so a typo can't quietly
			// run a different scan than the one requested.
			if err := validatePreset(preset); err != nil {
				return err
			}
			if err := validateView(view); err != nil {
				return err
			}
			if err := validatePositive("concurrency", concurrency); err != nil {
				return err
			}
			if err := validatePositive("host-timeout", hostTimeoutSec); err != nil {
				return err
			}
			if reportOut != "" {
				if _, err := reportFormat(reportOut); err != nil {
					return err
				}
			}
			// guard vendor flag when mac is off
			if showVendors && !showMac {
				ui.Warnf("--show-vendors requires --show-mac. Vendors will be skipped.")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, argv []string) error {
			// Detect SSH target (first arg contains '@' and is not a CIDR/IP)
			var sshTarget string
			targets := argv
			if looksLikeSSHTarget(argv[0]) {
				sshTarget = argv[0]
				if len(argv) == 1 {
					return fmt.Errorf("no scan targets provided after SSH target")
				}
				targets = argv[1:]
			}

			ui.Banner(version)
			start := time.Now()

			where := "locally"
			if sshTarget != "" {
				where = "via " + sshTarget
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()

			// Reject a malformed port spec before any probing happens. Left to
			// the scanners it would surface as an empty result table, which
			// reads as "nothing was open" rather than "we never looked".
			if err := scan.ValidatePorts(ports); err != nil {
				return err
			}

			plan := engine.Plan{
				SSHTarget: sshTarget, Targets: targets, Preset: preset, Ports: ports,
				ShowMAC: showMac, ShowVendors: showVendors, RootScan: rootScan,
				Concurrency: concurrency, HostTimeout: time.Duration(hostTimeoutSec) * time.Second,
				Fast: fastDiscover, DiscoverOnly: discoverOnly, Hostnames: true,
				Multicast: mdns, IdentifyTLS: tlsID,
			}
			sp := ui.StartSpinner(fmt.Sprintf("Discovering hosts on %s (%s)…", strings.Join(targets, ", "), where))
			var progressMu sync.Mutex
			liveCount := 0
			scanStarted := false
			emit := func(ev engine.Event) {
				progressMu.Lock()
				defer progressMu.Unlock()
				if ev.Kind == engine.EventRows && liveCount == 0 {
					liveCount = len(ev.Rows)
				}
				if ev.Kind == engine.EventWarning {
					ui.Warnf("%s", ev.Warning)
					return
				}
				if ev.Kind != engine.EventPhase || ev.Phase != engine.PhaseScan {
					return
				}
				liveCount = ev.Total
				if showMac {
					// The engine owns MAC collection, so its count is available only
					// in the terminal Outcome. Preserve message ordering after Run.
					return
				}
				if !scanStarted {
					sp.Success(fmt.Sprintf("Found %d live host(s)", ev.Total))
					sp = ui.StartSpinner(fmt.Sprintf("Scanning ports on %d host(s) (preset: %s)… 0/%d", ev.Total, preset, ev.Total))
					scanStarted = true
				}
				// Which scanner is running is the engine's decision, reported
				// on the event rather than recomputed here — a second copy of
				// that rule would drift the first time the engine's changed.
				if ev.Native {
					sp.Update(fmt.Sprintf("Scanning ports on %d host(s) (native)… %d/%d", ev.Total, ev.Done, ev.Total))
				} else {
					sp.Update(fmt.Sprintf("Scanning ports on %d host(s) (preset: %s)… %d/%d", ev.Total, preset, ev.Done, ev.Total))
				}
			}
			eng := engine.New()
			scanStart := time.Now()
			outcome := eng.Run(ctx, plan, emit)
			if outcome.Status == engine.StatusFailed {
				sp.Fail("Host discovery failed")
				return outcome.Err
			}
			if outcome.Status == engine.StatusCancelled {
				sp.Fail("Port scan failed")
				return ctx.Err()
			}
			if outcome.FirstErr != nil && outcome.Failed == 0 {
				sp.Fail("Port scan failed")
				return outcome.FirstErr
			}
			// Record the run so `ndscan diff` has a baseline. The CLI is
			// otherwise stateless, but a diff command that tells the user to
			// run a scan, from a scan that records nothing, is advice that
			// cannot be followed. Persist rejects untrustworthy runs itself.
			// Vendors only matter when the user asked to see them; loading the
			// ~39k-prefix OUI table otherwise is pure cost.
			var oui vendor.DB
			if showMac && showVendors {
				oui = vendor.LoadDefault()
			}
			rec := eng.PersistWithGateway(outcome, plan, scanStart, oui, netinfo.DefaultGateway().IP)
			for _, w := range rec.Warnings {
				ui.Warnf("%s", w)
			}
			for _, a := range rec.Alerts {
				ui.Warnf("%s: %s", a.Title, a.Body)
			}

			if len(outcome.Rows) == 0 {
				sp.Fail("No live hosts found.")
				return nil
			}
			if liveCount == 0 {
				liveCount = len(outcome.Rows)
			}
			if showMac {
				sp.Success(fmt.Sprintf("Found %d live host(s)", liveCount))
				sp = ui.StartSpinner("Collecting MAC addresses…")
				sp.Success(fmt.Sprintf("Collected %d MAC address(es)", len(outcome.MACs)))
			}
			if discoverOnly {
				if !showMac {
					sp.Success(fmt.Sprintf("Found %d live host(s)", liveCount))
				}
				ui.Infof("Discover-only mode: skipping port scan")
			} else {
				if showMac {
					sp = ui.StartSpinner(fmt.Sprintf("Scanning ports on %d host(s) (preset: %s)… %d/%d", liveCount, preset, liveCount, liveCount))
				}
				sp.Success("Port scan complete")
				if outcome.Failed > 0 {
					ui.Warnf("%d host(s) failed to scan (first error: %v)", outcome.Failed, outcome.FirstErr)
				}
				if outcome.Fallbacks > 0 {
					ui.Warnf("SYN unavailable for %d host(s); used TCP connect fallback", outcome.Fallbacks)
				}
			}
			rows := outcome.Rows

			// 4) output
			// --report and --json are independent: passing both writes both.
			// (The report branch used to return early, silently dropping the
			// JSON file the user asked for.)
			if reportOut != "" {
				rep := report.Report{
					Targets:   strings.Join(targets, ", "),
					Preset:    preset,
					Generated: start.Format("2006-01-02 15:04:05"),
					Rows:      rows,
				}
				format, err := reportFormat(reportOut) // already validated in PreRunE
				if err != nil {
					return err
				}
				isHTML := format == "html"
				content := rep.Markdown()
				if isHTML {
					content = rep.HTML()
				}
				if err := os.WriteFile(reportOut, []byte(content), 0o644); err != nil {
					return err
				}
				if err := userenv.Chown(reportOut); err != nil {
					return err
				}
				ui.Infof("Wrote report to %s", reportOut)
				// Open HTML reports in the browser unless suppressed.
				if isHTML && !noOpen && report.CanOpen() {
					if err := report.Open(reportOut); err == nil {
						ui.Infof("Opened %s in your browser", reportOut)
					}
				}
			}
			if jsonOut != "" {
				b, err := json.MarshalIndent(rows, "", "  ")
				if err != nil {
					return err
				}
				if err := os.WriteFile(jsonOut, b, 0o644); err != nil {
					return err
				}
				if err := userenv.Chown(jsonOut); err != nil {
					return err
				}
				ui.Infof("Wrote JSON results to %s", jsonOut)
			}
			// Writing files is the requested output; don't also dump a table.
			if reportOut != "" || jsonOut != "" {
				return nil
			}
			fmt.Println()
			switch view {
			case "tree":
				ui.PrintTreeRows(rows, showMac, showVendors)
			default:
				ui.PrintTableRows(rows, showMac)
			}
			hostsUp, openPorts := ui.SummarizeRows(rows)
			ui.PrintSummary(hostsUp, openPorts, time.Since(start))
			return nil
		},
	}

	// standard flags
	scanCmd.Flags().StringVarP(&preset, "preset", "P", "quick", "quick|smart|default|udp|deep")
	scanCmd.Flags().StringVarP(&ports, "ports", "p", "", "ports (e.g., 1-1024 or 22,80,443)")
	scanCmd.Flags().StringVarP(&jsonOut, "json", "j", "", "write JSON output to file")
	scanCmd.Flags().StringVar(&reportOut, "report", "", "write a Markdown/HTML report (format inferred from .md/.html)")
	scanCmd.Flags().BoolVar(&noOpen, "no-open", false, "don't open HTML reports in the browser")
	scanCmd.Flags().BoolVar(&tlsID, "tls", false, "read certificates on open TLS ports to identify the product behind a host")
	scanCmd.Flags().BoolVar(&mdns, "mdns", false, "ask the network for its own names via mDNS/SSDP (adds a few seconds)")
	scanCmd.Flags().BoolVar(&fastDiscover, "fast", false, "native ARP+TCP host discovery (no nmap, no root) — much faster on a LAN")
	scanCmd.Flags().BoolVar(&discoverOnly, "discover", false, "only list live hosts (skip the port scan) — fastest")
	scanCmd.Flags().BoolVar(&showMac, "show-mac", false, "include MAC addresses (same L2 only)")
	scanCmd.Flags().BoolVar(&showVendors, "show-vendors", false, "include vendor names (requires --show-mac)")
	scanCmd.Flags().BoolVar(&rootScan, "root-scan", false, "use SYN scan (-sS), requires root on the machine running nmap")
	scanCmd.Flags().IntVar(&concurrency, "concurrency", 64, "max parallel host scans")
	scanCmd.Flags().IntVar(&hostTimeoutSec, "host-timeout", 20, "per-host timeout seconds (nmap)")
	scanCmd.Flags().StringVar(&view, "view", "table", "output view: table | tree")

	// your requested tags
	scanCmd.Flags().BoolVar(&flagTB, "tb", false, "alias: same as --view table (use as -tb)")
	scanCmd.Flags().BoolVar(&flagTR, "tr", false, "alias: same as --view tree (use as -tr)")

	var (
		webAddr   string
		webNoOpen bool
	)
	webCmd := &cobra.Command{
		Use:   "web",
		Short: "Serve the browser interface (localhost only by default)",
		Long: `Starts a local web server exposing the network map and scan controls.

It binds to 127.0.0.1 by default. ndscan is a network scanner, so a reachable
web interface is a remotely-controllable scanner — only bind it to a wider
address on a network you trust, and never on an untrusted one.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()

			if !strings.HasPrefix(webAddr, "127.0.0.1:") && !strings.HasPrefix(webAddr, "localhost:") {
				ui.Warnf("binding to %s — the web UI can control scans from any host that can reach it", webAddr)
			}
			url := "http://" + webAddr
			ui.Infof("ndscan web listening on %s", url)
			if !webNoOpen && report.CanOpen() {
				_ = report.Open(url)
			}
			return web.NewServer(version).ListenAndServe(ctx, webAddr)
		},
	}
	webCmd.Flags().StringVar(&webAddr, "addr", "127.0.0.1:8080", "address to bind (loopback by default)")
	webCmd.Flags().BoolVar(&webNoOpen, "no-open", false, "don't open a browser on start")

	root.AddCommand(scanCmd)
	root.AddCommand(tuiCmd)
	root.AddCommand(webCmd)
	root.AddCommand(newDiffCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// wantsPrivilegedScan reports whether this invocation is a `scan` subcommand
// that should relaunch as root. It scans argv directly (before Cobra parses) so
// the decision happens before any elevation. Help and version requests never
// qualify, and neither does the interactive TUI (bare `ndscan` or `ndscan
// tui`), which is designed to run unprivileged.
func wantsPrivilegedScan(args []string) bool {
	for _, a := range args {
		switch a {
		case "-h", "--help", "-v", "--version", "help":
			return false
		case "--fast":
			// Native ARP+TCP discovery is unprivileged by design. Elevating for
			// it would defeat the point and force a password the scan does not
			// need.
			return false
		}
	}
	// The first non-flag token is the subcommand. Only `scan` is elevated.
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a == "scan"
	}
	// No subcommand at all → bare `ndscan` launches the TUI, unprivileged.
	return false
}

// ensureRoot relaunches ndscan through sudo before any CLI or TUI state is
// created. The original home is passed explicitly so root-owned execution
// still reads and writes the invoking user's ndscan config and exports.
func ensureRoot() (bool, error) {
	if scan.IsRoot() {
		return false, nil
	}
	if !scan.SudoAvailable() {
		return false, fmt.Errorf("ndscan scans require root, but sudo was not found on PATH.\n"+
			"  Re-run as root, e.g.:  su -c 'ndscan %s'", strings.Join(os.Args[1:], " "))
	}
	exe, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("locate ndscan executable: %w", err)
	}
	home, _ := os.UserHomeDir()
	configDir, _ := os.UserConfigDir()
	nmapPath, _ := exec.LookPath("nmap")
	args := []string{"env",
		"NDSCAN_USER_HOME=" + home,
		"NDSCAN_USER_CONFIG_DIR=" + configDir,
		fmt.Sprintf("NDSCAN_USER_UID=%d", os.Getuid()),
		fmt.Sprintf("NDSCAN_USER_GID=%d", os.Getgid()),
		"NDSCAN_NMAP_PATH=" + nmapPath,
		"NDSCAN_ELEVATED=1",
		exe,
	}
	args = append(args, os.Args[1:]...)
	cmd := exec.Command("sudo", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		// Distinguish "couldn't authenticate" from "the scan itself failed".
		// Without this the user sees a bare exit status and a pile of per-host
		// failures, with no hint that the real problem was privileges.
		return false, fmt.Errorf("ndscan scans require root, and elevating via sudo failed.\n"+
			"  Re-run it yourself so sudo can prompt:  sudo ndscan %s\n"+
			"  (underlying error: %w)", strings.Join(os.Args[1:], " "), err)
	}
	return true, nil
}

var (
	cliAccent = text.Colors{text.FgHiCyan}
	cliBold   = text.Colors{text.Bold}
	cliDim    = text.Colors{text.FgHiBlack}
	cliOK     = text.Colors{text.FgHiGreen}
	cliWarn   = text.Colors{text.FgHiYellow}
	cliErr    = text.Colors{text.FgHiRed}
	cliTitle  = text.Colors{text.FgHiCyan, text.Bold}
)

// validPresets and validViews are the accepted values for --preset and --view.
// Unknown values used to fall through to a default, silently producing a scan
// the user didn't ask for, so both are validated up front.
var (
	validPresets = []string{"quick", "smart", "default", "udp", "deep"}
	validViews   = []string{"table", "tree"}
)

func validatePreset(p string) error {
	for _, v := range validPresets {
		if p == v {
			return nil
		}
	}
	return fmt.Errorf("invalid --preset %q (choose one of: %s)", p, strings.Join(validPresets, ", "))
}

func validateView(v string) error {
	for _, ok := range validViews {
		if v == ok {
			return nil
		}
	}
	return fmt.Errorf("invalid --view %q (choose one of: %s)", v, strings.Join(validViews, ", "))
}

// validatePositive rejects zero and negative values for flags where they'd
// silently disable a safety limit (a non-positive host timeout means "no
// timeout" to nmap) or be clamped without telling the user.
func validatePositive(flag string, n int) error {
	if n < 1 {
		return fmt.Errorf("--%s must be at least 1 (got %d)", flag, n)
	}
	return nil
}

// reportFormat resolves the report format from the output path's extension.
// Anything other than .md/.html is an error: the old behavior wrote Markdown
// into, say, "report.json", which looked like it had honored the name.
func reportFormat(path string) (string, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".html":
		return "html", nil
	case ".md":
		return "md", nil
	default:
		return "", fmt.Errorf("cannot infer report format from %q: use a .md or .html extension", path)
	}
}

// treat "user@host" as SSH target if it contains '@' and no '/' (CIDR)
func looksLikeSSHTarget(s string) bool {
	if !strings.Contains(s, "@") {
		return false
	}
	if strings.Contains(s, "/") {
		return false
	}
	return true
}
