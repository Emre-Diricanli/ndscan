package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Emre-Diricanli/ndscan/internal/report"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/tui"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/userenv"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
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

			// Choose runner (local or ssh)
			var runner scan.Runner
			if sshTarget != "" {
				runner = scan.NewRunner(sshTarget)
			} else {
				runner = scan.NewLocalRunner()
			}
			where := "locally"
			if sshTarget != "" {
				where = "via " + sshTarget
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()

			cfg := scan.Config{
				Preset:         preset,      // quick|default|udp|deep
				Ports:          ports,       // "22,80,443" or "1-1024"
				UseSYN:         rootScan,    // -sS (root) vs -sT
				Concurrency:    concurrency, // per-host workers
				HostTimeout:    time.Duration(hostTimeoutSec) * time.Second,
				DisableVendors: !(showMac && showVendors),
				NeedMAC:        showMac,
				BatchSize:      16,
			}

			// 1) host discovery first (runs where runner points)
			sp := ui.StartSpinner(fmt.Sprintf("Discovering hosts on %s (%s)…", strings.Join(targets, ", "), where))
			nmapMACWorthwhile := sshTarget != "" || scan.IsRoot()
			var live []string
			var discoveredMACs map[string]string
			var err error
			switch {
			case fastDiscover && scan.NativeDiscoverySupported(runner):
				// Native ARP + TCP sweep: no nmap, no root, ~20x faster on a LAN.
				live, discoveredMACs, err = scan.NativeDiscovery(ctx, targets, runner, nil)
			case showMac && nmapMACWorthwhile:
				live, discoveredMACs, err = scan.HostDiscoveryWithMACs(ctx, targets, runner)
			default:
				live, err = scan.HostDiscovery(ctx, targets, runner)
			}
			if err != nil {
				sp.Fail("Host discovery failed")
				return err
			}
			// ARP-cache fallback: find neighbors + MACs unprivileged nmap misses.
			arpMap := scan.ARPCache(ctx, runner)
			live = scan.MergeARPHosts(live, targets, arpMap)
			if len(live) == 0 {
				sp.Fail("No live hosts found.")
				return nil
			}
			sp.Success(fmt.Sprintf("Found %d live host(s)", len(live)))

			// 1b) optional: collect MACs. The ARP cache covers every L2
			// neighbor for free; only run the extra nmap -sn MAC sweep when it
			// can do better (root locally, or over SSH where we can't tell).
			var macMap map[string]string
			if showMac {
				sp = ui.StartSpinner("Collecting MAC addresses…")
				macMap = map[string]string{}
				if nmapMACWorthwhile {
					for ip, mac := range discoveredMACs {
						macMap[ip] = mac
					}
				}
				for ip, mac := range arpMap {
					if _, ok := macMap[ip]; !ok {
						macMap[ip] = mac
					}
				}
				sp.Success(fmt.Sprintf("Collected %d MAC address(es)", len(macMap)))
			}

			// 2) parallel per-host scans (remote or local depending on runner).
			// --discover skips the port scan entirely for a fast "who's up" view.
			var results []scan.HostResult
			if discoverOnly {
				ui.Infof("Discover-only mode: skipping port scan")
				results = scan.HostsUpResults(live)
			} else {
				sp = ui.StartSpinner(fmt.Sprintf("Scanning ports on %d host(s) (preset: %s)… 0/%d", len(live), preset, len(live)))
				cfg.Progress = func(done, total int) {
					sp.Update(fmt.Sprintf("Scanning ports on %d host(s) (preset: %s)… %d/%d", total, preset, done, total))
				}
				var err error
				if fastDiscover && scan.NativePortScanViable(cfg, runner) {
					// --fast means fast end-to-end: native connect scanning for
					// ports too, not just discovery.
					results = scan.NativePortScan(ctx, live, cfg, func(done, total int) {
						sp.Update(fmt.Sprintf("Scanning ports on %d host(s) (native)… %d/%d", total, done, total))
					})
				} else {
					results, err = scan.ScanHosts(ctx, live, cfg, runner)
				}
				if err != nil {
					sp.Fail("Port scan failed")
					return err
				}
				sp.Success("Port scan complete")
				if failed := countFailed(results); failed > 0 {
					ui.Warnf("%d host(s) failed to scan (first error: %v)", failed, firstError(results))
				}
				if fallback := countFallback(results); fallback > 0 {
					ui.Warnf("SYN unavailable for %d host(s); used TCP connect fallback", fallback)
				}
			}

			// 3) vendor DB (only if needed)
			var oui vendor.DB
			if showMac && showVendors {
				oui = vendor.LoadDefault()
			}

			// 4) output
			// --report and --json are independent: passing both writes both.
			// (The report branch used to return early, silently dropping the
			// JSON file the user asked for.)
			if reportOut != "" {
				rows := ui.BuildRows(results, oui, showMac, showVendors, macMap)
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
				if err := ui.WriteJSONWithMACMap(results, oui, jsonOut, showMac, showVendors, macMap); err != nil {
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
				ui.PrintTreeWithMACMap(results, oui, showMac, showVendors, macMap)
			default:
				ui.PrintTableWithMACMap(results, oui, showMac, showVendors, macMap)
			}
			hostsUp, openPorts := ui.Summarize(results)
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

	root.AddCommand(scanCmd)
	root.AddCommand(tuiCmd)

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

func countFailed(results []scan.HostResult) int {
	n := 0
	for _, r := range results {
		if r.Err != nil {
			if len(r.Targets) > 0 {
				n += len(r.Targets)
			} else {
				n++
			}
		}
	}
	return n
}

func countFallback(results []scan.HostResult) int {
	n := 0
	for _, r := range results {
		if r.Fallback {
			n += max(1, len(r.Targets))
		}
	}
	return n
}

func firstError(results []scan.HostResult) error {
	for _, r := range results {
		if r.Err != nil {
			return r.Err
		}
	}
	return nil
}

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
