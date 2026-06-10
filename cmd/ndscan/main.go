package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Emre-Diricanli/ndscan/internal/report"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/tui"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
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
	normalizeArgs()

	var (
		preset         string
		ports          string
		jsonOut        string
		reportOut      string
		noOpen         bool
		showMac        bool
		showVendors    bool
		rootScan       bool
		useSudo        bool
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

			// Elevate local scans when requested (or already root).
			if useSudo && sshTarget == "" && !scan.IsRoot() {
				if !scan.SudoAvailable() {
					return fmt.Errorf("--sudo requested but sudo not found on PATH")
				}
				if err := scan.PrimeSudo(); err != nil {
					return fmt.Errorf("sudo authentication failed: %w", err)
				}
			}

			// Choose runner (local or ssh)
			var runner scan.Runner
			if sshTarget != "" {
				runner = scan.NewRunner(sshTarget)
			} else {
				runner = scan.NewLocalRunner(useSudo && !scan.IsRoot())
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
			}

			// 1) host discovery first (runs where runner points)
			sp := ui.StartSpinner(fmt.Sprintf("Discovering hosts on %s (%s)…", strings.Join(targets, ", "), where))
			live, err := scan.HostDiscovery(ctx, targets, runner)
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

			// 1b) optional: collect MACs (nmap when privileged, plus ARP cache)
			var macMap map[string]string
			if showMac {
				sp = ui.StartSpinner("Collecting MAC addresses…")
				macMap = map[string]string{}
				if nmapMACs, _ := scan.DiscoverMACs(ctx, live, runner); nmapMACs != nil {
					for ip, mac := range nmapMACs {
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

			// 2) parallel per-host scans (remote or local depending on runner)
			sp = ui.StartSpinner(fmt.Sprintf("Scanning ports on %d host(s) (preset: %s)… 0/%d", len(live), preset, len(live)))
			cfg.Progress = func(done, total int) {
				sp.Update(fmt.Sprintf("Scanning ports on %d host(s) (preset: %s)… %d/%d", total, preset, done, total))
			}
			results, err := scan.ScanHosts(ctx, live, cfg, runner)
			if err != nil {
				sp.Fail("Port scan failed")
				return err
			}
			sp.Success("Port scan complete")
			if failed := countFailed(results); failed > 0 {
				ui.Warnf("%d host(s) failed to scan (first error: %v)", failed, firstError(results))
			}

			// 3) vendor DB (only if needed)
			var oui vendor.DB
			if showMac && showVendors {
				oui = vendor.LoadDefault()
			}

			// 4) output
			// Markdown/HTML report (inferred from the file extension).
			if reportOut != "" {
				rows := ui.BuildRows(results, oui, showMac, showVendors, macMap)
				rep := report.Report{
					Targets:   strings.Join(targets, ", "),
					Preset:    preset,
					Generated: start.Format("2006-01-02 15:04:05"),
					Rows:      rows,
				}
				isHTML := strings.HasSuffix(strings.ToLower(reportOut), ".html")
				content := rep.Markdown()
				if isHTML {
					content = rep.HTML()
				}
				if err := os.WriteFile(reportOut, []byte(content), 0o644); err != nil {
					return err
				}
				ui.Infof("Wrote report to %s", reportOut)
				// Open HTML reports in the browser unless suppressed.
				if isHTML && !noOpen && report.CanOpen() {
					if err := report.Open(reportOut); err == nil {
						ui.Infof("Opened %s in your browser", reportOut)
					}
				}
				return nil
			}
			if jsonOut != "" {
				if err := ui.WriteJSONWithMACMap(results, oui, jsonOut, showMac, showVendors, macMap); err != nil {
					return err
				}
				ui.Infof("Wrote JSON results to %s", jsonOut)
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
	scanCmd.Flags().StringVarP(&preset, "preset", "P", "quick", "quick|default|udp|deep")
	scanCmd.Flags().StringVarP(&ports, "ports", "p", "", "ports (e.g., 1-1024 or 22,80,443)")
	scanCmd.Flags().StringVarP(&jsonOut, "json", "j", "", "write JSON output to file")
	scanCmd.Flags().StringVar(&reportOut, "report", "", "write a Markdown/HTML report (format inferred from .md/.html)")
	scanCmd.Flags().BoolVar(&noOpen, "no-open", false, "don't open HTML reports in the browser")
	scanCmd.Flags().BoolVar(&showMac, "show-mac", false, "include MAC addresses (same L2 only)")
	scanCmd.Flags().BoolVar(&showVendors, "show-vendors", false, "include vendor names (requires --show-mac)")
	scanCmd.Flags().BoolVar(&rootScan, "root-scan", false, "use SYN scan (-sS), requires root on the machine running nmap")
	scanCmd.Flags().BoolVar(&useSudo, "sudo", false, "run local nmap via sudo for full ARP discovery, SYN scans, and MACs")
	scanCmd.Flags().IntVar(&concurrency, "concurrency", 32, "max parallel host scans")
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

func countFailed(results []scan.HostResult) int {
	n := 0
	for _, r := range results {
		if r.Err != nil {
			n++
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
