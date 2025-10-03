package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

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
		Use:   "ndscan",
		Short: "ndscan — fast, modular network scan CLI (local or over SSH)",
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
				fmt.Fprintln(os.Stderr, "Warning: --show-vendors requires --show-mac. Vendors will be skipped.")
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

			// Choose runner (local or ssh)
			runner := scan.NewRunner(sshTarget)

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
			live, err := scan.HostDiscovery(ctx, targets, runner)
			if err != nil {
				return err
			}
			if len(live) == 0 {
				fmt.Println("No live hosts found.")
				return nil
			}

			// 1b) optional: collect MACs with a separate ARP/ND discovery pass
			var macMap map[string]string
			if showMac {
				macMap, _ = scan.DiscoverMACs(ctx, live, runner) // best-effort; empty off-L2 or if perms missing
			}

			// 2) parallel per-host scans (remote or local depending on runner)
			results, err := scan.ScanHosts(ctx, live, cfg, runner)
			if err != nil {
				return err
			}

			// 3) vendor DB (only if needed)
			var oui vendor.DB
			if showMac && showVendors {
				oui = vendor.LoadDefault()
			}

			// 4) output
			if jsonOut != "" {
				return ui.WriteJSONWithMACMap(results, oui, jsonOut, showMac, showVendors, macMap)
			}
			switch view {
			case "tree":
				ui.PrintTreeWithMACMap(results, oui, showMac, showVendors, macMap)
			default:
				ui.PrintTableWithMACMap(results, oui, showMac, showVendors, macMap)
			}
			return nil
		},
	}

	// standard flags
	scanCmd.Flags().StringVarP(&preset, "preset", "P", "quick", "quick|default|udp|deep")
	scanCmd.Flags().StringVarP(&ports, "ports", "p", "", "ports (e.g., 1-1024 or 22,80,443)")
	scanCmd.Flags().StringVarP(&jsonOut, "json", "j", "", "write JSON output to file")
	scanCmd.Flags().BoolVar(&showMac, "show-mac", false, "include MAC addresses (same L2 only)")
	scanCmd.Flags().BoolVar(&showVendors, "show-vendors", false, "include vendor names (requires --show-mac)")
	scanCmd.Flags().BoolVar(&rootScan, "root-scan", false, "use SYN scan (-sS), requires root on the machine running nmap")
	scanCmd.Flags().IntVar(&concurrency, "concurrency", 32, "max parallel host scans")
	scanCmd.Flags().IntVar(&hostTimeoutSec, "host-timeout", 20, "per-host timeout seconds (nmap)")
	scanCmd.Flags().StringVar(&view, "view", "table", "output view: table | tree")

	// your requested tags
	scanCmd.Flags().BoolVar(&flagTB, "tb", false, "alias: same as --view table (use as -tb)")
	scanCmd.Flags().BoolVar(&flagTR, "tr", false, "alias: same as --view tree (use as -tr)")

	root.AddCommand(scanCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
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
