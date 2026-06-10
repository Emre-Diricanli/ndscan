package tui

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

// scanParams is the resolved configuration captured from the form.
type scanParams struct {
	sshTarget   string
	targets     []string
	preset      string
	ports       string
	showMac     bool
	showVendors bool
	rootScan    bool
	concurrency int
	hostTimeout time.Duration
}

// ----- messages streamed from the scan goroutine into the Bubble Tea loop -----

type phaseMsg struct {
	phase string // "discover" | "mac" | "scan"
	done  int
	total int
}

// hostRowMsg carries one host's parsed rows the moment its scan finishes.
type hostRowMsg struct {
	rows []ui.Row
}

type doneMsg struct {
	rows      []ui.Row
	failed    int
	elapsed   time.Duration
	cancelled bool
	diff      map[string]config.HostDiff
}

type errMsg struct{ err error }

// listen blocks on the event channel and forwards the next message into the
// Bubble Tea runtime. It is re-issued from Update until a terminal message
// (doneMsg / errMsg) arrives.
func listen(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

// nmapAvailable reports whether nmap can run for the given SSH target
// ("" = locally). Remote availability is left to the SSH side to report.
func nmapAvailable(sshTarget string) bool {
	if sshTarget != "" {
		return true
	}
	_, err := exec.LookPath("nmap")
	return err == nil
}

// runScan launches the scan in a background goroutine, returning the channel
// that progress and result messages are delivered on, plus a cancel func.
func runScan(p scanParams) (<-chan tea.Msg, context.CancelFunc) {
	ch := make(chan tea.Msg, 64)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)

	go func() {
		defer close(ch)
		defer cancel()
		start := time.Now()
		runner := scan.NewRunner(p.sshTarget)

		finish := func(rows []ui.Row, failed int, cancelled bool) {
			prev := config.LoadHistory(p.targets, p.ports, p.preset)
			cur := make([]config.HostSnapshot, 0, len(rows))
			for _, r := range rows {
				cur = append(cur, config.HostSnapshot{IP: r.IP, Host: r.Host, Ports: r.Ports})
			}
			var diff map[string]config.HostDiff
			if !cancelled { // don't diff or overwrite history with partial results
				diff = config.Diff(prev, cur)
				_ = config.SaveHistory(p.targets, p.ports, p.preset, cur)
			}
			ch <- doneMsg{
				rows:      rows,
				failed:    failed,
				elapsed:   time.Since(start),
				cancelled: cancelled,
				diff:      diff,
			}
		}

		ch <- phaseMsg{phase: "discover"}
		live, err := scan.HostDiscovery(ctx, p.targets, runner)
		if err != nil {
			if ctx.Err() != nil {
				finish(nil, 0, true)
				return
			}
			ch <- errMsg{err}
			return
		}
		if len(live) == 0 {
			finish(nil, 0, false)
			return
		}

		var macMap map[string]string
		if p.showMac {
			ch <- phaseMsg{phase: "mac"}
			macMap, _ = scan.DiscoverMACs(ctx, live, runner) // best-effort
		}

		var oui vendor.DB
		if p.showMac && p.showVendors {
			oui = vendor.LoadDefault()
		}

		// Stream each host's parsed rows as its scan completes.
		var mu sync.Mutex
		var streamed []ui.Row
		failed := 0
		cfg := scan.Config{
			Preset:         p.preset,
			Ports:          p.ports,
			UseSYN:         p.rootScan,
			Concurrency:    p.concurrency,
			HostTimeout:    p.hostTimeout,
			DisableVendors: !(p.showMac && p.showVendors),
			NeedMAC:        p.showMac,
			Progress: func(done, total int) {
				ch <- phaseMsg{phase: "scan", done: done, total: total}
			},
			OnResult: func(r scan.HostResult) {
				mu.Lock()
				defer mu.Unlock()
				if r.Err != nil {
					if ctx.Err() == nil {
						failed++
					}
					return
				}
				rows := ui.BuildRows([]scan.HostResult{r}, oui, p.showMac, p.showVendors, macMap)
				if len(rows) == 0 {
					return
				}
				streamed = append(streamed, rows...)
				ch <- hostRowMsg{rows: rows}
			},
		}
		ch <- phaseMsg{phase: "scan", done: 0, total: len(live)}

		_, err = scan.ScanHosts(ctx, live, cfg, runner)
		mu.Lock()
		rows := append([]ui.Row(nil), streamed...)
		nFailed := failed
		mu.Unlock()

		if ctx.Err() != nil {
			finish(rows, nFailed, true)
			return
		}
		if err != nil {
			ch <- errMsg{err}
			return
		}
		finish(rows, nFailed, false)
	}()

	return ch, cancel
}

// parseTargets splits a raw target string, peeling off a leading "user@host"
// SSH jump target if present.
func parseTargets(raw string) (sshTarget string, targets []string) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", nil
	}
	if strings.Contains(fields[0], "@") && !strings.Contains(fields[0], "/") {
		return fields[0], fields[1:]
	}
	return "", fields
}

// localCIDR guesses the primary local IPv4 network (e.g. "192.168.1.0/24")
// for prefilling the targets field. Returns "" if none found.
func localCIDR() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			ones, _ := ipn.Mask.Size()
			return ipn.IP.Mask(ipn.Mask).String() + "/" + strconv.Itoa(ones)
		}
	}
	return ""
}
