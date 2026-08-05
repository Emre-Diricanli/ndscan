package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Emre-Diricanli/ndscan/internal/report"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

// discoverState holds the focused single-host deep scan shown in the Discover
// overlay. It is independent of the main scan lifecycle.
type discoverState struct {
	ip       string
	scanning bool
	row      *ui.Row // result once the deep scan completes
	err      error
	elapsed  time.Duration
	cancel   context.CancelFunc
	notice   string // transient feedback (e.g. "opened in browser")
}

// discoverDoneMsg carries the result of a single-host deep scan.
type discoverDoneMsg struct {
	ip      string
	row     *ui.Row
	err     error
	elapsed time.Duration
}

// startDiscover opens the Discover overlay for the given IP and kicks off a
// deep (-A, all-ports) scan of just that host.
func (m *Model) startDiscover(ip string) tea.Cmd {
	if m.disco.cancel != nil {
		m.disco.cancel()
	}
	m.mode = modeDiscover
	m.disco = discoverState{ip: ip, scanning: true}
	return tea.Batch(m.spin.Tick, m.runDiscover(ip))
}

// runDiscover scans a single host deeply on its own goroutine + context.
func (m *Model) runDiscover(ip string) tea.Cmd {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	m.disco.cancel = cancel

	sshTarget := m.params.sshTarget

	return func() tea.Msg {
		defer cancel()
		start := time.Now()

		var runner scan.Runner
		if sshTarget != "" {
			runner = scan.NewRunner(sshTarget)
		} else {
			runner = scan.NewLocalRunner()
		}

		// "default" preset gives -A (service versions, OS, default scripts,
		// TLS certs, HTTP titles) without deep's all-65535-ports sweep, which
		// is impractical per-host — especially against hosts that SYN-ACK
		// every port. A 45s host budget keeps it responsive.
		cfg := scan.Config{
			Preset:      "default",
			Ports:       "1-1024,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017",
			UseSYN:      scan.IsRoot(),
			Concurrency: 1,
			HostTimeout: 45 * time.Second,
			NeedMAC:     true,
		}
		results, err := scan.ScanHosts(ctx, []string{ip}, cfg, runner)
		if err != nil {
			return discoverDoneMsg{ip: ip, err: err, elapsed: time.Since(start)}
		}

		// Resolve MAC from the ARP cache and vendor names for the panel.
		macMap := scan.ARPCache(ctx, runner)
		oui := vendor.LoadDefault()
		rows := ui.BuildRows(results, oui, true, true, macMap)
		var row *ui.Row
		if len(rows) > 0 {
			row = &rows[0]
		}
		return discoverDoneMsg{ip: ip, row: row, elapsed: time.Since(start)}
	}
}

// webURLs returns browser-openable URLs for any http/https ports on the host.
func (d discoverState) webURLs() []string {
	if d.row == nil {
		return nil
	}
	var urls []string
	for _, p := range d.row.PortDetails {
		scheme := ""
		switch {
		case p.TLS || p.Service == "https" || p.Port == 443:
			scheme = "https"
		case strings.HasPrefix(p.Service, "http") || p.Port == 80 || p.Port == 8080 || p.Port == 8000:
			scheme = "http"
		}
		if scheme != "" {
			urls = append(urls, fmt.Sprintf("%s://%s:%d", scheme, d.ip, p.Port))
		}
	}
	return urls
}

// discoverPanel renders the Discover overlay: a deep single-host scan with a
// richer layout than the static detail pane, plus inline actions.
func (m Model) discoverPanel() string {
	d := m.disco
	var b strings.Builder

	// Header
	b.WriteString(accentText.Bold(true).Render("⊙ Discover") +
		hintStyle.Render("  deep scan · ") + valueStyle.Bold(true).Render(d.ip) + "\n\n")

	if d.scanning {
		b.WriteString("  " + m.spin.View() + accentText.Render("deep scan: ports + service/version + OS…") + "\n")
		b.WriteString("\n  " + hintStyle.Render("this is thorough and can take ~30s · esc to cancel"))
		return discoverBox(b.String())
	}
	if d.err != nil {
		b.WriteString("  " + errStyle.Render("✖ scan failed: "+d.err.Error()) + "\n")
		b.WriteString("\n  " + hintStyle.Render("r rescan · esc back"))
		return discoverBox(b.String())
	}

	r := d.row
	if r == nil {
		// No parseable result — the scan timed out or was inconclusive.
		b.WriteString("  " + warnStyle.Render("scan timed out before finishing") + "\n")
		b.WriteString(hintStyle.Render("  (the host may be filtering probes or SYN-ACKing every port)") + "\n")
		b.WriteString("\n  " + hintStyle.Render("r rescan · esc back"))
		return discoverBox(b.String())
	}

	// Host facts block
	fact := func(k, v string) {
		if v == "" {
			return
		}
		b.WriteString("  " + labelStyle.Width(9).Render(k) + " " + valueStyle.Render(v) + "\n")
	}
	fact("Host", r.Host)
	fact("MAC", r.MAC)
	fact("Vendor", r.Vendor)
	if r.OS != "" {
		os := r.OS
		if r.OSAccuracy > 0 {
			os += hintStyle.Render(fmt.Sprintf("  (%d%%)", r.OSAccuracy))
		}
		b.WriteString("  " + labelStyle.Width(9).Render("OS") + " " + valueStyle.Render(os) + "\n")
	}
	fact("RTT", r.RTT)
	b.WriteString("  " + labelStyle.Width(9).Render("Scan") + " " +
		hintStyle.Render(fmt.Sprintf("completed in %s", d.elapsed.Round(time.Millisecond*100))) + "\n")

	// Ports / services. A host reporting hundreds of "open" ports is almost
	// certainly SYN-ACKing everything (a tarpit / firewall), not genuinely
	// running that many services — call it out instead of listing noise.
	const saturated = 100
	if len(r.PortDetails) >= saturated {
		b.WriteString("\n  " + warnStyle.Render(fmt.Sprintf("⚠ %d ports report open", len(r.PortDetails))) + "\n")
		b.WriteString("  " + hintStyle.Render("this host SYN-ACKs every port (a firewall/tarpit) —") + "\n")
		b.WriteString("  " + hintStyle.Render("the \"open\" ports aren't real services. Try enabling SYN scan.") + "\n")
		b.WriteString("\n  " + hintStyle.Render("r rescan · esc back"))
		return discoverBox(b.String())
	}
	b.WriteString("\n  " + labelFocusedStyle.Render(fmt.Sprintf("Open ports (%d)", len(r.PortDetails))) + "\n")
	if len(r.PortDetails) == 0 {
		b.WriteString("  " + hintStyle.Render("none open") + "\n")
	}
	for _, p := range r.PortDetails {
		head := accentText.Render(fmt.Sprintf("%d/%s", p.Port, p.Proto))
		if p.Service != "" {
			head += "  " + valueStyle.Render(p.Service)
		}
		if p.TLS {
			head += "  " + okStyle.Render("tls")
		}
		if vl := p.VersionLabel(); vl != "" {
			head += "  " + hintStyle.Render(vl)
		}
		b.WriteString("  " + head + "\n")
		sub := func(k, v string) {
			if v != "" {
				b.WriteString("      " + hintStyle.Render(k+": ") + valueStyle.Render(v) + "\n")
			}
		}
		sub("info", p.ExtraInfo)
		sub("title", p.HTTPTitle)
		sub("cert", p.Cert)
		if p.Risk != "" {
			b.WriteString("      " + sevStyle(p.Severity).Render("⚠ "+p.Risk) + "\n")
		}
	}

	// Web services hint
	if urls := d.webURLs(); len(urls) > 0 {
		b.WriteString("\n  " + okStyle.Render("◆ web: ") + hintStyle.Render(strings.Join(urls, "  ")) + "\n")
	}

	if d.notice != "" {
		b.WriteString("\n  " + okStyle.Render("✔ "+d.notice) + "\n")
	}

	// Action footer
	actions := []string{"r rescan"}
	if len(d.webURLs()) > 0 {
		actions = append(actions, "o open web")
	}
	actions = append(actions, "esc back")
	b.WriteString("\n  " + hintStyle.Render(strings.Join(actions, " · ")))
	return discoverBox(b.String())
}

func discoverBox(s string) string {
	return panelStyle.Render(s)
}

// openWeb opens every web service on the host in the browser.
func (m *Model) openWeb() string {
	urls := m.disco.webURLs()
	if len(urls) == 0 {
		return "no web services on this host"
	}
	if !report.CanOpen() {
		return "opening not supported on this system"
	}
	for _, u := range urls {
		_ = report.Open(u)
	}
	if len(urls) == 1 {
		return "opened " + urls[0]
	}
	return fmt.Sprintf("opened %d web service(s)", len(urls))
}
