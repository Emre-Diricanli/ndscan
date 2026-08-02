package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"

	"github.com/Emre-Diricanli/ndscan/internal/scan"
)

func (m Model) View() string {
	var base string
	switch m.screen {
	case screenRunning:
		base = m.viewRunning()
	case screenResults:
		base = m.viewResults()
	default:
		base = m.viewForm()
	}
	if m.mode != modeNone && m.mode != modeFilter {
		return m.overlay(base)
	}
	return base
}

// header renders the title bar, with a right-aligned context chip and a rule
// beneath it so every screen starts the same way.
func (m Model) header(context string) string {
	title := titleStyle.Render("ndscan")
	sub := appBar.Render(fmt.Sprintf("network scanner · v%s", m.version))
	left := lipgloss.JoinHorizontal(lipgloss.Center, title, sub)

	w := m.width
	if w == 0 {
		w = 100
	}
	bar := left
	if context != "" {
		chip := badgeStyle.Render(context)
		gap := w - lipgloss.Width(left) - lipgloss.Width(chip) - 2
		if gap > 1 {
			bar = left + strings.Repeat(" ", gap) + chip
		}
	}
	return bar + "\n" + divider(w-2)
}

// overlay renders the active modal centered over dimmed base content.
func (m Model) overlay(base string) string {
	var panel string
	switch m.mode {
	case modeHelp:
		panel = m.helpPanel()
	case modeDetail:
		panel = m.detailPanel()
	case modeProfileName:
		panel = panelStyle.Render(
			labelFocusedStyle.Render("Save profile as:") + "\n\n" +
				m.profileNameIn.View() + "\n\n" +
				hintStyle.Render("enter save · esc cancel"))
	case modeProfilePicker:
		panel = m.profilePanel()
	case modeDiscover:
		panel = m.discoverPanel()
	default:
		return base
	}
	w, h := m.width, m.height
	if w == 0 {
		w = 100
	}
	if h == 0 {
		h = 30
	}
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, panel)
}

func (m Model) helpPanel() string {
	rows := []string{
		labelFocusedStyle.Render("Keybindings"),
		"",
		accentText.Render("Form"),
		"  tab / ↑↓        move between fields",
		"  ← →             change preset",
		"  space / enter   toggle checkbox",
		"  Use sudo        elevate for full discovery (prompts once)",
		"  ctrl+s          save form as profile",
		"  ctrl+p          load / manage profiles",
		"  enter on Start  begin scan",
		"",
		accentText.Render("Scanning"),
		"  esc or q        cancel (keeps partial results)",
		"",
		accentText.Render("Results"),
		"  ↑↓              move selection (table) / scroll (tree)",
		"  mouse wheel      scroll the list",
		"  pgup/pgdn g G   page / jump (tree)",
		"  enter           Discover: deep-scan the selected host",
		"    in Discover:   r rescan · o open web services · esc back",
		"  t               cycle view: table · tree · map",
		"  /               filter rows (esc clears)",
		"  s               cycle sort (in the map: scan next network)",
		"  e / c           export JSON / CSV",
		"  m / h           export Markdown / HTML report",
		"  " + hintStyle.Render("                 → ~/Downloads/ndscan/<date>/"),
		"  w               toggle watch mode (auto-rescan)",
		"  b               toggle desktop notifications on change",
		"  + / -           watch interval ±15s",
		"  r               new scan (back to form)",
		"  q               quit",
		"",
		accentText.Render("Network map") + hintStyle.Render("  (t to reach it)"),
		hintStyle.Render("  Shows every network this machine is attached to, the"),
		hintStyle.Render("  default gateway, and the hosts found on each. Networks"),
		hintStyle.Render("  you haven't scanned are marked — press s to scan one."),
		hintStyle.Render("  It reads interfaces and the routing table only, so it"),
		hintStyle.Render("  can't see subnets beyond the gateway."),
		"",
		hintStyle.Render("Δ column shows changes vs the previous scan of the"),
		hintStyle.Render("same targets: NEW host, GONE host, +/-port."),
		"",
		hintStyle.Render("Risk column flags notable open ports:"),
		"  " + errStyle.Render("!!") + hintStyle.Render(" high (telnet/ftp/nfs)  ") +
			warnStyle.Render("▲") + hintStyle.Render(" warn (smb/rdp/db)  ") +
			accentText.Render("·") + hintStyle.Render(" info"),
		hintStyle.Render("Open host details (enter) for per-port service,"),
		hintStyle.Render("version, RTT, and the reason a port is flagged."),
		"",
		hintStyle.Render("press any key to close"),
	}
	return panelStyle.Render(strings.Join(rows, "\n"))
}

func (m Model) detailPanel() string {
	rv := m.selectedRow()
	if rv == nil {
		return panelStyle.Render("no host selected")
	}
	r := rv.row
	var b strings.Builder
	line := func(k, v string) {
		b.WriteString(labelStyle.Width(9).Render(k) + " " + valueStyle.Render(dash(v)) + "\n")
	}
	b.WriteString(accentText.Bold(true).Render(r.IP) + "\n\n")
	line("Host", r.Host)
	if rv.gone {
		b.WriteString(labelStyle.Width(9).Render("Status") + " " + errStyle.Render("GONE — seen in previous scan, not this one") + "\n")
	} else if r.Up {
		b.WriteString(labelStyle.Width(9).Render("Status") + " " + okStyle.Render("up") + "\n")
	} else {
		b.WriteString(labelStyle.Width(9).Render("Status") + " " + errStyle.Render("down") + "\n")
	}
	line("MAC", r.MAC)
	line("Vendor", r.Vendor)
	// OS with confidence and CPE when available.
	if r.OS != "" {
		os := r.OS
		if r.OSAccuracy > 0 {
			os += hintStyle.Render(fmt.Sprintf("  (%d%%)", r.OSAccuracy))
		}
		b.WriteString(labelStyle.Width(9).Render("OS") + " " + valueStyle.Render(os) + "\n")
		if r.OSCPE != "" {
			b.WriteString(strings.Repeat(" ", 10) + hintStyle.Render(r.OSCPE) + "\n")
		}
	} else {
		line("OS", "")
	}
	line("RTT", r.RTT)
	if rv.diff.Changed() && !rv.gone {
		b.WriteString(labelStyle.Width(9).Render("Changes") + " " + warnStyle.Render(diffBadge(rv.diff)) + "\n")
	}

	// Open ports, with service+version and a risk badge for notable services.
	b.WriteString("\n" + labelStyle.Render("Open ports") + "\n")
	if len(r.PortDetails) == 0 && len(r.Ports) == 0 {
		b.WriteString(hintStyle.Render("  none") + "\n")
	}
	if len(r.PortDetails) > 0 {
		highest := ""
		for _, p := range r.PortDetails {
			head := accentText.Render(fmt.Sprintf("%d/%s", p.Port, p.Proto))
			if p.Service != "" {
				head += "  " + valueStyle.Render(p.Service)
			}
			if p.TLS {
				head += "  " + okStyle.Render("🔒 tls")
			}
			if vl := p.VersionLabel(); vl != "" {
				head += "  " + hintStyle.Render(vl)
			}
			b.WriteString("  " + head + "\n")
			detail := func(k, v string) {
				b.WriteString("      " + hintStyle.Render(k+": ") + valueStyle.Render(v) + "\n")
			}
			if p.ExtraInfo != "" {
				detail("info", p.ExtraInfo)
			}
			if p.HTTPTitle != "" {
				detail("title", p.HTTPTitle)
			}
			if p.Cert != "" {
				detail("cert", p.Cert)
			}
			if p.CPE != "" {
				b.WriteString("      " + hintStyle.Render(p.CPE) + "\n")
			}
			if p.Risk != "" {
				b.WriteString("      " + sevStyle(p.Severity).Render("⚠ "+p.Risk) + "\n")
			}
			if rankSeverity(p.Severity) > rankSeverity(highest) {
				highest = p.Severity
			}
		}
		if highest == "high" || highest == "warn" {
			b.WriteString("\n  " + sevStyle(highest).Render("▲ "+exposureNote(highest)) + "\n")
		}
	} else {
		// fall back to raw labels if structured detail is unavailable
		for _, p := range r.Ports {
			b.WriteString("  " + accentText.Render(p) + "\n")
		}
	}

	b.WriteString("\n" + hintStyle.Render("esc to close"))
	return panelStyle.Render(b.String())
}

func (m Model) profilePanel() string {
	var b strings.Builder
	b.WriteString(labelFocusedStyle.Render("Profiles") + "\n\n")
	if len(m.profiles) == 0 {
		b.WriteString(hintStyle.Render("  none saved yet — ctrl+s on the form saves one") + "\n")
	}
	for i, p := range m.profiles {
		cursor := "  "
		style := valueStyle
		if i == m.profileIdx {
			cursor = accentText.Render("▸ ")
			style = labelFocusedStyle
		}
		b.WriteString(cursor + style.Render(p.Name) + hintStyle.Render("  "+p.Settings.Targets) + "\n")
	}
	b.WriteString("\n" + hintStyle.Render("enter load · d delete · esc close"))
	return panelStyle.Render(b.String())
}

// ----- FORM VIEW -----

func (m Model) viewForm() string {
	var b strings.Builder

	field := func(idx int, label, value, hint string) {
		ls := labelStyle
		if m.focus == idx {
			ls = labelFocusedStyle
		}
		cursor := "  "
		if m.focus == idx {
			cursor = accentText.Render("▸ ")
		}
		line := fmt.Sprintf("%s%s  %s", cursor, ls.Width(14).Render(label), value)
		b.WriteString(line)
		if hint != "" {
			b.WriteString("  " + hintStyle.Render(hint))
		}
		b.WriteString("\n")
	}

	section := func(name string) {
		b.WriteString("\n  " + sectionStyle.Render(name) + "\n")
	}

	section("TARGET")
	field(fTargets, "Targets", m.targetsIn.View(), "")
	field(fPreset, "Preset", presetSelector(m.presetIdx), "← → to change")
	field(fPorts, "Ports", m.portsIn.View(), "")

	section("DETAIL")
	field(fShowMac, "Show MAC", checkbox(m.showMac), "from ARP cache (no root) + nmap")
	field(fShowVendors, "Show vendors", checkbox(m.showVend), "needs Show MAC")

	section("PRIVILEGE")
	field(fRootScan, "SYN scan", checkbox(m.rootScan), "-sS, needs root/sudo")
	sudoHint := "thorough ARP + SYN scan via sudo"
	if scan.IsRoot() {
		sudoHint = "already root — not needed"
	}
	field(fSudo, "Use sudo", checkbox(m.sudo || scan.IsRoot()), sudoHint)

	section("PERFORMANCE")
	field(fConcurrency, "Concurrency", m.concurIn.View(), "parallel hosts")
	field(fHostTimeout, "Host timeout", m.timeoutIn.View(), "seconds")

	b.WriteString("\n")
	cursor := "  "
	startBtn := buttonStyle.Render("▶ Start scan")
	if m.focus == fStart {
		cursor = accentText.Render("▸ ")
		startBtn = buttonFocusedStyle.Render("▶ Start scan")
	}
	b.WriteString(cursor + startBtn + "\n")

	// advisory when an unprivileged local scan will under-report
	if !scan.IsRoot() && !m.sudo {
		b.WriteString("\n  " + warnStyle.Render("⚠ not root: ") +
			hintStyle.Render("MACs come from the ARP cache; for full host discovery"))
		b.WriteString("\n    " + hintStyle.Render("and SYN scans, toggle ") +
			accentText.Render("Use sudo") + hintStyle.Render(" or run ") +
			accentText.Render("sudo ndscan") + "\n")
	}

	if m.err != nil {
		b.WriteString("\n  " + errStyle.Render("✖ "+m.err.Error()) + "\n")
	}
	if m.notice != "" {
		b.WriteString("\n  " + okStyle.Render("✔ "+m.notice) + "\n")
	}

	help := helpStyle.Render(keyHint(
		[2]string{"tab/↑↓", "move"},
		[2]string{"space", "toggle"},
		[2]string{"enter", "start"},
		[2]string{"ctrl+s", "save profile"},
		[2]string{"ctrl+p", "profiles"},
		[2]string{"esc", "quit"},
	))

	panel := panelStyle.Render(b.String())
	return "\n" + m.header("configure") + "\n\n" + panel + "\n" + help
}

func presetSelector(active int) string {
	parts := make([]string, len(presets))
	for i, p := range presets {
		if i == active {
			parts[i] = lipgloss.NewStyle().Foreground(lipgloss.Color("#0b1120")).
				Background(accent).Bold(true).Padding(0, 1).Render(p)
		} else {
			parts[i] = hintStyle.Padding(0, 1).Render(p)
		}
	}
	return strings.Join(parts, " ")
}

// ----- RUNNING VIEW -----

func (m Model) viewRunning() string {
	steps := []struct {
		key, label string
	}{
		{"discover", "Discover live hosts"},
		{"mac", "Collect MAC addresses"},
		{"scan", "Scan ports"},
	}
	order := map[string]int{"discover": 0, "mac": 1, "scan": 2}
	cur := order[m.phase]

	var b strings.Builder
	for _, s := range steps {
		if s.key == "mac" && !m.params.showMac {
			continue
		}
		i := order[s.key]
		switch {
		case i < cur:
			b.WriteString(okStyle.Render("  ✔ ") + s.label + "\n")
		case i == cur:
			detail := ""
			if s.key == "scan" && m.phaseTotal > 0 {
				detail = hintStyle.Render(fmt.Sprintf("  %d/%d", m.phaseDone, m.phaseTotal))
			}
			b.WriteString("  " + m.spin.View() + accentText.Render(s.label) + detail + "\n")
		default:
			b.WriteString(hintStyle.Render("  ○ "+s.label) + "\n")
		}
	}

	if m.phase == "scan" && m.phaseTotal > 0 {
		b.WriteString("\n  " + progressBar(m.phaseDone, m.phaseTotal, 40) + "\n")
	}

	target := strings.Join(m.params.targets, ", ")
	where := "locally"
	if m.params.sshTarget != "" {
		where = "via " + m.params.sshTarget
	}
	b.WriteString("\n" + hintStyle.Render(fmt.Sprintf("  scanning %s  (%s, preset: %s)", target, where, m.params.preset)))

	panel := panelStyle.Render(b.String())

	// live results stream in below the progress panel as hosts finish
	live := ""
	if len(m.visible) > 0 {
		live = "\n" + m.tbl.View()
	}

	help := helpStyle.Render(keyHint(
		[2]string{"esc", "cancel (keeps partial results)"},
		[2]string{"?", "help"},
	))
	return "\n" + m.header("scanning") + "\n\n" + panel + live + "\n" + help
}

// progressBar renders a filled bar with a partial leading cell, so slow scans
// still show visible movement between whole-cell steps.
func progressBar(done, total, width int) string {
	if total <= 0 {
		total = 1
	}
	if done > total {
		done = total
	}
	// Work in eighths for sub-cell resolution.
	eighths := done * width * 8 / total
	filled := eighths / 8
	if filled > width {
		filled = width
	}
	partial := ""
	if filled < width {
		if rem := eighths % 8; rem > 0 {
			partial = string([]rune("▏▎▍▌▋▊▉")[rem-1])
		}
	}
	empty := width - filled - lipgloss.Width(partial)
	if empty < 0 {
		empty = 0
	}
	bar := accentText.Render(strings.Repeat("█", filled)+partial) +
		dividerStyle.Render(strings.Repeat("░", empty))
	pct := done * 100 / total
	return fmt.Sprintf("%s %s", bar, accentText.Render(fmt.Sprintf("%3d%%", pct)))
}

// ----- RESULTS VIEW -----

func (m Model) viewResults() string {
	var body string
	switch {
	// The map is meaningful even with no results: it still shows the networks
	// this machine is attached to.
	case m.view == viewTopology:
		body = m.mapVP.View()
	case len(m.visible) == 0 && m.filterIn.Value() != "":
		body = warnStyle.Render("  No rows match the filter.")
	case len(m.visible) == 0:
		body = warnStyle.Render("  No live hosts found.")
	case m.view == viewTree:
		body = m.treeVP.View()
	default:
		body = m.tbl.View()
	}

	summary := okStyle.Render("● ") + valueStyle.Render(m.summary)
	if m.failed > 0 {
		summary += warnStyle.Render(fmt.Sprintf("  (%d host scan failures)", m.failed))
	}
	if d := m.diffSummary(); d != "" {
		summary += "\n  " + warnStyle.Render("Δ "+d)
	}
	if m.notice != "" {
		summary += "\n  " + okStyle.Render("✔ "+m.notice)
	}

	var status []string
	if m.mode == modeFilter {
		status = append(status, accentText.Render("filter: ")+m.filterIn.View())
	} else if m.filterIn.Value() != "" {
		status = append(status, hintStyle.Render("filter: ")+accentText.Render(m.filterIn.Value()))
	}
	status = append(status, hintStyle.Render("sort: ")+accentText.Render(m.sortBy.String()))
	// Scroll indicator when the active scrollable view overflows its viewport.
	if vp, ok := m.activeViewport(); ok && vp.TotalLineCount() > vp.Height {
		status = append(status, hintStyle.Render("scroll: ")+accentText.Render(fmt.Sprintf("%3.0f%%", vp.ScrollPercent()*100)))
	}
	if m.watch {
		bell := "🔔"
		if !m.notify {
			bell = "🔕"
		}
		status = append(status, okStyle.Render(fmt.Sprintf("watch: rescan in %ds (every %s) %s", m.watchLeft, m.watchEvery, bell)))
	}
	statusLine := "  " + strings.Join(status, hintStyle.Render("  ·  "))

	// The sort key is meaningless in the map, where "s" scans instead.
	sortOrScan := [2]string{"s", "sort"}
	if m.view == viewTopology {
		sortOrScan = [2]string{"s", "scan next network"}
	}
	help := helpStyle.Render(keyHint(
		[2]string{"enter", "discover"},
		[2]string{"t", "view [" + m.view.String() + "]"},
		[2]string{"/", "filter"},
		sortOrScan,
		[2]string{"e/c/m/h", "export"},
		[2]string{"w", "watch"},
		[2]string{"r", "rescan"},
		[2]string{"?", "help"},
		[2]string{"q", "quit"},
	))

	return "\n" + m.header(m.view.String()) + "\n\n" + body + "\n" + statusLine + "\n\n  " + summary + "\n" + help
}

// activeViewport returns the scrollable viewport for the current view, if the
// current view is a scrolling one.
func (m Model) activeViewport() (viewport.Model, bool) {
	switch m.view {
	case viewTree:
		if len(m.visible) > 0 {
			return m.treeVP, true
		}
	case viewTopology:
		return m.mapVP, true
	}
	return viewport.Model{}, false
}

// diffSummary aggregates the change map into one line.
func (m Model) diffSummary() string {
	if len(m.diff) == 0 {
		return ""
	}
	newHosts, gone, opened, closed := 0, 0, 0, 0
	for _, d := range m.diff {
		switch {
		case d.New:
			newHosts++
		case d.Gone:
			gone++
		}
		opened += len(d.PortsOpened)
		closed += len(d.PortsClosed)
	}
	var parts []string
	if newHosts > 0 {
		parts = append(parts, fmt.Sprintf("%d new host(s)", newHosts))
	}
	if gone > 0 {
		parts = append(parts, fmt.Sprintf("%d host(s) gone", gone))
	}
	if opened > 0 {
		parts = append(parts, fmt.Sprintf("%d port(s) opened", opened))
	}
	if closed > 0 {
		parts = append(parts, fmt.Sprintf("%d port(s) closed", closed))
	}
	if len(parts) == 0 {
		return "no changes since previous scan"
	}
	return strings.Join(parts, " · ")
}

func (m Model) treeView() string {
	var b strings.Builder
	for _, rv := range m.visible {
		r := rv.row
		head := accentText.Bold(true).Render(r.IP)
		if rv.badge != "" {
			head += "  " + warnStyle.Render("["+rv.badge+"]")
		}
		b.WriteString("  " + head + "\n")
		if rv.gone {
			b.WriteString(hintStyle.Render("  └─ ") + errStyle.Render("not seen in this scan") + "\n\n")
			continue
		}
		host := r.Host
		if host == "" {
			host = "-"
		}
		b.WriteString(hintStyle.Render("  ├─ ") + "Host: " + host + "\n")
		up := errStyle.Render("no")
		if r.Up {
			up = okStyle.Render("yes")
		}
		b.WriteString(hintStyle.Render("  ├─ ") + "Up: " + up + "\n")
		if r.OS != "" {
			b.WriteString(hintStyle.Render("  ├─ ") + "OS: " + r.OS + "\n")
		}
		if r.RTT != "" {
			b.WriteString(hintStyle.Render("  ├─ ") + "RTT: " + r.RTT + "\n")
		}
		if m.params.showMac {
			b.WriteString(hintStyle.Render("  ├─ ") + "MAC: " + dash(r.MAC) + "\n")
			if m.params.showVendors {
				b.WriteString(hintStyle.Render("  ├─ ") + "Vendor: " + dash(r.Vendor) + "\n")
			}
		}
		if len(r.PortDetails) == 0 && len(r.Ports) == 0 {
			b.WriteString(hintStyle.Render("  └─ ") + "Ports: -\n")
		} else if len(r.PortDetails) > 0 {
			b.WriteString(hintStyle.Render("  └─ ") + "Ports:\n")
			for i, p := range r.PortDetails {
				branch := "     ├─ "
				if i == len(r.PortDetails)-1 {
					branch = "     └─ "
				}
				label := fmt.Sprintf("%d/%s %s", p.Port, p.Proto, p.Service)
				if vl := p.VersionLabel(); vl != "" {
					label += " " + vl
				}
				line := hintStyle.Render(branch) + accentText.Render(label)
				if p.Risk != "" {
					line += "  " + sevStyle(p.Severity).Render("⚠ "+p.Risk)
				}
				b.WriteString(line + "\n")
			}
		} else {
			b.WriteString(hintStyle.Render("  └─ ") + "Ports:\n")
			for i, p := range r.Ports {
				branch := "     ├─ "
				if i == len(r.Ports)-1 {
					branch = "     └─ "
				}
				b.WriteString(hintStyle.Render(branch) + accentText.Render(p) + "\n")
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
