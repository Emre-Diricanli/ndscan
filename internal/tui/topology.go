package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/topology"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// Glyphs for the map. Kept in one place so the visual language stays
// consistent, and so a future ASCII-only fallback has a single switch point.
const (
	glyphSelf    = "▚" // this machine
	glyphGateway = "⌂" // default gateway
	glyphHost    = "▪" // ordinary host
	glyphScanned = "◆" // segment was scanned
	glyphUnknown = "○" // segment attached but not scanned
	glyphRisk    = "⚠"
)

// topologyView renders the network map: every network this machine is attached
// to, the gateway, and the hosts found on each.
func (m Model) topologyView() string {
	locals := m.netLocals
	gw := m.netGateway

	rows := make([]ui.Row, 0, len(m.visible))
	for _, rv := range m.visible {
		if !rv.gone {
			rows = append(rows, rv.row)
		}
	}
	tm := topology.Build(rows, locals, gw)

	if len(tm.Segments) == 0 {
		return hintStyle.Render("  No networks detected. Run a scan to populate the map.")
	}

	var b strings.Builder
	// Legend makes the glyph vocabulary self-explanatory without opening help.
	b.WriteString("  " + hintStyle.Render(fmt.Sprintf(
		"%s this machine   %s gateway   %s host   %s risk",
		glyphSelf, glyphGateway, glyphHost, glyphRisk)) + "\n\n")

	self := selfLabel(locals)
	b.WriteString("  " + accentText.Bold(true).Render(glyphSelf+" "+self) + "\n")
	b.WriteString("  " + hintStyle.Render("│") + "\n")

	for si, seg := range tm.Segments {
		last := si == len(tm.Segments)-1
		b.WriteString(m.renderSegment(seg, last, gw))
		if !last {
			b.WriteString("  " + hintStyle.Render("│") + "\n")
		}
	}
	return b.String()
}

// firstUnscannedNetwork returns the CIDR of the first attached network the
// current results don't cover, for the map's "press s to scan" affordance.
func (m Model) firstUnscannedNetwork() (string, bool) {
	rows := make([]ui.Row, 0, len(m.visible))
	for _, rv := range m.visible {
		if !rv.gone {
			rows = append(rows, rv.row)
		}
	}
	for _, seg := range topology.Build(rows, m.netLocals, m.netGateway).Segments {
		// Only offer networks this machine is actually attached to; synthetic
		// segments from remote scans have no interface and aren't ours to scan.
		// Skip /32s: a point-to-point tunnel address is not a scannable range.
		if seg.NotScanned && seg.Interface != "" && !strings.HasSuffix(seg.CIDR, "/32") {
			return seg.CIDR, true
		}
	}
	return "", false
}

// selfLabel names this machine for the root of the map.
func selfLabel(locals []netinfo.Network) string {
	host := shortHostname()
	if len(locals) > 0 {
		if host != "" {
			return host + "  " + locals[0].Addr
		}
		return locals[0].Addr
	}
	if host != "" {
		return host
	}
	return "this machine"
}

// renderSegment draws one network and its hosts.
func (m Model) renderSegment(seg topology.Segment, last bool, gw netinfo.Gateway) string {
	var b strings.Builder

	elbow := "├─"
	cont := "│ "
	if last {
		elbow = "└─"
		cont = "  "
	}

	// Segment header: interface, CIDR, and scan state.
	head := hintStyle.Render("  "+elbow+" ") + labelFocusedStyle.Render(seg.CIDR)
	if seg.Interface != "" {
		head += hintStyle.Render("  " + seg.Interface)
	}
	if seg.NotScanned {
		head += "  " + hintStyle.Render(glyphUnknown+" not scanned")
	} else {
		head += "  " + okStyle.Render(fmt.Sprintf("%s scanned · %d host(s)", glyphScanned, seg.HostCount()))
	}
	b.WriteString(head + "\n")

	if seg.NotScanned {
		// A /32 is a single point-to-point address (a VPN tunnel endpoint),
		// not a range worth sweeping — say so rather than offering a scan that
		// would find only this machine.
		if strings.HasSuffix(seg.CIDR, "/32") {
			b.WriteString(hintStyle.Render("  "+cont+"   point-to-point tunnel · no range to scan") + "\n")
		} else {
			b.WriteString(hintStyle.Render("  "+cont+"   press ") +
				accentText.Render("s") + hintStyle.Render(" to scan this network") + "\n")
		}
		return b.String()
	}

	// Column widths are computed per segment so each network's hosts align
	// with each other without forcing a global width on unrelated segments.
	addrW, nameW := 0, 0
	for _, n := range seg.Nodes {
		if w := lipgloss.Width(shortAddr(n.Row.IP, seg.CIDR)); w > addrW {
			addrW = w
		}
		if w := lipgloss.Width(nodeName(n)); w > nameW {
			nameW = w
		}
	}
	if nameW > 18 {
		nameW = 18
	}

	for i, n := range seg.Nodes {
		lastNode := i == len(seg.Nodes)-1
		branch := "├─"
		if lastNode {
			branch = "└─"
		}
		b.WriteString(hintStyle.Render("  "+cont+" "+branch+" ") + m.renderNode(n, seg, addrW, nameW) + "\n")
	}
	return b.String()
}

// nodeName is the display name for a host: hostname, else vendor, else a
// marker for this machine, else empty.
func nodeName(n topology.Node) string {
	switch {
	case n.Row.Host != "":
		return n.Row.Host
	case n.Row.Vendor != "":
		return n.Row.Vendor
	case n.IsSelf:
		return "this machine"
	default:
		return ""
	}
}

// pad right-pads s to width w, measuring display cells rather than bytes so
// non-ASCII names don't break the columns.
func pad(s string, w int) string {
	if d := w - lipgloss.Width(s); d > 0 {
		return s + strings.Repeat(" ", d)
	}
	return s
}

// renderNode draws one host line in aligned columns:
//
//	⌂ .1    router    gateway  53 80 443       3.1ms
//	▪ .31   Espressif          ⚠ 23            48ms
func (m Model) renderNode(n topology.Node, seg topology.Segment, addrW, nameW int) string {
	glyph := glyphHost
	style := valueStyle
	switch {
	case n.IsGateway:
		glyph, style = glyphGateway, accentText.Bold(true)
	case n.IsSelf:
		glyph, style = glyphSelf, accentText
	}

	// Show the host octet(s) rather than repeating the network prefix.
	addr := pad(shortAddr(n.Row.IP, seg.CIDR), addrW)
	line := style.Render(glyph+" "+addr) + "  "

	line += valueStyle.Render(pad(truncate(nodeName(n), nameW), nameW)) + "  "

	// Role marker keeps the gateway visually distinct from ordinary hosts.
	role := "       "
	if n.IsGateway {
		role = hintStyle.Render("gateway")
	}
	line += role + "  "

	// Ports, with the worst severity colored. Width fits the longest summary
	// portSummary can emit (four ports plus a "+N" overflow marker).
	const portsW = 22
	ports := portSummary(n.Row)
	switch {
	case ports == "":
		line += pad("", portsW)
	case n.Severity == "high" || n.Severity == "warn":
		labeled := glyphRisk + " " + ports
		line += sevStyle(n.Severity).Render(labeled) + strings.Repeat(" ", maxInt(0, portsW-lipgloss.Width(labeled)))
	default:
		line += hintStyle.Render(ports) + strings.Repeat(" ", maxInt(0, portsW-lipgloss.Width(ports)))
	}

	if n.Row.RTT != "" {
		line += hintStyle.Render(n.Row.RTT)
	}
	return strings.TrimRight(line, " ")
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// portSummary condenses a host's open ports for the map, e.g. "22 443 +3".
func portSummary(r ui.Row) string {
	if len(r.PortDetails) == 0 {
		return ""
	}
	const maxShown = 4
	parts := make([]string, 0, maxShown)
	for i, p := range r.PortDetails {
		if i == maxShown {
			parts = append(parts, fmt.Sprintf("+%d", len(r.PortDetails)-maxShown))
			break
		}
		parts = append(parts, fmt.Sprintf("%d", p.Port))
	}
	return strings.Join(parts, " ")
}

// shortAddr trims the network prefix from an address so the map reads as a
// list of hosts, e.g. "192.168.1.10" in a /24 becomes ".10".
func shortAddr(ip, cidr string) string {
	prefix, _, ok := strings.Cut(cidr, "/")
	if !ok {
		return ip
	}
	octets := strings.Split(prefix, ".")
	if len(octets) != 4 {
		return ip
	}
	base := strings.Join(octets[:3], ".")
	if trimmed, found := strings.CutPrefix(ip, base); found {
		return trimmed // keeps the leading dot, e.g. ".10"
	}
	return ip
}

func truncate(s string, n int) string {
	if lipgloss.Width(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
