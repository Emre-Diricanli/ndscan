package ui

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/userenv"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

type Row struct {
	IP         string   `json:"ip"`
	MAC        string   `json:"mac,omitempty"`
	Vendor     string   `json:"vendor,omitempty"`
	Host       string   `json:"hostname,omitempty"`
	OS         string   `json:"os,omitempty"`          // best OS-detection guess (needs -A presets)
	OSAccuracy int      `json:"os_accuracy,omitempty"` // confidence 0-100
	OSCPE      string   `json:"os_cpe,omitempty"`      // first OS CPE
	RTT        string   `json:"rtt,omitempty"`         // smoothed round-trip time, e.g. "2.1ms"
	Up         bool     `json:"up"`
	Ports      []string `json:"ports,omitempty"` // labels like "22/tcp ssh"
	// PortDetails carries the structured per-port view (number, service,
	// version, risk) for detail panes and reports. It mirrors Ports.
	PortDetails []PortInfo `json:"port_details,omitempty"`
}

// PortInfo is the structured form of one open port.
type PortInfo struct {
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Service   string `json:"service,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	ExtraInfo string `json:"extra_info,omitempty"` // e.g. "Python 3.14.3"
	CPE       string `json:"cpe,omitempty"`        // e.g. "cpe:/a:python:python:3.14"
	TLS       bool   `json:"tls,omitempty"`        // service runs over an SSL/TLS tunnel
	HTTPTitle string `json:"http_title,omitempty"` // page title (http-title script)
	Cert      string `json:"cert,omitempty"`       // TLS cert summary (ssl-cert script)
	Severity  string `json:"severity,omitempty"`   // "", "info", "warn", "high"
	Risk      string `json:"risk,omitempty"`       // human-readable reason
}

// VersionLabel renders product + version, e.g. "OpenSSH 9.6", or "".
func (p PortInfo) VersionLabel() string {
	parts := make([]string, 0, 2)
	if p.Product != "" {
		parts = append(parts, p.Product)
	}
	if p.Version != "" {
		parts = append(parts, p.Version)
	}
	return strings.Join(parts, " ")
}

// stripControls removes C0/C1 control characters and ANSI escape sequences
// from a network-derived string before it reaches the user's terminal. A
// hostile service banner or PTR record can otherwise inject escapes that
// clear the screen or forge output. Printable text — including legitimate
// non-ASCII UTF-8 — passes through byte-for-byte.
func stripControls(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	// state: 0 = normal, 1 = saw ESC (next char is the introducer),
	// 2 = inside a CSI sequence, swallowing through its final byte.
	state := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch state {
		case 1:
			if r == '[' {
				state = 2
			} else {
				state = 0 // two-byte escape (ESC + one char) fully swallowed
			}
		case 2:
			// A CSI sequence ends at its final byte (0x40–0x7E); everything
			// before that is parameters.
			if r >= 0x40 && r <= 0x7E {
				state = 0
			}
		default:
			switch {
			case r == 0x1B: // ESC
				state = 1
			case r == 0x9B: // C1 CSI
				state = 2
			case r == utf8.RuneError && size == 1:
				// Invalid UTF-8 byte: a terminal may still interpret a
				// stray C1 byte (raw 0x9B is CSI), so drop it rather than
				// pass it through.
				if s[i] == 0x9B {
					state = 2
				}
			case unicode.IsControl(r):
				// drop C0/C1 control characters
			default:
				b.WriteString(s[i : i+size])
			}
		}
		i += size
	}
	return b.String()
}

func flatten(res []scan.HostResult) []Row {
	out := make([]Row, 0, len(res))
	for _, r := range res {
		if r.Err != nil || len(r.XMLBytes) == 0 {
			continue
		}
		nr, err := scan.ParseOne(r.XMLBytes)
		if err != nil {
			continue
		}

		for _, h := range nr.Hosts {
			row := Row{Up: h.Status.State == "up"}
			for _, a := range h.Addresses {
				switch a.AddrType {
				case "ipv4", "ipv6":
					row.IP = a.Addr
				case "mac":
					row.MAC = a.Addr
				}
			}
			// Everything parsed from nmap XML is controlled by the scanned
			// host, so this is the single boundary where terminal escapes
			// are stripped before strings enter any rendered row.
			if len(h.Hostnames.Names) > 0 {
				row.Host = stripControls(h.Hostnames.Names[0].Name)
			}
			if osd := h.BestOSDetail(); osd != nil {
				row.OS = stripControls(osd.Name)
				row.OSAccuracy = osd.Accuracy
				row.OSCPE = stripControls(osd.CPE)
			}
			if rtt := h.RTT(); rtt > 0 {
				row.RTT = formatRTT(rtt)
			}
			for _, p := range h.Ports.List {
				if p.State.State == "open" {
					label := fmt.Sprintf("%d/%s %s", p.PortID, p.Protocol, stripControls(p.Service.Name))
					if p.Service.Product != "" {
						label += " " + stripControls(p.Service.Product)
					}
					if p.Service.Version != "" {
						label += " " + stripControls(p.Service.Version)
					}
					row.Ports = append(row.Ports, label)

					risk := scan.ClassifyPort(p.PortID, p.Service.Name)
					pi := PortInfo{
						Port:      p.PortID,
						Proto:     p.Protocol,
						Service:   stripControls(p.Service.Name),
						Product:   stripControls(p.Service.Product),
						Version:   stripControls(p.Service.Version),
						ExtraInfo: stripControls(p.Service.ExtraInfo),
						CPE:       stripControls(p.Service.CPE()),
						TLS:       p.Service.Tunnel == "ssl",
						HTTPTitle: stripControls(p.HTTPTitle()),
						Severity:  risk.Severity.String(),
						Risk:      risk.Reason,
					}
					if cert := p.TLSCert(); cert != nil {
						pi.Cert = stripControls(cert.Summary())
					}
					row.PortDetails = append(row.PortDetails, pi)
				}
			}
			out = append(out, row)
		}
	}
	return mergePorts(out)
}

// BuildRows flattens raw scan results into display rows, fills any missing MACs
// from macMap, and resolves vendor names when requested. The TUI and the
// non-interactive printers share this so the data is identical across views.
func BuildRows(res []scan.HostResult, db vendor.DB, showMac, showVendors bool, macMap map[string]string) []Row {
	rows := flatten(res)
	if showMac && macMap != nil {
		for i := range rows {
			if rows[i].MAC == "" {
				if mac, ok := macMap[rows[i].IP]; ok {
					rows[i].MAC = mac
				}
			}
		}
	}
	if showMac && showVendors {
		for i := range rows {
			rows[i].Vendor = vendor.Lookup(db, rows[i].MAC, "")
		}
	}
	ApplyHostnames(rows, hostnames)
	return rows
}

// ApplyHostnames fills in hostnames the scan itself didn't learn.
//
// The native fast path reports no hostnames at all — it never asks a resolver —
// which is the main reason users reach for the far slower nmap presets. A
// reverse lookup closes most of that gap for a few milliseconds. Names already
// present are never overwritten: nmap's own PTR result came from the scan and
// outranks a later best-effort lookup.
func ApplyHostnames(rows []Row, names map[string]string) {
	if len(names) == 0 {
		return
	}
	for i := range rows {
		if rows[i].Host == "" {
			// PTR data is resolver-controlled, so it gets the same
			// treatment as nmap-derived strings in flatten.
			rows[i].Host = stripControls(names[rows[i].IP])
		}
	}
}

// hostnames is consulted by BuildRows so every CLI renderer — table, tree,
// report, JSON — shows the same names without each of the four having to
// thread an extra parameter through. A nil map (the default) leaves behaviour
// exactly as it was.
//
// This is deliberately for the one-shot CLI only. The TUI and web server are
// long-lived and scan repeatedly, so a process-global would leak one scan's
// names into the next; those callers use ApplyHostnames on their own row slice
// instead. Two mechanisms, not duplication: the lifetime differs.
var hostnames map[string]string

// SetHostnames registers reverse-DNS results for the current scan. Call it
// after the scan and before rendering. Not safe for concurrent use with
// rendering, which is fine for its one caller: the CLI resolves once, then
// prints. Long-running callers should use ApplyHostnames instead.
func SetHostnames(names map[string]string) { hostnames = names }

// PortNumber exposes the "22/tcp ssh" -> "22" reduction for table-style views.
func PortNumber(label string) string { return extractPortNumber(label) }

// IPLess orders IPv4/IPv6 addresses numerically, falling back to a string
// compare for values that don't parse. Every view sorts through this so the CLI
// and the TUI agree on ordering (a lexical sort would put .10 before .9).
func IPLess(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return a < b
	}
	ia, ib = ia.To16(), ib.To16()
	for i := range ia {
		if ia[i] != ib[i] {
			return ia[i] < ib[i]
		}
	}
	return false
}

// formatRTT renders a round-trip time compactly: sub-millisecond as "0.4ms",
// otherwise one decimal of milliseconds ("2.1ms"), seconds for slow hosts.
func formatRTT(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	switch {
	case ms >= 1000:
		return fmt.Sprintf("%.2fs", ms/1000)
	case ms >= 10:
		return fmt.Sprintf("%.0fms", ms)
	default:
		return fmt.Sprintf("%.1fms", ms)
	}
}

func mergePorts(rows []Row) []Row {
	key := func(r Row) string { return r.IP + "|" + r.MAC + "|" + r.Host }
	m := map[string]Row{}
	for _, r := range rows {
		k := key(r)
		ex, ok := m[k]
		if !ok {
			m[k] = r
			continue
		}
		ex.Ports = append(ex.Ports, r.Ports...)
		ex.PortDetails = append(ex.PortDetails, r.PortDetails...)
		if ex.RTT == "" {
			ex.RTT = r.RTT
		}
		m[k] = ex
	}
	out := make([]Row, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	// stable order (sort by IP, numerically — see IPLess)
	sort.Slice(out, func(i, j int) bool { return IPLess(out[i].IP, out[j].IP) })
	return out
}

// extractPortNumber takes a label like "22/tcp ssh" or "443/tcp https" and returns "22", "443".
func extractPortNumber(label string) string {
	for i, r := range label {
		if !unicode.IsDigit(r) {
			if i == 0 {
				return label
			}
			return label[:i]
		}
	}
	return label
}

// ====== TABLE (port numbers only) ======

func PrintTableWithMACMap(res []scan.HostResult, db vendor.DB, showMac, showVendors bool, macMap map[string]string) {
	PrintTableRows(BuildRows(res, db, showMac, showVendors, macMap), showMac)
}

// PrintTableRows renders rows that have already been built.
//
// The scan pipeline hands its callers []Row rather than raw nmap results, so
// the renderers have to start from the same place. Keeping one implementation
// here — rather than a second copy in whichever front end needed rows — is what
// stops the table drifting between the CLI and everything else.
func PrintTableRows(rows []Row, showMac bool) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.Style().Format.Header = text.FormatDefault
	t.Style().Color.Header = cTitle
	if showMac {
		t.AppendHeader(table.Row{"IP", "MAC", "Vendor", "Host", "Up", "Risk", "Open Ports"})
	} else {
		t.AppendHeader(table.Row{"IP", "Host", "Up", "Risk", "Open Ports"})
	}

	for _, r := range rows {
		up := cErr.Sprint("✖ no")
		if r.Up {
			up = cOK.Sprint("✔ yes")
		}
		// Convert labels like "22/tcp ssh" -> "22" and join
		var justNums []string
		for _, lbl := range r.Ports {
			n := extractPortNumber(lbl)
			if n != "" {
				justNums = append(justNums, n)
			}
		}
		ports := cAccent.Sprint(strings.Join(justNums, ", "))
		risk := riskCell(r.PortDetails)

		host := r.Host
		if host == "" {
			host = cDim.Sprint("-")
		}
		ip := cBold.Sprint(r.IP)
		if showMac {
			mac := r.MAC
			if mac == "" {
				mac = cDim.Sprint("-")
			}
			t.AppendRow(table.Row{ip, mac, dashStr(r.Vendor), host, up, risk, ports})
		} else {
			t.AppendRow(table.Row{ip, host, up, risk, ports})
		}
	}
	t.Render()
}

// riskCell renders a colored severity glyph for the highest-risk open port.
func riskCell(ports []PortInfo) string {
	highest := ""
	rank := map[string]int{"high": 3, "warn": 2, "info": 1, "": 0}
	for _, p := range ports {
		if rank[p.Severity] > rank[highest] {
			highest = p.Severity
		}
	}
	switch highest {
	case "high":
		return cErr.Sprint("!!")
	case "warn":
		return cWarn.Sprint("▲")
	case "info":
		return cAccent.Sprint("·")
	default:
		return ""
	}
}

// Summarize returns the number of hosts that are up and the total count of
// open ports across all results, for the post-scan summary line.
func SummarizeRows(rows []Row) (hostsUp, openPorts int) {
	for _, r := range rows {
		if r.Up {
			hostsUp++
		}
		openPorts += len(r.Ports)
	}
	return
}

func Summarize(res []scan.HostResult) (hostsUp, openPorts int) {
	for _, r := range flatten(res) {
		if r.Up {
			hostsUp++
		}
		openPorts += len(r.Ports)
	}
	return
}

// PrintSummary prints the closing stats line to stderr.
func PrintSummary(hostsUp, openPorts int, elapsed time.Duration) {
	fmt.Fprintf(os.Stderr, "\n%s %s up · %s open · %s\n",
		cOK.Sprint("●"),
		cBold.Sprintf("%d host(s)", hostsUp),
		cBold.Sprintf("%d port(s)", openPorts),
		cDim.Sprintf("done in %s", elapsed.Round(time.Millisecond*10)),
	)
}

// PrintNextSteps names what the scan just made possible.
//
// Every scan records a baseline, a device inventory and a timeline, and none of
// that was ever mentioned at the one moment the user is certain to be paying
// attention. The result was a product whose entire change-detection half went
// unnoticed unless someone read `--help` for fun.
//
// recorded comes from the engine's own judgement about whether this run became
// a baseline; a cancelled or partial scan records nothing, and pointing that
// user at `ndscan diff` would be advice they cannot act on.
//
// stderr, like the summary above it, so redirected stdout stays clean. One line
// each, printed once: a scanner that lectures after every run is worse than one
// that says nothing.
func PrintNextSteps(recorded bool, targets []string) {
	if !recorded {
		return
	}
	target := strings.Join(targets, " ")
	if target == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "%s\n",
		cDim.Sprintf("  baseline saved · rerun later, then `ndscan diff %s` shows what changed", target))
	fmt.Fprintf(os.Stderr, "%s\n",
		cDim.Sprint("  `ndscan devices list` — every device seen so far"))
}

func WriteJSONWithMACMap(res []scan.HostResult, db vendor.DB, path string, showMac, showVendors bool, macMap map[string]string) error {
	rows := flatten(res)
	if showMac && macMap != nil {
		for i := range rows {
			if rows[i].MAC == "" {
				if mac, ok := macMap[rows[i].IP]; ok {
					rows[i].MAC = mac
				}
			}
		}
	}
	if showMac && showVendors {
		for i := range rows {
			rows[i].Vendor = vendor.Lookup(db, rows[i].MAC, "")
		}
	}
	b, _ := json.MarshalIndent(rows, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return err
	}
	return userenv.Chown(path)
}

// ====== TREE (detailed labels) ======

func PrintTreeWithMACMap(res []scan.HostResult, db vendor.DB, showMac, showVendors bool, macMap map[string]string) {
	PrintTreeRows(BuildRows(res, db, showMac, showVendors, macMap), showMac, showVendors)
}

// PrintTreeRows renders the tree view from rows that have already been built.
func PrintTreeRows(rows []Row, showMac, showVendors bool) {

	branch := cDim.Sprint("├─")
	leaf := cDim.Sprint("└─")
	for _, r := range rows {
		fmt.Println(cTitle.Sprint(r.IP))
		host := r.Host
		if host == "" {
			host = "-"
		}
		fmt.Printf("%s Host: %s\n", branch, host)
		up := cErr.Sprint("no")
		if r.Up {
			up = cOK.Sprint("yes")
		}
		fmt.Printf("%s Up: %s\n", branch, up)
		if showMac {
			fmt.Printf("%s MAC: %s\n", branch, dashStr(r.MAC))
		}
		if showMac && showVendors {
			fmt.Printf("%s Vendor: %s\n", branch, dashStr(r.Vendor))
		}
		if r.OS != "" {
			fmt.Printf("%s OS: %s\n", branch, r.OS)
		}
		if r.RTT != "" {
			fmt.Printf("%s RTT: %s\n", branch, r.RTT)
		}
		if len(r.PortDetails) == 0 {
			fmt.Printf("%s Ports: -\n", leaf)
		} else {
			fmt.Printf("%s Ports:\n", leaf)
			for i, p := range r.PortDetails {
				prefix := "   " + branch + " "
				if i == len(r.PortDetails)-1 {
					prefix = "   " + leaf + " "
				}
				label := fmt.Sprintf("%d/%s %s", p.Port, p.Proto, p.Service)
				if vl := p.VersionLabel(); vl != "" {
					label += " " + vl
				}
				out := prefix + cAccent.Sprint(label)
				if p.Risk != "" {
					out += "  " + sevColor(p.Severity).Sprint("⚠ "+p.Risk)
				}
				fmt.Println(out)
			}
		}
		fmt.Println()
	}
}

func dashStr(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// sevColor maps a risk severity string to its terminal color for CLI output.
func sevColor(severity string) text.Colors {
	switch severity {
	case "high":
		return cErr
	case "warn":
		return cWarn
	case "info":
		return cAccent
	default:
		return cDim
	}
}
