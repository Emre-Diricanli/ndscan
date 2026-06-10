package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

type Row struct {
	IP     string   `json:"ip"`
	MAC    string   `json:"mac,omitempty"`
	Vendor string   `json:"vendor,omitempty"`
	Host   string   `json:"hostname,omitempty"`
	OS     string   `json:"os,omitempty"` // best OS-detection guess (needs -A presets)
	Up     bool     `json:"up"`
	Ports  []string `json:"ports,omitempty"` // labels like "22/tcp ssh"
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
			if len(h.Hostnames.Names) > 0 {
				row.Host = h.Hostnames.Names[0].Name
			}
			row.OS = h.BestOSGuess()
			for _, p := range h.Ports.List {
				if p.State.State == "open" {
					label := fmt.Sprintf("%d/%s %s", p.PortID, p.Protocol, p.Service.Name)
					if p.Service.Product != "" {
						label += " " + p.Service.Product
					}
					if p.Service.Version != "" {
						label += " " + p.Service.Version
					}
					row.Ports = append(row.Ports, label)
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
	return rows
}

// PortNumber exposes the "22/tcp ssh" -> "22" reduction for table-style views.
func PortNumber(label string) string { return extractPortNumber(label) }

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
		m[k] = ex
	}
	out := make([]Row, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	// stable order (sort by IP)
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
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
	rows := flatten(res)

	// fill missing MACs from macMap (best-effort)
	if showMac && macMap != nil {
		for i := range rows {
			if rows[i].MAC == "" {
				if mac, ok := macMap[rows[i].IP]; ok {
					rows[i].MAC = mac
				}
			}
		}
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.Style().Format.Header = text.FormatDefault
	t.Style().Color.Header = cTitle
	if showMac {
		t.AppendHeader(table.Row{"IP", "MAC", "Vendor", "Host", "Up", "Open Ports"})
	} else {
		t.AppendHeader(table.Row{"IP", "Host", "Up", "Open Ports"})
	}

	for _, r := range rows {
		up := cErr.Sprint("✖ no")
		if r.Up {
			up = cOK.Sprint("✔ yes")
		}
		vend := ""
		if showMac && showVendors {
			vend = vendor.Lookup(db, r.MAC, "")
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
			t.AppendRow(table.Row{ip, mac, vend, host, up, ports})
		} else {
			t.AppendRow(table.Row{ip, host, up, ports})
		}
	}
	t.Render()
}

// Summarize returns the number of hosts that are up and the total count of
// open ports across all results, for the post-scan summary line.
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
	return os.WriteFile(path, b, 0644)
}

// ====== TREE (detailed labels) ======

func PrintTreeWithMACMap(res []scan.HostResult, db vendor.DB, showMac, showVendors bool, macMap map[string]string) {
	rows := flatten(res)

	// fill missing MACs from macMap (best-effort)
	if showMac && macMap != nil {
		for i := range rows {
			if rows[i].MAC == "" {
				if mac, ok := macMap[rows[i].IP]; ok {
					rows[i].MAC = mac
				}
			}
		}
	}

	type node struct {
		IP, Host, MAC, Vendor string
		Up                    bool
		Ports                 []string
	}
	byIP := map[string]*node{}
	order := []string{}
	for _, r := range rows {
		n, ok := byIP[r.IP]
		if !ok {
			n = &node{IP: r.IP, Host: r.Host, Up: r.Up, MAC: r.MAC}
			byIP[r.IP] = n
			order = append(order, r.IP)
		}
		if showMac && showVendors && n.Vendor == "" {
			n.Vendor = vendor.Lookup(db, r.MAC, "")
		}
		if len(r.Ports) > 0 {
			n.Ports = append(n.Ports, r.Ports...)
		}
	}

	// stable order
	sort.Strings(order)

	branch := cDim.Sprint("├─")
	leaf := cDim.Sprint("└─")
	for _, ip := range order {
		n := byIP[ip]
		fmt.Println(cTitle.Sprint(n.IP))
		host := n.Host
		if host == "" {
			host = "-"
		}
		fmt.Printf("%s Host: %s\n", branch, host)
		up := cErr.Sprint("no")
		if n.Up {
			up = cOK.Sprint("yes")
		}
		fmt.Printf("%s Up: %s\n", branch, up)
		if showMac {
			mac := n.MAC
			if mac == "" {
				mac = "-"
			}
			fmt.Printf("%s MAC: %s\n", branch, mac)
		}
		if showMac && showVendors {
			vend := n.Vendor
			if vend == "" {
				vend = "-"
			}
			fmt.Printf("%s Vendor: %s\n", branch, vend)
		}
		if len(n.Ports) == 0 {
			fmt.Printf("%s Ports: -\n", leaf)
		} else {
			fmt.Printf("%s Ports:\n", leaf)
			for i, p := range n.Ports {
				prefix := "   " + branch + " "
				if i == len(n.Ports)-1 {
					prefix = "   " + leaf + " "
				}
				fmt.Println(prefix + cAccent.Sprint(p))
			}
		}
		fmt.Println()
	}
}
