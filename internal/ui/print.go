package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

type Row struct {
	IP     string   `json:"ip"`
	MAC    string   `json:"mac,omitempty"`
	Vendor string   `json:"vendor,omitempty"`
	Host   string   `json:"hostname,omitempty"`
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
			for _, p := range h.Ports.List {
				if p.State.State == "open" {
					label := fmt.Sprintf("%d/%s %s", p.PortID, p.Protocol, p.Service.Name)
					if p.Service.Product != "" {
						label += " " + p.Service.Product
					}
					row.Ports = append(row.Ports, label)
				}
			}
			out = append(out, row)
		}
	}
	return mergePorts(out)
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
	if showMac {
		t.AppendHeader(table.Row{"IP", "MAC", "Vendor", "Host", "Up", "Open Ports"})
	} else {
		t.AppendHeader(table.Row{"IP", "Host", "Up", "Open Ports"})
	}

	for _, r := range rows {
		up := "no"
		if r.Up {
			up = "yes"
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
		ports := strings.Join(justNums, ", ")

		if showMac {
			t.AppendRow(table.Row{r.IP, r.MAC, vend, r.Host, up, ports})
		} else {
			t.AppendRow(table.Row{r.IP, r.Host, up, ports})
		}
	}
	t.Render()
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

	for _, ip := range order {
		n := byIP[ip]
		fmt.Println(n.IP)
		host := n.Host
		if host == "" {
			host = "-"
		}
		fmt.Printf("├─ Host: %s\n", host)
		up := "no"
		if n.Up {
			up = "yes"
		}
		fmt.Printf("├─ Up: %s\n", up)
		if showMac {
			mac := n.MAC
			if mac == "" {
				mac = "-"
			}
			fmt.Printf("├─ MAC: %s\n", mac)
		}
		if showMac && showVendors {
			vend := n.Vendor
			if vend == "" {
				vend = "-"
			}
			fmt.Printf("├─ Vendor: %s\n", vend)
		}
		if len(n.Ports) == 0 {
			fmt.Println("└─ Ports: -")
		} else {
			fmt.Println("└─ Ports:")
			for i, p := range n.Ports {
				isLast := i == len(n.Ports)-1
				prefix := "   ├─ "
				if isLast {
					prefix = "   └─ "
				}
				fmt.Println(prefix + p)
			}
		}
		fmt.Println()
	}
}
