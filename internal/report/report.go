// Package report renders scan results into shareable Markdown and HTML
// documents, surfacing the service/version/TLS/risk intel that the table and
// tree views keep compact. Both formats are built from the same Report struct
// so they stay in sync.
package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// Report is the input to the renderers: the scanned rows plus context.
type Report struct {
	Targets   string // e.g. "192.168.86.0/24"
	Preset    string // quick|default|udp|deep
	Generated string // caller-supplied human-readable timestamp
	Rows      []ui.Row
}

// Finding is one host/port flagged by the risk engine, for the exposure list.
type Finding struct {
	IP       string
	Host     string
	Port     int
	Service  string
	Severity string
	Reason   string
}

// stats summarizes the rows for the report header.
type stats struct {
	hostsUp   int
	openPorts int
	flagged   int // hosts with at least one warn/high port
	highCount int
	warnCount int
	infoCount int
}

func summarize(rows []ui.Row) (stats, []Finding) {
	var s stats
	var findings []Finding
	for _, r := range rows {
		if r.Up {
			s.hostsUp++
		}
		s.openPorts += len(r.PortDetails)
		hostFlagged := false
		for _, p := range r.PortDetails {
			switch p.Severity {
			case "high":
				s.highCount++
			case "warn":
				s.warnCount++
			case "info":
				s.infoCount++
			}
			if p.Severity == "high" || p.Severity == "warn" {
				hostFlagged = true
				findings = append(findings, Finding{
					IP: r.IP, Host: r.Host, Port: p.Port,
					Service: p.Service, Severity: p.Severity, Reason: p.Risk,
				})
			}
		}
		if hostFlagged {
			s.flagged++
		}
	}
	// Sort findings high-first, then by IP/port for stable output.
	sevRank := map[string]int{"high": 0, "warn": 1}
	sort.SliceStable(findings, func(i, j int) bool {
		if sevRank[findings[i].Severity] != sevRank[findings[j].Severity] {
			return sevRank[findings[i].Severity] < sevRank[findings[j].Severity]
		}
		if findings[i].IP != findings[j].IP {
			return findings[i].IP < findings[j].IP
		}
		return findings[i].Port < findings[j].Port
	})
	return s, findings
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// portSummary renders a host's open ports as a compact one-liner for tables.
func portSummary(r ui.Row) string {
	if len(r.PortDetails) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(r.PortDetails))
	for _, p := range r.PortDetails {
		label := fmt.Sprintf("%d/%s", p.Port, p.Proto)
		if p.Service != "" {
			label += " " + p.Service
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, ", ")
}
