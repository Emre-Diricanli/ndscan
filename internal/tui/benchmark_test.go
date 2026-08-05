package tui

import (
	"fmt"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

func BenchmarkResultViews(b *testing.B) {
	for _, n := range []int{256, 1024} {
		rows := make([]ui.Row, n)
		for i := range rows {
			rows[i] = ui.Row{IP: fmt.Sprintf("10.0.%d.%d", (i>>8)&255, i&255), Host: fmt.Sprintf("host-%d", i), Up: true,
				Ports: []string{"22/tcp ssh", "443/tcp https"}, PortDetails: []ui.PortInfo{{Port: 22, Severity: "info"}, {Port: 443}}}
		}
		b.Run(fmt.Sprintf("table-%d", n), func(b *testing.B) {
			m := New("bench")
			m.width, m.height, m.screen, m.rows = 140, 45, screenResults, rows
			b.ReportAllocs()
			for range b.N {
				m.rebuildTable()
			}
		})
		b.Run(fmt.Sprintf("topology-%d", n), func(b *testing.B) {
			m := New("bench")
			m.width, m.height, m.screen, m.rows, m.view = 140, 45, screenResults, rows, viewTopology
			m.netLocals = []netinfo.Network{{Interface: "en0", CIDR: "10.0.0.0/16", Addr: "10.0.0.1"}}
			m.rebuildTable()
			b.ResetTimer()
			b.ReportAllocs()
			for range b.N {
				m.mapDirty = true
				m.refreshMap()
			}
		})
	}
}
