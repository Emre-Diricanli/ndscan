package topology

import (
	"fmt"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

func BenchmarkBuild(b *testing.B) {
	for _, n := range []int{256, 1024, 10000} {
		b.Run(fmt.Sprintf("hosts-%d", n), func(b *testing.B) {
			rows := make([]ui.Row, n)
			for i := range rows {
				rows[i] = ui.Row{IP: fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255), Up: true}
			}
			locals := []netinfo.Network{{Interface: "en0", CIDR: "10.0.0.0/8", Addr: "10.0.0.1"}}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = Build(rows, Input{Locals: locals, Gateway: netinfo.Gateway{IP: "10.0.0.254"}})
			}
		})
	}
}
