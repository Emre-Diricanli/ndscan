package report

import (
	"strings"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

func TestMdCell(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "ssh", "ssh"},
		{"pipe escaped", "a|b", `a\|b`},
		{"newline collapsed", "a\nb", "a b"},
		{"crlf collapsed once", "a\r\nb", "a b"},
		{"backtick escaped", "a`b", "a\\`b"},
		{"brackets escaped", "a[b]c", `a\[b\]c`},
		{"utf-8 unchanged", "café — 中文", "café — 中文"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mdCell(tc.in); got != tc.want {
				t.Errorf("mdCell(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMarkdown_EscapesHostileValues(t *testing.T) {
	r := Report{
		Generated: "now",
		Rows: []ui.Row{{
			IP: "10.0.0.9", Host: "evil|host\nname", Up: true,
			OS: "Linux `5.X`", OSAccuracy: 92,
			PortDetails: []ui.PortInfo{{
				Port: 23, Proto: "tcp", Service: "tel|net",
				Product: "Tel`net`", Version: "1\n2",
				HTTPTitle: "click [here](http://x)",
				Severity:  "high", Risk: "cleartext | indeed",
			}},
		}},
	}
	md := r.Markdown()

	// Table rows must keep their shape: exposure has 5 columns (6 pipes),
	// hosts has 7 (8 pipes) — anything else means a value broke the table.
	for _, line := range strings.Split(md, "\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		switch got := strings.Count(strings.ReplaceAll(line, `\|`, ""), "|"); got {
		case 6, 8:
		default:
			t.Errorf("table row has %d unescaped pipes: %q", got, line)
		}
	}

	for _, want := range []string{
		`evil\|host name`,     // pipe escaped, newline collapsed
		`tel\|net`,            // service in exposure table
		`cleartext \| indeed`, // reason in exposure table
		"Linux \\`5.X\\` (92%)",
		"Tel\\`net\\` 1 2", // version label inline
		`click \[here\](http://x)`,
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing escaped form %q", want)
		}
	}
	// No table line may contain a raw hostile value.
	for _, line := range strings.Split(md, "\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		for _, bad := range []string{"evil|host", "tel|net", "cleartext | indeed", "Linux `5.X`"} {
			if strings.Contains(line, bad) {
				t.Errorf("table row contains unescaped value %q: %q", bad, line)
			}
		}
	}
	// Inline sections must not contain raw formatting injection either.
	for _, bad := range []string{"Tel`net`", "[here]"} {
		if strings.Contains(md, bad) {
			t.Errorf("markdown contains unescaped value %q", bad)
		}
	}
}
