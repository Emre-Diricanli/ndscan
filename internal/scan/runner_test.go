package scan

import (
	"strings"
	"testing"
)

func TestRemoteCommandQuotesShellMetacharacters(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{name: "semicolon", arg: "host; touch /tmp/pwned", want: "'host; touch /tmp/pwned'"},
		{name: "pipe", arg: "host|cat /etc/passwd", want: "'host|cat /etc/passwd'"},
		{name: "ampersand", arg: "host&whoami", want: "'host&whoami'"},
		{name: "dollar", arg: "host$HOME", want: "'host$HOME'"},
		{name: "backtick", arg: "host`whoami`", want: "'host`whoami`'"},
		{name: "newline", arg: "host\ntouch /tmp/pwned", want: "'host\ntouch /tmp/pwned'"},
		{name: "single quote", arg: "host'quote", want: "'host'\"'\"'quote'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := remoteCommand("nmap", "-sn", "-oG", "-", tt.arg)
			want := "'nmap' '-sn' '-oG' '-' " + tt.want
			if got != want {
				t.Fatalf("remote command:\n got: %q\nwant: %q", got, want)
			}
			if strings.Contains(got, " nmap ") {
				t.Fatal("binary unexpectedly left unquoted")
			}
		})
	}
}

func TestShellQuoteEmptyArgument(t *testing.T) {
	if got, want := shellQuote(""), "''"; got != want {
		t.Fatalf("shellQuote(empty) = %q, want %q", got, want)
	}
}
