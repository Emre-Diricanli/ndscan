package scan

import (
	"context"
	"reflect"
	"testing"
	"time"
)

type fakeRunner struct {
	bin  string
	args []string
	out  []byte
	err  error
}

func (r *fakeRunner) Run(_ context.Context, bin string, args ...string) ([]byte, error) {
	r.bin = bin
	r.args = append([]string(nil), args...)
	return r.out, r.err
}

func TestScanOneNmapArgs(t *testing.T) {
	tests := []struct {
		name   string
		preset string
		useSYN bool
		ports  string
		want   []string
	}{
		{name: "quick connect", preset: "quick", want: []string{"-oX", "-", "-Pn", "-sT", "-T4", "--top-ports", "100", "--host-timeout", "20s", "--max-retries", "0", "--min-rate", "1000", "192.0.2.1"}},
		{name: "quick SYN", preset: "quick", useSYN: true, want: []string{"-oX", "-", "-Pn", "-sS", "-T4", "--top-ports", "100", "--host-timeout", "20s", "--max-retries", "0", "--min-rate", "1000", "192.0.2.1"}},
		{name: "quick explicit ports", preset: "quick", ports: "22,80", want: []string{"-oX", "-", "-Pn", "-sT", "-T4", "-p", "22,80", "--host-timeout", "20s", "--max-retries", "0", "--min-rate", "1000", "192.0.2.1"}},
		{name: "quick SYN explicit ports", preset: "quick", useSYN: true, ports: "22,80", want: []string{"-oX", "-", "-Pn", "-sS", "-T4", "-p", "22,80", "--host-timeout", "20s", "--max-retries", "0", "--min-rate", "1000", "192.0.2.1"}},
		{name: "default connect", preset: "default", want: []string{"-oX", "-", "-Pn", "-sT", "-T4", "-A", "--host-timeout", "20s", "--max-retries", "2", "--min-rate", "200", "192.0.2.1"}},
		{name: "default SYN", preset: "default", useSYN: true, want: []string{"-oX", "-", "-Pn", "-sS", "-T4", "-A", "--host-timeout", "20s", "--max-retries", "2", "--min-rate", "200", "192.0.2.1"}},
		{name: "default explicit ports", preset: "default", ports: "22,80", want: []string{"-oX", "-", "-Pn", "-sT", "-T4", "-A", "-p", "22,80", "--host-timeout", "20s", "--max-retries", "2", "--min-rate", "200", "192.0.2.1"}},
		{name: "default SYN explicit ports", preset: "default", useSYN: true, ports: "22,80", want: []string{"-oX", "-", "-Pn", "-sS", "-T4", "-A", "-p", "22,80", "--host-timeout", "20s", "--max-retries", "2", "--min-rate", "200", "192.0.2.1"}},
		{name: "udp ignores UseSYN off", preset: "udp", want: []string{"-oX", "-", "-Pn", "-sU", "-T4", "--host-timeout", "20s", "--max-retries", "0", "--min-rate", "1000", "192.0.2.1"}},
		{name: "udp ignores UseSYN on", preset: "udp", useSYN: true, want: []string{"-oX", "-", "-Pn", "-sU", "-T4", "--host-timeout", "20s", "--max-retries", "0", "--min-rate", "1000", "192.0.2.1"}},
		{name: "udp explicit ports", preset: "udp", ports: "53,161", want: []string{"-oX", "-", "-Pn", "-sU", "-T4", "-p", "53,161", "--host-timeout", "20s", "--max-retries", "0", "--min-rate", "1000", "192.0.2.1"}},
		{name: "udp UseSYN explicit ports", preset: "udp", useSYN: true, ports: "53,161", want: []string{"-oX", "-", "-Pn", "-sU", "-T4", "-p", "53,161", "--host-timeout", "20s", "--max-retries", "0", "--min-rate", "1000", "192.0.2.1"}},
		{name: "deep connect", preset: "deep", want: []string{"-oX", "-", "-Pn", "-sT", "-T4", "-A", "-p", "1-65535", "--host-timeout", "20s", "--max-retries", "2", "--min-rate", "200", "192.0.2.1"}},
		{name: "deep SYN", preset: "deep", useSYN: true, want: []string{"-oX", "-", "-Pn", "-sS", "-T4", "-A", "-p", "1-65535", "--host-timeout", "20s", "--max-retries", "2", "--min-rate", "200", "192.0.2.1"}},
		{name: "deep explicit ports", preset: "deep", ports: "1-1024", want: []string{"-oX", "-", "-Pn", "-sT", "-T4", "-A", "-p", "1-1024", "--host-timeout", "20s", "--max-retries", "2", "--min-rate", "200", "192.0.2.1"}},
		{name: "deep SYN explicit ports", preset: "deep", useSYN: true, ports: "1-1024", want: []string{"-oX", "-", "-Pn", "-sS", "-T4", "-A", "-p", "1-1024", "--host-timeout", "20s", "--max-retries", "2", "--min-rate", "200", "192.0.2.1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := &fakeRunner{}
			_, err := scanOne(context.Background(), "192.0.2.1", Config{
				Preset: tt.preset, Ports: tt.ports, UseSYN: tt.useSYN, HostTimeout: 20 * time.Second,
			}, runner)
			if err != nil {
				t.Fatalf("scanOne returned error: %v", err)
			}
			if runner.bin != "nmap" {
				t.Fatalf("binary = %q, want nmap", runner.bin)
			}
			if !reflect.DeepEqual(runner.args, tt.want) {
				t.Fatalf("args:\n got: %#v\nwant: %#v", runner.args, tt.want)
			}
		})
	}
}
