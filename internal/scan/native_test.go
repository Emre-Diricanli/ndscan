package scan

import "testing"

// Native discovery probes from the local machine, so it must not be used when
// the runner points at a remote host — those probes would hit the wrong network.
func TestNativeDiscoverySupported(t *testing.T) {
	if !NativeDiscoverySupported(LocalRunner{}) {
		t.Error("local runner should support native discovery")
	}
	if NativeDiscoverySupported(&SSHRunner{Target: "user@host"}) {
		t.Error("SSH runner must NOT use native discovery (probes originate locally)")
	}
}
