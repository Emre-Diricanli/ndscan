package userenv

import "testing"

func TestHomeUsesInvokingUserOverride(t *testing.T) {
	t.Setenv("NDSCAN_USER_HOME", "/tmp/ndscan-user")
	if got := Home(); got != "/tmp/ndscan-user" {
		t.Fatalf("Home() = %q", got)
	}
}

func TestChownWithoutOriginalIDsIsNoOp(t *testing.T) {
	t.Setenv("NDSCAN_USER_UID", "")
	t.Setenv("NDSCAN_USER_GID", "")
	if err := Chown("/path/does/not/exist"); err != nil {
		t.Fatal(err)
	}
}
