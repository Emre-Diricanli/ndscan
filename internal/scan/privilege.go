package scan

import (
	"context"
	"os"
	"os/exec"
	"time"
)

// IsRoot reports whether the process is already running as root, in which case
// nmap can do ARP discovery, SYN scans, and MAC reporting without sudo.
func IsRoot() bool { return os.Geteuid() == 0 }

// SudoAvailable reports whether the sudo binary exists on PATH.
func SudoAvailable() bool {
	_, err := exec.LookPath("sudo")
	return err == nil
}

// SudoPrimed reports whether sudo can run non-interactively right now
// (credentials cached from a recent authentication).
func SudoPrimed() bool {
	if IsRoot() {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "true").Run() == nil
}

// PrimeSudo runs an interactive `sudo -v` to cache credentials. It connects the
// real terminal so the password prompt is visible — callers MUST invoke this
// BEFORE a Bubble Tea alt-screen takes over, otherwise the prompt is hidden.
// Returns nil if already root or on successful authentication.
func PrimeSudo() error {
	if IsRoot() {
		return nil
	}
	cmd := exec.Command("sudo", "-v")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
