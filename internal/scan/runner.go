package scan

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Runner abstracts how we execute commands (locally or over SSH).
type Runner interface {
	Run(ctx context.Context, bin string, args ...string) ([]byte, error)
}

// ----- Local runner -----

type LocalRunner struct {
	// Sudo, when true, prefixes commands with `sudo -n` so nmap can use ARP
	// host discovery, SYN scans, and report MACs. Requires sudo to already be
	// authenticated (see PrimeSudo); -n never prompts, so an unprimed sudo
	// fails fast rather than hanging the UI.
	Sudo bool
}

// NewRunner returns a local runner (optionally elevated) or an SSH runner.
func NewRunner(sshTarget string) Runner {
	if sshTarget == "" {
		return LocalRunner{}
	}
	return &SSHRunner{Target: sshTarget}
}

// NewLocalRunner returns a local runner that elevates via sudo when requested.
func NewLocalRunner(sudo bool) Runner { return LocalRunner{Sudo: sudo} }

func (r LocalRunner) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	name := bin
	full := args
	if r.Sudo {
		name = "sudo"
		full = append([]string{"-n", bin}, args...)
	}
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, name, full...)
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s failed: %v\nstderr: %s", bin, err, errb.String())
	}
	return out.Bytes(), nil
}

// ----- SSH runner -----
// Executes: ssh [options] -- <target> <quoted remote command>.
// The local exec uses an argv and "--" protects the destination from local ssh
// option parsing. SSH still hands the remote command to the remote login shell,
// so every remote argument is single-quoted before the command is passed to ssh.
// The input source is whoever supplies ndscan's target string; this quoting is
// defense-in-depth for wrapper scripts and CI, not a remote-attacker boundary.
type SSHRunner struct {
	Target string // user@host (or host if agent configured)
}

func (r *SSHRunner) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	sshArgs := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"--",
		r.Target,
		remoteCommand(bin, args...),
	}
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, "ssh", sshArgs...)
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ssh to %s failed: %v\nstderr: %s", r.Target, err, errb.String())
	}
	return out.Bytes(), nil
}

// remoteCommand constructs the single command string that ssh sends to the
// remote login shell. Each argv element is quoted independently so shell
// metacharacters remain literal data.
func remoteCommand(bin string, args ...string) string {
	quoted := make([]string, 0, len(args)+1)
	quoted = append(quoted, shellQuote(bin))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

// shellQuote returns a POSIX-shell single-quoted word. A literal quote is
// represented by ending the quoted word, emitting a quoted quote, and
// reopening it: ' becomes '"'"'.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
