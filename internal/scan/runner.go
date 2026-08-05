package scan

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Runner abstracts how we execute commands (locally or over SSH).
type Runner interface {
	Run(ctx context.Context, bin string, args ...string) ([]byte, error)
}

// ----- Local runner -----

type LocalRunner struct{}

// NewRunner returns a local runner (optionally elevated) or an SSH runner.
func NewRunner(sshTarget string) Runner {
	if sshTarget == "" {
		return LocalRunner{}
	}
	return &SSHRunner{Target: sshTarget}
}

func NewLocalRunner() Runner { return LocalRunner{} }

func (r LocalRunner) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	if bin == "nmap" {
		if path := os.Getenv("NDSCAN_NMAP_PATH"); path != "" {
			bin = path
		}
	}
	// Startup authenticates sudo once. Execute every local probe through its
	// non-interactive path as a final privilege boundary; this guarantees tools
	// such as nmap see a real root execution context on macOS without another
	// prompt, even when the elevated Go launcher retains unusual credentials.
	name := bin
	commandArgs := args
	if os.Getenv("NDSCAN_ELEVATED") == "1" {
		name = "sudo"
		commandArgs = append([]string{"-n", "--", bin}, args...)
	}
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, name, commandArgs...)
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s failed: %v\nstderr: %s\nstdout: %s", bin, err, errb.String(), out.String())
	}
	return out.Bytes(), nil
}

func nmapExecutable() (string, error) {
	if path := os.Getenv("NDSCAN_NMAP_PATH"); path != "" {
		return path, nil
	}
	return exec.LookPath("nmap")
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
		"-o", "ControlMaster=auto",
		"-o", "ControlPersist=60",
		"-o", "ControlPath=/tmp/ndscan-ssh-%C",
		"--",
		r.Target,
		remoteCommand(bin, args...),
	}
	var out, errb bytes.Buffer
	name := "ssh"
	commandArgs := sshArgs
	// The scanner runs as root, but remote authentication should continue to
	// use the invoking user's SSH config and keys rather than root's identity.
	if user := os.Getenv("SUDO_USER"); os.Geteuid() == 0 && user != "" && user != "root" {
		name = "sudo"
		commandArgs = append([]string{"-H", "-u", user, "--", "ssh"}, sshArgs...)
	}
	cmd := exec.CommandContext(ctx, name, commandArgs...)
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
