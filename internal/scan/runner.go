package scan

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// Runner abstracts how we execute commands (locally or over SSH).
type Runner interface {
	Run(ctx context.Context, bin string, args ...string) ([]byte, error)
}

// ----- Local runner -----

type LocalRunner struct{}

func NewRunner(sshTarget string) Runner {
	if sshTarget == "" {
		return LocalRunner{}
	}
	return &SSHRunner{Target: sshTarget}
}

func (LocalRunner) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s failed: %v\nstderr: %s", bin, err, errb.String())
	}
	return out.Bytes(), nil
}

// ----- SSH runner -----
// Executes: ssh <target> -- <bin> <args...>
// Using "--" avoids remote shell interpretation and passes raw argv to the remote process.
type SSHRunner struct {
	Target string // user@host (or host if agent configured)
}

func (r *SSHRunner) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	sshArgs := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		r.Target,
		"--",
		bin,
	}
	sshArgs = append(sshArgs, args...)
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, "ssh", sshArgs...)
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ssh to %s failed: %v\nstderr: %s", r.Target, err, errb.String())
	}
	return out.Bytes(), nil
}
