package update

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Options controls a MaybeUpdate run. The zero Checker uses production
// defaults; tests inject a fake one.
type Options struct {
	In          io.Reader // where the prompt answer is read (os.Stdin)
	Out         io.Writer // where prompts and status go (os.Stderr)
	Current     string    // running version, e.g. "0.1.0"
	Interactive bool      // false → no-op (scripts, pipes)
	ExePath     string    // binary to replace; defaults to os.Executable()
	Exec        func() error
	Checker     *Checker
}

// MaybeUpdate is the startup hook: if a newer release exists and the session
// is interactive, offer to self-update. It never blocks for more than the
// check timeout, never fails the host command, and stays silent when
// everything is fine. Set NDSCAN_NO_UPDATE_CHECK=1 to disable entirely.
func MaybeUpdate(ctx context.Context, opts Options) {
	if !opts.Interactive || os.Getenv("NDSCAN_NO_UPDATE_CHECK") != "" {
		return
	}
	// A sudo-relaunched scan runs after the unprivileged parent already had
	// its chance to prompt; asking again (and writing a root-owned cache into
	// the user's config dir) would be a nuisance.
	if os.Getenv("NDSCAN_ELEVATED") != "" {
		return
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return // no release artifacts for other platforms
	}
	checker := opts.Checker
	if checker == nil {
		checker = NewChecker()
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	latest, available, err := checker.Check(ctx, opts.Current)
	if err != nil || !available {
		return // silent: offline, rate-limited, or already current
	}

	out := opts.Out
	fmt.Fprintf(out, "\nndscan %s is available (you have v%s). Update now? [y/N/s] ", latest, strings.TrimPrefix(opts.Current, "v"))
	answer, _ := bufio.NewReader(opts.In).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		exe := opts.ExePath
		if exe == "" {
			if resolved, err := os.Executable(); err == nil {
				exe = resolved
			}
		}
		fmt.Fprintf(out, "Downloading and verifying %s…\n", latest)
		if err := checker.DownloadAndReplace(ctx, latest, exe); err != nil {
			fmt.Fprintf(out, "Update failed: %v\nContinuing with v%s.\n", err, strings.TrimPrefix(opts.Current, "v"))
			return
		}
		fmt.Fprintf(out, "Updated to %s — restarting…\n\n", latest)
		if opts.Exec != nil {
			if err := opts.Exec(); err != nil {
				fmt.Fprintf(out, "Restart failed (%v) — please re-run ndscan.\n", err)
			}
		}
	case "s", "skip":
		_ = checker.Decline(latest)
		fmt.Fprintf(out, "OK — won't ask about %s again.\n", latest)
	default:
		fmt.Fprintln(out, "Skipping update.")
	}
}

// Reexec replaces the running process with the updated binary, preserving
// the original arguments and environment. Unix-only by design (ndscan ships
// darwin/linux only); on success it never returns.
func Reexec() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return syscall.Exec(exe, os.Args, os.Environ())
}
