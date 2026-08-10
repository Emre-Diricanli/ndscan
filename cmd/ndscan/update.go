package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/update"
)

// updateCheckTimeout bounds the version lookup. Generous next to the startup
// hook's budget: the user typed this command and is waiting for its answer,
// where the hook is a side errand nobody asked for.
const updateCheckTimeout = 20 * time.Second

// updateDownloadTimeout covers a multi-megabyte fetch over a slow link.
const updateDownloadTimeout = 5 * time.Minute

// updateHint returns the trailing line for `ndscan --version`, naming a newer
// release when one is already known.
//
// Cobra handles --version before PersistentPreRun, so the startup update hook
// never runs for it: the command people type to ask "am I current?" was the
// one that could not say. This closes that gap without changing what --version
// costs or emits.
//
// Deliberately cache-only. A network round trip would make a command expected
// to return instantly hang on a slow link, and --version is scripted often
// enough that the risk is not worth a fresher answer. Whatever the last check
// learned is enough to say "run ndscan update", which does look properly.
//
// Returns "" — leaving the output byte-identical to before — when nothing is
// cached, when the cache is current, or when stderr is not a terminal. The
// string is a template suffix rendered to Cobra's output, so it must stay
// empty for scripts.
func updateHint(current string) string {
	if !ui.Interactive || os.Getenv("NDSCAN_NO_UPDATE_CHECK") != "" {
		return ""
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return ""
	}
	latest, ok := update.CachedLatest()
	if !ok {
		return ""
	}
	if cmp, err := update.CompareVersions(current, latest); err != nil || cmp >= 0 {
		return ""
	}
	return fmt.Sprintf("%s is available — run: ndscan update\n", latest)
}

// newUpdateCmd builds `ndscan update`.
//
// The startup hook already offers updates, but only from a real terminal, only
// once per cache interval, and never for a version the user has declined —
// three ways to end up on an old build with no way to ask. Asking is what this
// command is: it always checks live and always ignores a past decline, because
// running it *is* changing your mind.
func newUpdateCmd(version string) *cobra.Command {
	var checkOnly bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update ndscan to the latest release",
		Long: `Check for a newer ndscan release and install it in place.

The running binary is replaced only after the download is verified against the
release's published checksums. Use --check to report what is available without
installing anything.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
				return fmt.Errorf("no release binaries are published for %s; build from source instead", runtime.GOOS)
			}

			checker := update.NewChecker()
			// Empty CachePath disables the cache entirely, so an explicit
			// request always asks GitHub. A user running `ndscan update`
			// minutes after a release must not be told they are current
			// because a lookup from earlier in the hour is still warm.
			checker.CachePath = ""

			ctx, cancel := context.WithTimeout(cmd.Context(), updateCheckTimeout)
			latest, available, err := checker.Check(ctx, version)
			cancel()
			if err != nil {
				return fmt.Errorf("checking for updates: %w", err)
			}

			if !available {
				ui.Infof("ndscan %s is the latest release.", latest)
				return nil
			}
			if checkOnly {
				ui.Infof("ndscan %s is available (you have v%s).", latest, version)
				ui.Infof("Install it with: ndscan update")
				return nil
			}

			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("locating the ndscan binary to replace: %w", err)
			}

			ui.Infof("Downloading and verifying %s…", latest)
			dlCtx, dlCancel := context.WithTimeout(cmd.Context(), updateDownloadTimeout)
			defer dlCancel()
			if err := checker.DownloadAndReplace(dlCtx, latest, exe); err != nil {
				// Replacing a binary in /usr/local/bin needs write access the
				// user may not have, and "permission denied" alone does not
				// say which path to fix.
				return fmt.Errorf("updating %s: %w", exe, err)
			}
			ui.Infof("Updated to %s (%s)", latest, exe)
			return nil
		},
	}

	cmd.Flags().BoolVar(&checkOnly, "check", false, "report whether an update exists, without installing it")
	return cmd
}
