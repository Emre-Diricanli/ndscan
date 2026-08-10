package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CacheTTL is how long a "latest version" lookup stays valid. It keeps
// every-launch latency at zero and avoids hammering GitHub.
const CacheTTL = time.Hour

// Checker resolves the newest ndscan release and remembers lookups on disk.
type Checker struct {
	// BaseURL is the repo URL, e.g. https://github.com/Emre-Diricanli/ndscan.
	BaseURL string
	// CachePath is where lookups are persisted; empty disables caching.
	CachePath string
	// Now overrides the clock (tests). Defaults to time.Now.
	Now func() time.Time
	// Client overrides the HTTP client (tests). Defaults to http.DefaultClient.
	Client *http.Client
}

// NewChecker returns a Checker with production defaults: the real GitHub
// repo and a cache file in the ndscan config dir.
func NewChecker() *Checker {
	return &Checker{
		BaseURL:   "https://github.com/Emre-Diricanli/ndscan",
		CachePath: filepath.Join(configDir(), "update-check.json"),
	}
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return http.DefaultClient
}

// cache is the on-disk layout of update-check.json.
type cache struct {
	CheckedAt time.Time `json:"checked_at"`
	Latest    string    `json:"latest"`
	Declined  string    `json:"declined,omitempty"`
}

// configDir mirrors internal/config's location logic without importing it:
// NDSCAN_CONFIG_DIR wins, then NDSCAN_USER_CONFIG_DIR (set on sudo re-exec so
// root still uses the invoking user's config), then the OS user-config dir.
// Keeping this local avoids coupling the updater to the TUI's config package.
func configDir() string {
	if d := os.Getenv("NDSCAN_CONFIG_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("NDSCAN_USER_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "ndscan")
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "ndscan")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "ndscan")
}

func (c *Checker) readCache() cache {
	var ch cache
	if c.CachePath == "" {
		return ch
	}
	b, err := os.ReadFile(c.CachePath)
	if err != nil {
		return ch
	}
	_ = json.Unmarshal(b, &ch)
	// A cache we cannot replace must not be allowed to answer for us. Running
	// the tool once under sudo leaves this file owned by root, and from then on
	// every unprivileged run would read the version recorded that day and
	// suppress the check forever — the user simply stops being offered updates,
	// with nothing to indicate why. Treating it as absent costs one API call.
	if !c.cacheWritable() {
		return cache{}
	}
	return ch
}

// cacheWritable reports whether the cache file can actually be updated.
func (c *Checker) cacheWritable() bool {
	f, err := os.OpenFile(c.CachePath, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return os.IsNotExist(err) // absent is fine; it will be created
	}
	f.Close()
	return true
}

func (c *Checker) writeCache(ch cache) {
	if c.CachePath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.CachePath), 0o755); err != nil {
		return
	}
	b, err := json.MarshalIndent(ch, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(c.CachePath, b, 0o644) // best effort
}

// Check reports the latest release tag and whether it is newer than current.
// Results within CacheTTL are served from disk; a version the user declined
// (see Decline) never reports available. Any error means "couldn't check" —
// callers should treat that as silent and carry on.
func (c *Checker) Check(ctx context.Context, current string) (latest string, available bool, err error) {
	ch := c.readCache()
	if ch.Latest == "" || c.now().Sub(ch.CheckedAt) >= CacheTTL {
		tag, err := c.fetchLatest(ctx)
		if err != nil {
			return "", false, err
		}
		ch.Latest = tag
		ch.CheckedAt = c.now()
		c.writeCache(ch)
	}
	cmp, err := CompareVersions(current, ch.Latest)
	if err != nil {
		return ch.Latest, false, fmt.Errorf("comparing versions: %w", err)
	}
	available = cmp < 0 && ch.Latest != ch.Declined
	return ch.Latest, available, nil
}

// CachedLatest reports the newest release tag a previous check recorded,
// without contacting the network.
//
// It exists for `ndscan --version`, which Cobra answers before the startup
// update hook can run. That command must stay instant and script-safe, so it
// cannot afford a lookup — but it can repeat what the last one found, which is
// enough to point at `ndscan update`.
//
// ok is false when nothing has been cached yet, so a caller can stay silent
// rather than imply the running version is current. Declined versions are
// deliberately still reported: declining the startup prompt silences that
// prompt, not the answer to a direct question.
func CachedLatest() (string, bool) {
	ch := NewChecker().readCache()
	if ch.Latest == "" {
		return "", false
	}
	return ch.Latest, true
}

// Decline records a version the user chose to skip; Check will not report it
// as available again (a newer tag still will).
func (c *Checker) Decline(tag string) error {
	ch := c.readCache()
	ch.Declined = tag
	c.writeCache(ch)
	return nil
}

// fetchLatest resolves the newest release tag by following the
// /releases/latest redirect, exactly like install.sh — no API call, so no
// rate limit.
func (c *Checker) fetchLatest(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("checking for updates: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checking for updates: unexpected status %s", resp.Status)
	}
	// After redirects, the URL ends in /releases/tag/vX.Y.Z.
	tag := resp.Request.URL.Path[strings.LastIndex(resp.Request.URL.Path, "/")+1:]
	if !strings.HasPrefix(tag, "v") {
		return "", fmt.Errorf("could not determine latest release tag from %q", resp.Request.URL)
	}
	return tag, nil
}
