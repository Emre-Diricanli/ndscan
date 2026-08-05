package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		name    string
		current string
		latest  string
		want    int
	}{
		{"equal", "0.1.0", "0.1.0", 0},
		{"equal with v prefix", "0.1.0", "v0.1.0", 0},
		{"both v prefix", "v0.1.0", "v0.1.0", 0},
		{"patch newer", "0.1.0", "v0.1.1", -1},
		{"patch older", "0.1.2", "v0.1.1", 1},
		{"minor newer", "0.1.9", "v0.2.0", -1},
		{"major newer", "0.9.9", "v1.0.0", -1},
		{"multi-digit patch", "0.1.9", "v0.1.10", -1},
		{"multi-digit current", "0.1.10", "v0.1.9", 1},
		{"minor beats patch", "0.1.99", "v0.2.0", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CompareVersions(tc.current, tc.latest)
			if err != nil {
				t.Fatalf("CompareVersions(%q, %q) returned error: %v", tc.current, tc.latest, err)
			}
			if got != tc.want {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.current, tc.latest, got, tc.want)
			}
		})
	}
}

func TestCompareVersionsInvalid(t *testing.T) {
	for _, bad := range [][2]string{
		{"", "0.1.0"},
		{"0.1.0", "notaversion"},
		{"0.1", "0.1.0"},
		{"0.1.x", "0.1.0"},
	} {
		if _, err := CompareVersions(bad[0], bad[1]); err == nil {
			t.Errorf("CompareVersions(%q, %q) expected error, got nil", bad[0], bad[1])
		}
	}
}

// fakeGitHub serves the /releases/latest redirect like github.com does and
// counts how many times the redirect endpoint was hit. The tag is read
// through the pointer on every request, so tests can simulate a new release
// appearing upstream.
func fakeGitHub(t *testing.T, tag *string, hits *int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		http.Redirect(w, r, "/releases/tag/"+*tag, http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func testChecker(srv *httptest.Server, cachePath string) *Checker {
	return &Checker{BaseURL: srv.URL, CachePath: cachePath}
}

func TestCheckUpdateAvailable(t *testing.T) {
	var hits int32
	tag := "v9.9.9"
	srv := fakeGitHub(t, &tag, &hits)
	c := testChecker(srv, filepath.Join(t.TempDir(), "update-check.json"))

	latest, available, err := c.Check(context.Background(), "0.1.0")
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if !available {
		t.Error("expected available=true for newer latest")
	}
	if latest != "v9.9.9" {
		t.Errorf("latest = %q, want v9.9.9", latest)
	}
}

func TestCheckUpToDate(t *testing.T) {
	var hits int32
	tag := "v9.9.9"
	srv := fakeGitHub(t, &tag, &hits)
	c := testChecker(srv, filepath.Join(t.TempDir(), "update-check.json"))

	_, available, err := c.Check(context.Background(), "9.9.9")
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if available {
		t.Error("expected available=false when current == latest")
	}
}

func TestCheckCachesWithinTTL(t *testing.T) {
	var hits int32
	tag := "v9.9.9"
	srv := fakeGitHub(t, &tag, &hits)
	c := testChecker(srv, filepath.Join(t.TempDir(), "update-check.json"))

	if _, _, err := c.Check(context.Background(), "0.1.0"); err != nil {
		t.Fatalf("first Check: %v", err)
	}
	if _, _, err := c.Check(context.Background(), "0.1.0"); err != nil {
		t.Fatalf("second Check: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("server hit %d times, want 1 (second check should use cache)", got)
	}
}

func TestCheckRefetchesAfterTTL(t *testing.T) {
	var hits int32
	tag := "v9.9.9"
	srv := fakeGitHub(t, &tag, &hits)
	c := testChecker(srv, filepath.Join(t.TempDir(), "update-check.json"))
	now := time.Now()
	c.Now = func() time.Time { return now }

	if _, _, err := c.Check(context.Background(), "0.1.0"); err != nil {
		t.Fatalf("first Check: %v", err)
	}
	now = now.Add(2 * time.Hour)
	if _, _, err := c.Check(context.Background(), "0.1.0"); err != nil {
		t.Fatalf("second Check: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("server hit %d times, want 2 (stale cache should refetch)", got)
	}
}

func TestCheckDeclinedNotAvailable(t *testing.T) {
	var hits int32
	tag := "v9.9.9"
	srv := fakeGitHub(t, &tag, &hits)
	c := testChecker(srv, filepath.Join(t.TempDir(), "update-check.json"))

	if err := c.Decline("v9.9.9"); err != nil {
		t.Fatalf("Decline: %v", err)
	}
	_, available, err := c.Check(context.Background(), "0.1.0")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if available {
		t.Error("expected available=false for a declined version")
	}
}

func TestCheckNewerThanDeclinedIsAvailable(t *testing.T) {
	var hits int32
	tag := "v9.9.9"
	srv := fakeGitHub(t, &tag, &hits)
	c := testChecker(srv, filepath.Join(t.TempDir(), "update-check.json"))
	now := time.Now()
	c.Now = func() time.Time { return now }

	if err := c.Decline("v9.9.9"); err != nil {
		t.Fatalf("Decline: %v", err)
	}
	// A newer tag appears upstream, and the cache goes stale.
	tag = "v9.9.10"
	now = now.Add(2 * time.Hour)

	latest, available, err := c.Check(context.Background(), "0.1.0")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !available {
		t.Error("expected available=true when latest is newer than the declined version")
	}
	if latest != "v9.9.10" {
		t.Errorf("latest = %q, want v9.9.10", latest)
	}
}

func TestCheckNetworkError(t *testing.T) {
	tag := "v9.9.9"
	srv := fakeGitHub(t, &tag, new(int32))
	srv.Close() // nothing listening
	c := testChecker(srv, filepath.Join(t.TempDir(), "update-check.json"))

	if _, _, err := c.Check(context.Background(), "0.1.0"); err == nil {
		t.Error("expected error when the server is unreachable")
	}
}

// makeTarball builds a tar.gz in memory containing a single file, mimicking
// a GoReleaser archive (binary at the archive root).
func makeTarball(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// fakeRelease serves a tarball and checksums.txt for the given tag on the
// current platform, like a GitHub release page.
func fakeRelease(t *testing.T, tag string, tarball []byte, checksums string) *httptest.Server {
	t.Helper()
	ver := strings.TrimPrefix(tag, "v")
	asset := "ndscan_" + ver + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/download/"+tag+"/"+asset, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarball)
	})
	mux.HandleFunc("/releases/download/"+tag+"/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(checksums))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestDownloadAndReplace(t *testing.T) {
	newBin := []byte("#!/bin/sh\necho v9.9.9\n")
	tarball := makeTarball(t, "ndscan", newBin)
	sum := sha256.Sum256(tarball)
	ver := "9.9.9"
	asset := "ndscan_" + ver + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	checksums := hex.EncodeToString(sum[:]) + "  " + asset + "\n"
	srv := fakeRelease(t, "v"+ver, tarball, checksums)

	dir := t.TempDir()
	exe := filepath.Join(dir, "ndscan")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := &Checker{BaseURL: srv.URL}
	if err := c.DownloadAndReplace(context.Background(), "v"+ver, exe); err != nil {
		t.Fatalf("DownloadAndReplace: %v", err)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newBin) {
		t.Errorf("exe content = %q, want %q", got, newBin)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("exe is not executable after replace (mode %v)", info.Mode().Perm())
	}
}

func TestDownloadAndReplaceChecksumMismatch(t *testing.T) {
	tarball := makeTarball(t, "ndscan", []byte("new binary"))
	ver := "9.9.9"
	asset := "ndscan_" + ver + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	wrong := strings.Repeat("0", 64)
	srv := fakeRelease(t, "v"+ver, tarball, wrong+"  "+asset+"\n")

	dir := t.TempDir()
	exe := filepath.Join(dir, "ndscan")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := &Checker{BaseURL: srv.URL}
	if err := c.DownloadAndReplace(context.Background(), "v"+ver, exe); err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "old binary" {
		t.Errorf("old binary was modified despite mismatch: %q", got)
	}
}

func TestDownloadAndReplaceMissingChecksumEntry(t *testing.T) {
	tarball := makeTarball(t, "ndscan", []byte("new binary"))
	srv := fakeRelease(t, "v9.9.9", tarball, "")

	exe := filepath.Join(t.TempDir(), "ndscan")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &Checker{BaseURL: srv.URL}
	if err := c.DownloadAndReplace(context.Background(), "v9.9.9", exe); err == nil {
		t.Fatal("expected error for missing checksum entry, got nil")
	}
}

func TestDownloadAndReplaceUnwritableDir(t *testing.T) {
	newBin := []byte("new binary")
	tarball := makeTarball(t, "ndscan", newBin)
	sum := sha256.Sum256(tarball)
	ver := "9.9.9"
	asset := "ndscan_" + ver + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	srv := fakeRelease(t, "v"+ver, tarball, hex.EncodeToString(sum[:])+"  "+asset+"\n")

	dir := t.TempDir()
	exe := filepath.Join(dir, "ndscan")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	c := &Checker{BaseURL: srv.URL}
	if err := c.DownloadAndReplace(context.Background(), "v"+ver, exe); err == nil {
		t.Fatal("expected error for unwritable install dir, got nil")
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "old binary" {
		t.Errorf("old binary was modified despite failed replace: %q", got)
	}
}

// fakeGitHubFull serves both the /releases/latest redirect and the release
// assets, for exercising the full prompt-and-update flow.
func fakeGitHubFull(t *testing.T, tag string, tarball []byte, checksums string) *httptest.Server {
	t.Helper()
	ver := strings.TrimPrefix(tag, "v")
	asset := "ndscan_" + ver + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/"+tag, http.StatusFound)
	})
	mux.HandleFunc("/releases/tag/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/releases/download/"+tag+"/"+asset, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tarball)
	})
	mux.HandleFunc("/releases/download/"+tag+"/checksums.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(checksums))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func promptTestSetup(t *testing.T) (srv *httptest.Server, exe string, newBin []byte) {
	t.Helper()
	newBin = []byte("new binary")
	tarball := makeTarball(t, "ndscan", newBin)
	sum := sha256.Sum256(tarball)
	ver := "9.9.9"
	asset := "ndscan_" + ver + "_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	srv = fakeGitHubFull(t, "v"+ver, tarball, hex.EncodeToString(sum[:])+"  "+asset+"\n")
	exe = filepath.Join(t.TempDir(), "ndscan")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	return srv, exe, newBin
}

func TestMaybeUpdateNonInteractive(t *testing.T) {
	srv, exe, _ := promptTestSetup(t)
	var out bytes.Buffer
	MaybeUpdate(context.Background(), Options{
		In: strings.NewReader("y\n"), Out: &out, Current: "0.1.0",
		Interactive: false, ExePath: exe, Checker: &Checker{BaseURL: srv.URL},
	})
	if out.Len() != 0 {
		t.Errorf("expected silence when non-interactive, got %q", out.String())
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "old binary" {
		t.Error("binary changed despite non-interactive run")
	}
}

func TestMaybeUpdateEnvOptOut(t *testing.T) {
	t.Setenv("NDSCAN_NO_UPDATE_CHECK", "1")
	srv, exe, _ := promptTestSetup(t)
	var out bytes.Buffer
	MaybeUpdate(context.Background(), Options{
		In: strings.NewReader("y\n"), Out: &out, Current: "0.1.0",
		Interactive: true, ExePath: exe, Checker: &Checker{BaseURL: srv.URL},
	})
	if out.Len() != 0 {
		t.Errorf("expected silence with NDSCAN_NO_UPDATE_CHECK=1, got %q", out.String())
	}
}

func TestMaybeUpdateAnswerNo(t *testing.T) {
	srv, exe, _ := promptTestSetup(t)
	var out bytes.Buffer
	MaybeUpdate(context.Background(), Options{
		In: strings.NewReader("n\n"), Out: &out, Current: "0.1.0",
		Interactive: true, ExePath: exe,
		Checker: &Checker{BaseURL: srv.URL, CachePath: filepath.Join(t.TempDir(), "c.json")},
	})
	if !strings.Contains(out.String(), "v9.9.9") {
		t.Errorf("prompt should mention the new version, got %q", out.String())
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "old binary" {
		t.Error("binary changed after answering no")
	}
}

func TestMaybeUpdateAnswerSkip(t *testing.T) {
	srv, exe, _ := promptTestSetup(t)
	cachePath := filepath.Join(t.TempDir(), "c.json")
	checker := &Checker{BaseURL: srv.URL, CachePath: cachePath}
	var out bytes.Buffer
	MaybeUpdate(context.Background(), Options{
		In: strings.NewReader("s\n"), Out: &out, Current: "0.1.0",
		Interactive: true, ExePath: exe, Checker: checker,
	})
	got, _ := os.ReadFile(exe)
	if string(got) != "old binary" {
		t.Error("binary changed after answering skip")
	}
	// A second run must not prompt again for the same version.
	var out2 bytes.Buffer
	MaybeUpdate(context.Background(), Options{
		In: strings.NewReader("y\n"), Out: &out2, Current: "0.1.0",
		Interactive: true, ExePath: exe, Checker: checker,
	})
	if strings.Contains(out2.String(), "Update now?") {
		t.Errorf("declined version was re-prompted: %q", out2.String())
	}
}

func TestMaybeUpdateAnswerYes(t *testing.T) {
	srv, exe, newBin := promptTestSetup(t)
	execCalled := false
	var out bytes.Buffer
	MaybeUpdate(context.Background(), Options{
		In: strings.NewReader("y\n"), Out: &out, Current: "0.1.0",
		Interactive: true, ExePath: exe,
		Checker: &Checker{BaseURL: srv.URL, CachePath: filepath.Join(t.TempDir(), "c.json")},
		Exec:    func() error { execCalled = true; return nil },
	})
	got, _ := os.ReadFile(exe)
	if !bytes.Equal(got, newBin) {
		t.Errorf("exe content = %q, want %q", got, newBin)
	}
	if !execCalled {
		t.Error("Exec was not called after a successful update")
	}
}

func TestMaybeUpdateUpToDateSilent(t *testing.T) {
	srv, exe, _ := promptTestSetup(t)
	var out bytes.Buffer
	MaybeUpdate(context.Background(), Options{
		In: strings.NewReader("y\n"), Out: &out, Current: "9.9.9",
		Interactive: true, ExePath: exe,
		Checker: &Checker{BaseURL: srv.URL, CachePath: filepath.Join(t.TempDir(), "c.json")},
	})
	if out.Len() != 0 {
		t.Errorf("expected silence when up to date, got %q", out.String())
	}
}

func TestMaybeUpdateElevatedSkip(t *testing.T) {
	t.Setenv("NDSCAN_ELEVATED", "1")
	srv, exe, _ := promptTestSetup(t)
	var out bytes.Buffer
	MaybeUpdate(context.Background(), Options{
		In: strings.NewReader("y\n"), Out: &out, Current: "0.1.0",
		Interactive: true, ExePath: exe, Checker: &Checker{BaseURL: srv.URL},
	})
	if out.Len() != 0 {
		t.Errorf("expected silence when elevated (parent already prompted), got %q", out.String())
	}
}

func TestConfigDirUserConfigDirOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NDSCAN_USER_CONFIG_DIR", dir)
	// NDSCAN_CONFIG_DIR wins when both are set.
	t.Setenv("NDSCAN_CONFIG_DIR", "")
	if got := configDir(); got != filepath.Join(dir, "ndscan") {
		t.Errorf("configDir() = %q, want %q", got, filepath.Join(dir, "ndscan"))
	}
}
