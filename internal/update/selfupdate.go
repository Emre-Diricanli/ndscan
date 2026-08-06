package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// maxDownload caps the tarball and checksums reads so a hostile or broken
// server can't exhaust memory.
const maxDownload = 100 << 20 // 100 MiB

// DownloadAndReplace fetches the release tarball for tag, verifies it
// against the release's checksums.txt, and atomically replaces the binary
// at exePath. The old binary is left untouched unless the new one is fully
// downloaded, verified, and ready to swap in.
func (c *Checker) DownloadAndReplace(ctx context.Context, tag, exePath string) error {
	ver := strings.TrimPrefix(tag, "v")
	asset := fmt.Sprintf("ndscan_%s_%s_%s.tar.gz", ver, runtime.GOOS, runtime.GOARCH)
	base := c.BaseURL + "/releases/download/" + tag + "/"

	tarball, err := c.fetch(ctx, base+asset)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", asset, err)
	}
	checksums, err := c.fetch(ctx, base+"checksums.txt")
	if err != nil {
		return fmt.Errorf("downloading checksums.txt: %w", err)
	}

	expected, err := expectedSum(string(checksums), asset)
	if err != nil {
		return err
	}
	actual := sha256.Sum256(tarball)
	if !strings.EqualFold(expected, hex.EncodeToString(actual[:])) {
		return fmt.Errorf("checksum mismatch for %s — aborting (expected %s, got %s)",
			asset, expected, hex.EncodeToString(actual[:]))
	}

	binary, err := extractBinary(tarball, "ndscan")
	if err != nil {
		return err
	}
	return replaceExecutable(exePath, binary)
}

func (c *Checker) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownload))
}

// expectedSum finds the sha256 recorded for asset in a checksums.txt body
// (lines of "<hex>  <filename>").
func expectedSum(checksums, asset string) (string, error) {
	for _, ln := range strings.Split(checksums, "\n") {
		fields := strings.Fields(ln)
		if len(fields) == 2 && fields[1] == asset {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %s in checksums.txt", asset)
}

// extractBinary pulls the named file out of a .tar.gz archive in memory.
func extractBinary(tarball []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("reading archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading archive: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == name {
			return io.ReadAll(io.LimitReader(tr, maxDownload))
		}
	}
	return nil, fmt.Errorf("%s not found in downloaded archive", name)
}

// replaceExecutable writes bin next to exePath and renames it over exePath,
// so the swap is atomic on the same filesystem and the running binary's
// inode is never written to.
func replaceExecutable(exePath string, bin []byte) error {
	dir := filepath.Dir(exePath)
	tmp, err := os.CreateTemp(dir, ".ndscan-new-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s (try re-running with sudo, or use install.sh): %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed

	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		return fmt.Errorf("writing new binary: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return fmt.Errorf("marking new binary executable: %w", err)
	}
	// fsync before the rename: a power loss between write and rename can
	// otherwise install a zero-length binary, uninstalling the tool.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("flushing new binary to disk: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("finalizing new binary: %w", err)
	}
	if err := os.Rename(tmpName, exePath); err != nil {
		return fmt.Errorf("installing new binary to %s (try re-running with sudo, or use install.sh): %w", exePath, err)
	}
	return nil
}
