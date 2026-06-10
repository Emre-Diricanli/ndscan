#!/usr/bin/env bash
#
# ndscan one-line installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Emre-Diricanli/ndscan/main/install.sh | bash
#
# Options (via environment variables):
#   VERSION=v1.2.3     # Pin to a specific version (default: latest)
#   INSTALL_DIR=...    # Custom install location (default: /usr/local/bin)
#   FORCE=1            # Overwrite existing binary without prompting
#
set -euo pipefail

REPO="Emre-Diricanli/ndscan"
BINARY="ndscan"
DEFAULT_INSTALL_DIR="/usr/local/bin"

# Colors (only if stdout is a tty)
if [ -t 1 ]; then
  GREEN=$'\033[0;32m'
  YELLOW=$'\033[1;33m'
  RED=$'\033[0;31m'
  NC=$'\033[0m'
else
  GREEN=""
  YELLOW=""
  RED=""
  NC=""
fi

info()  { echo "${GREEN}==>${NC} $*"; }
warn()  { echo "${YELLOW}warning:${NC} $*"; }
error() { echo "${RED}error:${NC} $*" >&2; }

# Allow overrides
INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
VERSION="${VERSION:-latest}"
FORCE="${FORCE:-0}"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  darwin) OS="darwin" ;;
  linux)  OS="linux" ;;
  *)
    error "Unsupported operating system: $(uname -s)"
    echo "ndscan currently provides pre-built binaries for macOS and Linux."
    echo "You can still install from source with: go install github.com/Emre-Diricanli/ndscan/cmd/ndscan@latest"
    exit 1
    ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64)  ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    error "Unsupported architecture: $ARCH"
    echo "ndscan currently supports amd64 and arm64."
    exit 1
    ;;
esac

info "Detected platform: ${OS}/${ARCH}"

# Resolve version
if [ "$VERSION" = "latest" ]; then
  info "Resolving latest release..."
  # Follow the /latest redirect to extract the tag without hitting the API rate limit hard
  LATEST_URL=$(curl -fsSLI -o /dev/null -w "%{url_effective}" "https://github.com/${REPO}/releases/latest" 2>/dev/null || true)
  if [ -z "$LATEST_URL" ] || [[ "$LATEST_URL" != *"tag/"* ]]; then
    error "Could not determine latest version."
    echo "Please check https://github.com/${REPO}/releases or specify VERSION explicitly."
    exit 1
  fi
  VERSION="${LATEST_URL##*/}"   # e.g. v0.1.0
fi

# Strip leading 'v' if present for asset name construction, then re-add for download URL
VERSION_TAG="$VERSION"
if [[ "$VERSION" != v* ]]; then
  VERSION_TAG="v${VERSION}"
fi

ASSET_VERSION="${VERSION_TAG#v}"   # GoReleaser assets use 0.1.0 without the v in the filename
TARBALL="${BINARY}_${ASSET_VERSION}_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION_TAG}/${TARBALL}"

info "Installing ${BINARY} ${VERSION_TAG} for ${OS}/${ARCH}..."

TMPDIR=$(mktemp -d)
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

# Download
if ! curl -fL --progress-bar "$DOWNLOAD_URL" -o "$TMPDIR/$TARBALL"; then
  error "Failed to download $TARBALL"
  echo
  echo "Possible reasons:"
  echo "  • The release does not exist yet (have you created a GitHub Release with GoReleaser?)"
  echo "  • Your platform combination is not built for this release"
  echo
  echo "You can still install via Go:"
  echo "  go install github.com/Emre-Diricanli/ndscan/cmd/ndscan@${VERSION_TAG}"
  exit 1
fi

# Extract
tar -xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"

# Find the binary inside the tarball (GoReleaser puts it at the root)
if [ -f "$TMPDIR/$BINARY" ]; then
  SRC="$TMPDIR/$BINARY"
else
  SRC=$(find "$TMPDIR" -type f -name "$BINARY" 2>/dev/null | head -n 1)
fi

if [ -z "${SRC:-}" ] || [ ! -f "$SRC" ]; then
  error "Could not find ${BINARY} binary inside the downloaded archive."
  exit 1
fi

# Check if something is already installed
DEST="$INSTALL_DIR/$BINARY"
if [ -e "$DEST" ] && [ "$FORCE" != "1" ]; then
  CURRENT_VERSION="$("$DEST" --version 2>/dev/null | head -n1 || echo "unknown version")"
  warn "${BINARY} is already installed at $DEST ($CURRENT_VERSION)"
  read -r -p "Overwrite? [y/N] " reply
  if [[ ! "$reply" =~ ^[Yy]$ ]]; then
    info "Aborted. Existing binary left in place."
    exit 0
  fi
fi

# Install
mkdir -p "$INSTALL_DIR"

if [ -w "$INSTALL_DIR" ]; then
  mv "$SRC" "$DEST"
else
  info "Requesting sudo privileges to install to $INSTALL_DIR..."
  if command -v sudo >/dev/null 2>&1; then
    sudo mv "$SRC" "$DEST"
  else
    error "Cannot write to $INSTALL_DIR and sudo is not available."
    echo "Try running with INSTALL_DIR=\$HOME/.local/bin or add yourself to the appropriate group."
    exit 1
  fi
fi

chmod +x "$DEST"

# Success
echo
info "✅ ${GREEN}${BINARY}${NC} ${VERSION_TAG} installed to ${DEST}"
echo

# Verify it works and is on PATH
if command -v "$BINARY" >/dev/null 2>&1; then
  INSTALLED_PATH=$(command -v "$BINARY")
  if [ "$INSTALLED_PATH" != "$DEST" ]; then
    warn "Note: '$BINARY' on your PATH resolves to ${INSTALLED_PATH}, which is different from the newly installed ${DEST}"
    echo "You may want to adjust your PATH or remove the other copy."
  fi
  echo "Version: $("$BINARY" --version 2>/dev/null || echo "unknown")"
else
  echo "Installation complete, but '$BINARY' is not currently on your PATH."
  echo
  if [ "$INSTALL_DIR" != "$DEFAULT_INSTALL_DIR" ]; then
    echo "Add the following to your shell profile (~/.zshrc, ~/.bash_profile, etc.):"
    echo
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
  else
    echo "Make sure ${INSTALL_DIR} is in your PATH."
  fi
fi

echo
echo "Next steps:"
echo "  • Run 'ndscan' to start the interactive TUI"
echo "  • Run 'ndscan scan --help' for CLI usage"
echo "  • Make sure 'nmap' is installed on any machine you want to scan from (brew install nmap on macOS)"
echo
echo "Thanks for installing ndscan!"
