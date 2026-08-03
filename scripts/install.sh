#!/usr/bin/env bash
# scopuli installer.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/lucaspdude/scopuli/main/scripts/install.sh | bash
#
# Environment variables:
#   SCOPULI_REPO    GitHub repo (default: lucaspdude/scopuli)
#   SCOPULI_VERSION Tag to install (default: latest)
#   SCOPULI_DEST    Install dir (default: /usr/local/bin if writable, else ~/.local/bin)
#
# Re-running the script upgrades in place.

set -euo pipefail

REPO="${SCOPULI_REPO:-lucaspdude/scopuli}"
VERSION="${SCOPULI_VERSION:-latest}"
BIN_NAME="scopuli"

# --- detect OS / arch -----------------------------------------------------

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)          ARCH=amd64 ;;
  aarch64|arm64)   ARCH=arm64 ;;
  *)
    printf 'unsupported architecture: %s\n' "$ARCH" >&2
    exit 1
    ;;
esac

# macOS's uname -s is "Darwin"; we want "darwin" (matches our release asset names).
case "$OS" in
  linux|darwin) ;;
  *)
    printf 'unsupported OS: %s\n' "$OS" >&2
    exit 1
    ;;
esac

ASSET="scopuli-${OS}-${ARCH}.tar.gz"

# --- pick destination -----------------------------------------------------

pick_dest() {
  if [ -n "${SCOPULI_DEST:-}" ]; then
    mkdir -p "$SCOPULI_DEST"
    echo "$SCOPULI_DEST"
    return
  fi
  if [ -w /usr/local/bin ]; then
    echo /usr/local/bin
    return
  fi
  echo "$HOME/.local/bin"
}

DEST=$(pick_dest)
if [ ! -w "$DEST" ]; then
  if command -v sudo >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then
    SUDO=sudo
  else
    printf 'cannot write to %s and no sudo available\n' "$DEST" >&2
    exit 1
  fi
else
  SUDO=""
fi

# --- fetch + verify -------------------------------------------------------

if [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

printf 'downloading %s\n' "$ASSET"
curl -fsSL "$BASE_URL/$ASSET" -o "$TMP/$ASSET"

# Verify checksum if available. The release publishes a sidecar .sha256.
if curl -fsSL "$BASE_URL/$ASSET.sha256" -o "$TMP/$ASSET.sha256" 2>/dev/null; then
  printf 'verifying checksum\n'
  ( cd "$TMP" && sha256sum -c "$ASSET.sha256" )
fi

printf 'extracting\n'
tar xzf "$TMP/$ASSET" -C "$TMP"

# --- install --------------------------------------------------------------

BIN_PATH="$TMP/scopuli-${OS}-${ARCH}"
if [ ! -f "$BIN_PATH" ]; then
  printf 'asset layout unexpected: %s not found in tarball\n' "$BIN_PATH" >&2
  exit 1
fi

printf 'installing to %s\n' "$DEST"
$SUDO install -m 0755 "$BIN_PATH" "$DEST/$BIN_NAME"

INSTALL_PATH="$DEST/$BIN_NAME"
printf '\n✓ installed %s to %s\n' "$BIN_NAME" "$INSTALL_PATH"
"$INSTALL_PATH" version || true
