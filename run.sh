#!/usr/bin/env bash
set -euo pipefail

BIN_NAME="tunnel-helper"

OS="$(uname -s)"
if [[ "$OS" != "Linux" ]]; then
  echo "This tool supports Linux only. Detected: $OS"
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

command -v curl >/dev/null 2>&1 || { echo "curl is required."; exit 1; }
command -v tar  >/dev/null 2>&1 || { echo "tar is required."; exit 1; }

REPO="sudogeeker/tunnel-helper"
API="https://api.github.com/repos/${REPO}/releases/latest"

AUTH_HEADERS=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  AUTH_HEADERS=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

if ! json="$(curl -fsSL "${AUTH_HEADERS[@]}" "$API")"; then
  echo "Failed to fetch release metadata from ${REPO}."
  exit 1
fi

asset_url="$(printf '%s\n' "$json" | awk -v arch="$ARCH" -F '\"' '/browser_download_url/ && $0 ~ "linux_"arch"\\.tar\\.gz" {print $4; exit}')"

if [[ -z "$asset_url" ]]; then
  echo "Could not find a linux_${ARCH} release asset for ${REPO}."
  echo "Available assets:"
  printf '%s\n' "$json" | awk -F '\"' '/browser_download_url/ {print $4}' || true
  exit 1
fi

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

archive="$tmpdir/pkg.tar.gz"
curl -fsSL "${AUTH_HEADERS[@]}" "$asset_url" -o "$archive"
tar -xzf "$archive" -C "$tmpdir"

bin_path="$(find "$tmpdir" -maxdepth 2 -type f -name "$BIN_NAME" -print -quit)"
if [[ -z "$bin_path" ]]; then
  echo "Binary ${BIN_NAME} not found in release archive."
  exit 1
fi

chmod +x "$bin_path"

if [[ "${RUN_AFTER_DOWNLOAD:-1}" != "1" ]]; then
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    sudo "$bin_path" "$@"
  else
    echo "Run as root: $bin_path $*"
    exit 1
  fi
else
  "$bin_path" "$@"
fi
