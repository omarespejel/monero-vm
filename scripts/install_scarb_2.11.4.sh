#!/usr/bin/env bash
# Restore Scarb 2.11.4 into .bin/ for this project.
# Required because snforge_std_deprecated needs Cairo ≤ 2.11.4 (Scarb 2.11.x).
# Usage: ./scripts/install_scarb_2.11.4.sh

set -e
SCARB_VERSION="2.11.4"
REPO_URL="https://github.com/software-mansion/scarb/releases/download/v${SCARB_VERSION}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/.bin"
mkdir -p "$BIN_DIR"
cd "$BIN_DIR"

detect_platform() {
  local os arch
  case "$(uname -s)" in
    Darwin) os="apple-darwin" ;;
    Linux)  os="unknown-linux-gnu" ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
  esac
  case "$(uname -m)" in
    arm64|aarch64) arch="aarch64" ;;
    x86_64|amd64)  arch="x86_64" ;;
    *) echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
  esac
  echo "${arch}-${os}"
}

PLATFORM=$(detect_platform)
TARBALL="scarb-v${SCARB_VERSION}-${PLATFORM}.tar.gz"
URL="${REPO_URL}/${TARBALL}"
DIRNAME="scarb-v${SCARB_VERSION}-${PLATFORM}"

if [[ -x "${BIN_DIR}/${DIRNAME}/bin/scarb" ]]; then
  echo "Scarb ${SCARB_VERSION} already present at .bin/${DIRNAME}/bin/scarb"
  "${BIN_DIR}/${DIRNAME}/bin/scarb" --version
  exit 0
fi

echo "Downloading ${TARBALL} ..."
if command -v curl &>/dev/null; then
  curl -sSL -o "$TARBALL" "$URL"
else
  wget -q -O "$TARBALL" "$URL"
fi

echo "Extracting ..."
tar -xzf "$TARBALL"
rm -f "$TARBALL"

echo "Done. Scarb installed at:"
echo "  ${BIN_DIR}/${DIRNAME}/bin/scarb"
"${BIN_DIR}/${DIRNAME}/bin/scarb" --version
