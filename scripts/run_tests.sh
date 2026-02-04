#!/usr/bin/env bash
# Run project tests with Scarb 2.11.4 (required by snforge_std_deprecated).
# Uses .bin/scarb if present, otherwise PATH scarb (e.g. from mise/asdf per .tool-versions).
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

SCARB_2114=""
if [[ -d "$ROOT/.bin" ]]; then
  for d in "$ROOT/.bin"/scarb-v2.11.4-*; do
    if [[ -x "${d}/bin/scarb" ]]; then
      SCARB_2114="${d}/bin/scarb"
      break
    fi
  done
fi

if [[ -n "$SCARB_2114" ]]; then
  echo "Using pinned Scarb: $SCARB_2114"
  exec "$SCARB_2114" test "$@"
fi

# Fallback: PATH scarb (must be 2.11.x for snforge_std_deprecated)
if command -v scarb &>/dev/null; then
  echo "Using PATH scarb (ensure it is 2.11.x: scarb --version)"
  exec scarb test "$@"
fi

echo "No Scarb 2.11.4 found. Run: ./scripts/install_scarb_2.11.4.sh" >&2
exit 1
