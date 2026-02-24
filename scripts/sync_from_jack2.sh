#!/usr/bin/env bash
set -euo pipefail

# Copy (do not move) selected jack-2 files into vendor/jack2/ for reference.
#
# Usage:
#   ./scripts/sync_from_jack2.sh [/absolute/path/to/jack-2]
#
# Defaults to the author machine path, but can be overridden via:
#   JACK2_ROOT=/path/to/jack-2 ./scripts/sync_from_jack2.sh

JACK2_ROOT="${1:-${JACK2_ROOT:-/Users/tosi-n/Documents/Dev/Jenesys/jack-2}}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -d "${JACK2_ROOT}" ]; then
  echo "ERROR: jack-2 root not found: ${JACK2_ROOT}" >&2
  exit 1
fi

DEST_ROOT="${REPO_ROOT}/vendor/jack2"
mkdir -p "${DEST_ROOT}"

copy_file() {
  local rel="$1"
  local src="${JACK2_ROOT}/${rel}"
  local dst="${DEST_ROOT}/${rel}"
  if [ ! -f "${src}" ]; then
    echo "ERROR: missing upstream file: ${src}" >&2
    exit 1
  fi
  mkdir -p "$(dirname "${dst}")"
  cp -f "${src}" "${dst}"
}

FILES=(
  "backend/app/core/mailing/integrations/base.py"
  "backend/app/core/mailing/integrations/gmail.py"
  "backend/app/core/mailing/integrations/outlook.py"
  "backend/app/core/mailing/integrations/cache_manager.py"
  "backend/app/services/mailing/gmail.py"
  "backend/app/services/mailing/outlook.py"
  "backend/app/services/mailing/forwarding.py"
  "backend/app/services/mailing/email_forwarding_sender.py"
)

for f in "${FILES[@]}"; do
  copy_file "${f}"
done

echo "Synced ${#FILES[@]} files from ${JACK2_ROOT} -> ${DEST_ROOT}"

