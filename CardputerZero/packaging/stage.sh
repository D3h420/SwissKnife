#!/usr/bin/env bash
set -euo pipefail
: "${STAGE:?}"
: "${APP_INSTALL_DIR:?}"
: "${INSTALL_PREFIX:?}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="$STAGE$APP_INSTALL_DIR"
mkdir -p "$DEST" "$STAGE$INSTALL_PREFIX/bin"
tar -C "$ROOT" --exclude='__pycache__' --exclude='*.pyc' -cf - \
    core modules html swiss_knife.py requirements.txt \
    CardputerZero/__init__.py CardputerZero/app | tar -C "$DEST" -xf -
install -m 0755 "$ROOT/CardputerZero/packaging/swissknife-cardputer" \
    "$STAGE$INSTALL_PREFIX/bin/swissknife-cardputer"
