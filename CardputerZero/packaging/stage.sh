#!/usr/bin/env bash
set -euo pipefail
: "${STAGE:?}"
: "${APP_INSTALL_DIR:?}"
: "${INSTALL_PREFIX:?}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEST="$STAGE$APP_INSTALL_DIR"
mkdir -p "$DEST" "$STAGE$INSTALL_PREFIX/bin"
mkdir -p "$STAGE/usr/libexec/swissknife-cardputer"
tar -C "$ROOT" --exclude='__pycache__' --exclude='*.pyc' -cf - \
    core modules html swiss_knife.py requirements.txt \
    CardputerZero/__init__.py CardputerZero/app CardputerZero/swiss_intro.png | tar -C "$DEST" -xf -
install -m 0755 "$ROOT/CardputerZero/packaging/swissknife-cardputer" \
    "$STAGE$INSTALL_PREFIX/bin/swissknife-cardputer"
install -m 0755 "$ROOT/CardputerZero/packaging/scan-wifi" \
    "$STAGE/usr/libexec/swissknife-cardputer/scan-wifi"
