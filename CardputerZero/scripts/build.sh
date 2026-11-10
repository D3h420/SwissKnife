#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILDER="${APPBUILDER_DIR:-$ROOT/../AppBuilder}"
[[ -x "$BUILDER/scripts/pack-deb.sh" ]] || {
    echo "Set APPBUILDER_DIR to a clone of https://github.com/CardputerZero/AppBuilder" >&2
    exit 1
}
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    commit_count=$(git -C "$ROOT" rev-list --count HEAD)
    commit_hash=$(git -C "$ROOT" rev-parse --short=8 HEAD)
    export PKG_REVISION="m5stack1+git${commit_count}.${commit_hash}"
    if [[ -n "$(git -C "$ROOT" status --porcelain -- core modules html swiss_knife.py CardputerZero)" ]]; then
        PKG_REVISION="${PKG_REVISION}+dirty$(date -u +%Y%m%d%H%M%S)"
        export PKG_REVISION
    fi
fi
"$BUILDER/scripts/pack-deb.sh" "$ROOT/CardputerZero" --output-dir "$ROOT/dist"
