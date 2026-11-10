#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 -m compileall -q "$ROOT/core" "$ROOT/modules" "$ROOT/CardputerZero/app"
PYTHONPATH="$ROOT" python3 -m unittest discover -s "$ROOT/CardputerZero/tests" -p 'test_*.py'
