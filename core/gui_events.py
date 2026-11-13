"""Structured events from shared modules to the Cardputer interface."""

from __future__ import annotations

import json
import os


def emit(kind: str, **data: object) -> None:
    if not os.environ.get("SWISSKNIFE_GUI"):
        return
    fd = os.environ.get("SWISSKNIFE_CONTROL_FD")
    if fd is None:
        return
    prefix = os.environ.get("SWISSKNIFE_CONTROL_PREFIX", "SKINPUT:")
    payload = prefix + json.dumps({"type": "data", "kind": kind, "data": data}, ensure_ascii=False) + "\n"
    os.write(int(fd), payload.encode("utf-8"))
