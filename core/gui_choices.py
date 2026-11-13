"""Extract explicit numbered choices from a terminal module's current prompt."""

from __future__ import annotations

import re


_CHOICE = re.compile(r"^\s*(?:\[([0-9]{1,3}|[A-Za-z])\]|([0-9]{1,3})[).])\s+(.+?)\s*$")


def current_choices(lines: list[str]) -> list[tuple[str, str]]:
    choices: list[tuple[str, str]] = []
    started = False
    gaps = 0
    for line in reversed(lines[-120:]):
        match = _CHOICE.match(line)
        if match:
            choices.append((match.group(1) or match.group(2), match.group(3)))
            started = True
            gaps = 0
        elif started:
            gaps += 1
            if gaps > 1:
                break
        else:
            gaps += 1
            if gaps > 3:
                break
    choices.reverse()
    return choices
