"""Small, hardware-independent pieces of the LCD interface."""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class Choice:
    key: str
    label: str


class TerminalBuffer:
    """Keep readable output from CLI modules without ANSI terminal controls."""

    def __init__(self, max_lines: int = 500) -> None:
        self.lines: deque[str] = deque(maxlen=max_lines)
        self.current = ""
        self._escape = ""
        self._cr_pending = False
        self.version = 0

    def feed(self, chunk: str) -> None:
        if chunk:
            self.version += 1
        for char in chunk:
            if self._cr_pending:
                if char != "\n":
                    self.current = ""
                self._cr_pending = False
            if self._escape == "esc":
                if char == "[":
                    self._escape = "csi"
                elif char == "]":
                    self._escape = "osc"
                else:
                    self._escape = ""
                continue
            if self._escape == "csi":
                if "@" <= char <= "~":
                    self._escape = ""
                continue
            if self._escape == "osc":
                if char == "\a":
                    self._escape = ""
                elif char == "\x1b":
                    self._escape = "osc_esc"
                continue
            if self._escape == "osc_esc":
                self._escape = "" if char == "\\" else "osc"
                continue
            if char == "\x1b":
                self._escape = "esc"
            elif char == "\r":
                self._cr_pending = True
            elif char == "\n":
                self.lines.append(self.current)
                self.current = ""
            elif char == "\b":
                self.current = self.current[:-1]
            elif char == "\t":
                self.current += "    "
            elif char.isprintable():
                self.current += char
                # Some tools print a single enormous line; bound display memory.
                if len(self.current) > 4096:
                    self.current = self.current[-4096:]

    def visible_lines(self) -> list[str]:
        result = list(self.lines)
        if self.current:
            result.append(self.current)
        return result

    def prompt(self) -> str:
        if self.current.strip():
            return self.current.strip()
        return next((line.strip() for line in reversed(self.lines) if line.strip()), "")


_OPTION = re.compile(
    r"^\s*(?:\[([0-9]{1,2}|[A-Za-z])\]|([0-9]{1,2})[).]|[│|]?\s*([0-9]{1,2})\s*[│|]|([0-9]{1,2})\s{2,})\s*(.+?)\s*$"
)
_CHOICE_PROMPT = re.compile(
    r"\b(?:select|choose|choice|option|pick)\b|\(number(?:\s+or\s+name)?\)",
    re.IGNORECASE,
)
_ENTER_PROMPT = re.compile(r"\bpress\s+enter\b|\benter\s*\(or\s*ctrl\+c\)\s+to\s+stop\b", re.IGNORECASE)


def input_mode(buffer: TerminalBuffer) -> tuple[str, list[Choice]]:
    """Return enter, choices, or keyboard for the current CLI read."""
    prompt = buffer.prompt()
    if _ENTER_PROMPT.search(prompt):
        return "enter", []
    if _CHOICE_PROMPT.search(prompt):
        lines = buffer.visible_lines()
        if buffer.current:
            lines = lines[:-1]
        # The closest numbered block belongs to the current prompt. A large
        # network list can have many entries, so search more than one LCD page.
        recent = lines[-100:]
        collected: list[Choice] = []
        started = False
        gap = 0
        for line in reversed(recent):
            match = _OPTION.match(line)
            if match:
                key = match.group(1) or match.group(2) or match.group(3) or match.group(4)
                collected.append(Choice(key, match.group(5)))
                started = True
                gap = 0
            elif started:
                gap += 1
                if gap > 1:
                    break
            else:
                gap += 1
                if gap > 3:
                    break
        if collected:
            collected.reverse()
            return "choices", collected
    return "keyboard", []


BASE_CHARS = list("abcdefghijklmnopqrstuvwxyz0123456789-_.@/:")
SYMBOL_CHARS = (list("!?#$%&*()+=[]{};,'\"\\|`~<>^ąęłńóśźż") + list("0123456789"))[:42]
SPECIAL_KEYS = ["SP", "DEL", "OK", "SHIFT", "SYM", "LOG"]


class Keyboard:
    def __init__(self, secret: bool = False) -> None:
        self.value = ""
        self.cursor = 0
        self.shift = False
        self.symbols = False
        self.secret = secret

    @property
    def keys(self) -> list[str]:
        chars = SYMBOL_CHARS if self.symbols else BASE_CHARS
        if self.shift:
            chars = [char.upper() for char in chars]
        return chars + [""] * (42 - len(chars)) + SPECIAL_KEYS

    def move(self, direction: str) -> None:
        row, col = divmod(self.cursor, 8)
        if direction == "UP":
            row = (row - 1) % 6
        elif direction == "DOWN":
            row = (row + 1) % 6
        elif direction == "LEFT":
            col = (col - 1) % 8
        elif direction == "RIGHT":
            col = (col + 1) % 8
        self.cursor = row * 8 + col

    def activate(self) -> str | None:
        key = self.keys[self.cursor]
        if key == "SP":
            self.value += " "
        elif key == "DEL":
            self.value = self.value[:-1]
        elif key == "OK":
            return "submit"
        elif key == "SHIFT":
            self.shift = not self.shift
        elif key == "SYM":
            self.symbols = not self.symbols
        elif key == "LOG":
            return "view"
        elif key and len(self.value) < 128:
            self.value += key
        return None
