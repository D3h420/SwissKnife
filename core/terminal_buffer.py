"""Readable streaming output for the Cardputer graphical module view."""

from __future__ import annotations

from collections import deque


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
            elif char == "\f":
                # LCD-only live updates replace the previous snapshot.
                self.lines.clear()
                self.current = ""
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


