#!/usr/bin/env python3
"""SwissKnifOS: button-driven front end for the existing SwissKnife modules."""

from __future__ import annotations

import argparse
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .bridge import ModuleProcess
    from .logic import Choice, Keyboard, TerminalBuffer, input_mode
else:
    from bridge import ModuleProcess
    from logic import Choice, Keyboard, TerminalBuffer, input_mode

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class MenuItem:
    label: str
    target: str
    script: str = ""
    args: tuple[str, ...] = ()


MENUS: dict[str, tuple[MenuItem, ...]] = {
    "SwissKnifOS": (
        MenuItem("Recon", "module", "modules/recon.py"),
        MenuItem("Attacks", "Attacks"),
        MenuItem("Wardrive", "Wardrive"),
        MenuItem("System", "System"),
    ),
    "Attacks": (
        MenuItem("Deauth", "module", "modules/deauth.py"),
        MenuItem("Portal", "module", "modules/portal.py"),
        MenuItem("Evil Twin", "module", "modules/twins.py"),
        MenuItem("Handshaker", "module", "modules/handshaker.py"),
        MenuItem("WiFi Poet", "module", "modules/wifi_poet.py"),
        MenuItem("Dragon Drain", "module", "modules/dragon_drain.py"),
        MenuItem("ARP scan", "module", "modules/arp_scanner.py"),
        MenuItem("IP.CAM finder", "module", "modules/ipcam_finder.py"),
        MenuItem("Back", "back"),
    ),
    "Wardrive": (
        MenuItem("Start Wardrive", "module", "modules/wardrive.py", ("--start",)),
        MenuItem("GPS setup", "module", "modules/wardrive.py", ("--gps-setup",)),
        MenuItem("Back", "back"),
    ),
    "System": (
        MenuItem("About", "about"),
        MenuItem("Exit interface", "exit"),
        MenuItem("Power off Pi", "poweroff"),
        MenuItem("Back", "back"),
    ),
}


def _renderer():
    if __package__:
        from .render import Renderer
    else:
        from render import Renderer
    return Renderer()


class SwissKnifOS:
    def __init__(self, hardware, renderer=None) -> None:
        self.hardware = hardware
        self.renderer = renderer if renderer is not None else _renderer()
        self.screen = "boot"
        self.menu_stack = ["SwissKnifOS"]
        self.menu_selection: dict[str, int] = {name: 0 for name in MENUS}
        self.module: ModuleProcess | None = None
        self.module_name = ""
        self.output = TerminalBuffer()
        self.scroll = 0
        self.pending_reads = 0
        self.prompt = ""
        self.choices: list[Choice] = []
        self.choice_selection = 0
        self.keyboard = Keyboard()
        self.last_interrupt = 0.0
        self.stopping_since = 0.0
        self.module_done = False
        self.running = True
        self.dirty = True

    @property
    def menu_name(self) -> str:
        return self.menu_stack[-1]

    def _back_menu(self) -> None:
        if len(self.menu_stack) > 1:
            self.menu_stack.pop()
        self.screen = "menu"
        self.dirty = True

    def _launch(self, item: MenuItem) -> None:
        self.module_name = item.label
        self.output = TerminalBuffer()
        self.scroll = 0
        self.pending_reads = 0
        self.choices = []
        self.prompt = ""
        self.last_interrupt = 0.0
        self.stopping_since = 0.0
        self.module_done = False
        self.screen = "output"
        self.dirty = True
        self.module = ModuleProcess(ROOT / item.script, list(item.args))
        try:
            self.module.start()
        except Exception as exc:
            self.output.feed(f"Cannot start module: {exc}\n")
            self.module = None

    def _menu_action(self, item: MenuItem) -> None:
        if item.target == "module":
            self._launch(item)
        elif item.target == "back":
            self._back_menu()
        elif item.target in MENUS:
            self.menu_stack.append(item.target)
            self.screen = "menu"
            self.dirty = True
        elif item.target == "about":
            self.screen = "about"
            self.dirty = True
        elif item.target == "exit":
            self.running = False
        elif item.target == "poweroff":
            self.screen = "poweroff"
            self.dirty = True

    def _poll_module(self) -> None:
        if self.module is None:
            return
        for kind, value in self.module.poll():
            if kind == "text":
                self.output.feed(str(value))
                if self.scroll == 0:
                    self.dirty = True
            else:
                self.pending_reads += 1
                self.prompt = self.output.prompt()
                mode, self.choices = input_mode(self.output)
                self.choice_selection = 0
                secret = bool(value) or bool(re.search(r"password|passphrase|secret", self.prompt, re.IGNORECASE))
                self.keyboard = Keyboard(secret=secret)
                if mode == "choices" and self.choices:
                    self.screen = "choices"
                elif mode == "enter":
                    self.screen = "output"
                else:
                    self.screen = "keyboard"
                self.scroll = 0
                self.dirty = True

        if self.stopping_since and self.module.returncode is None:
            if time.monotonic() - self.stopping_since > 8.0:
                self.module.terminate()
                self.stopping_since = 0.0
                self.output.feed("\nStopped after cleanup timeout.\n")
                self.dirty = True
        if self.module.returncode is not None and not self.module_done:
            # The process may exit before its last pipe bytes are delivered.
            for kind, value in self.module.poll():
                if kind == "text":
                    self.output.feed(str(value))
            self.pending_reads = 0
            if self.screen in {"keyboard", "choices"}:
                self.screen = "output"
            self.output.feed(f"\nExit code: {self.module.returncode}\n")
            self.module_done = True
            self.dirty = True

    def _send(self, value: str) -> None:
        if self.module is None or self.pending_reads < 1:
            return
        try:
            self.module.send(value)
            self.output.feed("\n")
        except RuntimeError as exc:
            self.output.feed(f"\nInput failed: {exc}\n")
        self.pending_reads = max(0, self.pending_reads - 1)
        self.choices = []
        self.screen = "output"
        self.scroll = 0
        self.dirty = True

    def _interrupt(self) -> None:
        if self.module is None or self.module.returncode is not None:
            return
        now = time.monotonic()
        if self.last_interrupt and now - self.last_interrupt < 5:
            self.module.terminate()
            self.output.feed("\nModule terminated.\n")
            self.stopping_since = 0.0
        else:
            self.module.interrupt()
            self.output.feed("\nStopping module...\n")
            self.stopping_since = now
        self.last_interrupt = now
        self.pending_reads = 0
        self.choices = []
        self.prompt = ""
        self.screen = "output"
        self.dirty = True

    def _module_key(self, key: str) -> None:
        finished = self.module is None or self.module.returncode is not None
        if finished:
            if key in {"OK", "K1", "LEFT"}:
                if self.module is not None:
                    self.module.terminate()
                    self.module = None
                self.screen = "menu"
                self.dirty = True
            elif key in {"UP", "DOWN", "L", "R"}:
                self._scroll_key(key)
            return

        if key == "K3" and self.screen != "keyboard":
            self._interrupt()
            return
        if self.screen == "keyboard":
            if key in {"UP", "DOWN", "LEFT", "RIGHT"}:
                self.keyboard.move(key)
            elif key == "OK":
                action = self.keyboard.activate()
                if action == "submit":
                    self._send(self.keyboard.value)
                elif action == "view":
                    self.screen = "output"
            elif key == "K3":
                self.keyboard.value = self.keyboard.value[:-1]
            elif key == "K4":
                if len(self.keyboard.value) < 128:
                    self.keyboard.value += " "
            elif key == "R":
                self._send(self.keyboard.value)
            elif key == "K2":
                self.keyboard.symbols = not self.keyboard.symbols
            elif key == "K1":
                self.screen = "output"
            self.dirty = True
            return

        if self.screen == "choices":
            if key in {"UP", "DOWN", "L", "R"}:
                step = {"UP": -1, "DOWN": 1, "L": -6, "R": 6}[key]
                self.choice_selection = (self.choice_selection + step) % len(self.choices)
            elif key in {"OK", "RIGHT"}:
                self._send(self.choices[self.choice_selection].key)
            elif key == "K2":
                self.screen = "keyboard"
            elif key in {"K1", "LEFT"}:
                self.screen = "output"
            elif key == "K4":
                self._send("")
            self.dirty = True
            return

        # Log/output view. The module continues running while output is read.
        if key in {"UP", "DOWN", "L", "R"}:
            self._scroll_key(key)
        elif key == "K2" and self.pending_reads:
            self.screen = "keyboard"
        elif key == "RIGHT" and self.pending_reads:
            self.screen = "choices" if self.choices else "keyboard"
        elif key in {"OK", "K4"} and self.pending_reads:
            self._send("")
        elif key == "K1" and self.pending_reads:
            self.screen = "choices" if self.choices else "keyboard"
        self.dirty = True

    def _scroll_key(self, key: str) -> None:
        step = {"UP": 1, "DOWN": -1, "L": 7, "R": -7}[key]
        self.scroll = max(0, min(self.scroll + step, self.renderer.max_scroll(self.output)))
        self.dirty = True

    def _handle_key(self, key: str) -> None:
        if self.screen == "boot":
            self.screen = "menu"
            self.dirty = True
            return
        if self.screen == "menu":
            name = self.menu_name
            items = MENUS[name]
            selected = self.menu_selection[name]
            if key == "UP":
                selected = (selected - 1) % len(items)
            elif key == "DOWN":
                selected = (selected + 1) % len(items)
            elif key in {"L", "R"}:
                step = -6 if key == "L" else 6
                selected = max(0, min(selected + step, len(items) - 1))
            elif key in {"OK", "RIGHT", "K4"}:
                self._menu_action(items[selected])
            elif key in {"LEFT", "K1"}:
                self._back_menu()
            self.menu_selection[name] = selected
            self.dirty = True
        elif self.screen == "about":
            if key in {"OK", "K4", "K1", "LEFT"}:
                self.screen = "menu"
                self.dirty = True
        elif self.screen == "poweroff":
            if key in {"K1", "LEFT"}:
                self.screen = "menu"
            elif key in {"OK", "K4"}:
                subprocess.run(["systemctl", "poweroff"], check=False)
                self.screen = "menu"
            self.dirty = True
        else:
            self._module_key(key)

    def _frame(self):
        if self.screen == "boot":
            return self.renderer.boot()
        if self.screen == "menu":
            items = MENUS[self.menu_name]
            return self.renderer.menu(self.menu_name, [item.label for item in items], self.menu_selection[self.menu_name])
        if self.screen == "about":
            return self.renderer.message("SwissKnifOS", ["SwissKnife on Pi Zero 2 W", "Seengreat LCD 1.44", "Use only in your lab."], "OK back")
        if self.screen == "poweroff":
            return self.renderer.message("Power off Pi?", ["Press OK to shut down.", "K1 to cancel."], "OK power off  K1 cancel")
        if self.screen == "choices":
            return self.renderer.choices(self.module_name, self.prompt, self.choices, self.choice_selection)
        if self.screen == "keyboard":
            return self.renderer.keyboard(self.prompt, self.keyboard)
        finished = self.module is None or self.module.returncode is not None
        hint = "OK back  ↑↓ scroll" if finished else ("OK Enter  K2 type  K3 stop" if self.pending_reads else "↑↓ scroll  K3 stop")
        state = "END" if finished else ("IN" if self.pending_reads else "RUN")
        return self.renderer.output(self.module_name, self.output, self.scroll, hint, state)

    def run(self) -> None:
        try:
            while self.running:
                self._poll_module()
                for key in self.hardware.poll():
                    self._handle_key(key)
                if self.dirty:
                    self.hardware.show(self._frame())
                    self.dirty = False
                time.sleep(0.04)
        finally:
            if self.module is not None:
                self.module.terminate()
            self.hardware.close()


def preview(path: Path) -> None:
    """Write sample frames for layout review without GPIO or SPI."""
    path.mkdir(parents=True, exist_ok=True)
    renderer = _renderer()
    renderer.boot().save(path / "boot.png")
    renderer.menu("Attacks", [item.label for item in MENUS["Attacks"]], 4).save(path / "menu.png")
    buffer = TerminalBuffer()
    buffer.feed("Available interfaces:\n  1) wlan0 - onboard\n  2) wlan1 - USB\nSelect interface (number or name): ")
    _, choices = input_mode(buffer)
    renderer.choices("Recon", buffer.prompt(), choices, 1).save(path / "choices.png")
    buffer.feed("\nScanning...\nLab AP  -54 dBm\nChannel 6  WPA2\n3 clients observed\n")
    renderer.output("Recon", buffer, 0, "U/D scroll  K3 stop", "RUN").save(path / "output.png")
    keyboard = Keyboard()
    keyboard.value = "wlan1"
    renderer.keyboard("Enter SSID:", keyboard).save(path / "keyboard.png")


def main() -> None:
    parser = argparse.ArgumentParser(description="SwissKnifOS 1.44-inch LCD interface")
    parser.add_argument("--preview", type=Path, metavar="DIR", help="save sample PNG screens without hardware")
    args = parser.parse_args()
    if args.preview:
        preview(args.preview)
        return
    if __package__:
        from .hardware import SeengreatHardware
    else:
        from hardware import SeengreatHardware

    hardware = SeengreatHardware()
    app = SwissKnifOS(hardware)

    def stop(_signum, _frame):
        app.running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    app.run()


if __name__ == "__main__":
    main()
