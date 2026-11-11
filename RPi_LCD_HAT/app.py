#!/usr/bin/env python3
"""SwissKnifOS: button-driven front end for the existing SwissKnife modules."""

from __future__ import annotations

import argparse
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.features import features_for
from modules.sdr import PRESETS, MODULATIONS, SDRSession

if __package__:
    from .bridge import ModuleProcess
    from .logic import Choice, Keyboard, TerminalBuffer, input_mode
else:
    from bridge import ModuleProcess
    from logic import Choice, Keyboard, TerminalBuffer, input_mode

ROOT = Path(__file__).resolve().parent.parent


def git_revision() -> str | None:
    """Return the checked out revision when the app runs from a Git clone."""
    try:
        result = subprocess.run(
            ["git", "-c", f"safe.directory={ROOT}", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=2, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


@dataclass(frozen=True)
class MenuItem:
    label: str
    target: str
    script: str = ""
    args: tuple[str, ...] = ()


MENUS: dict[str, tuple[MenuItem, ...]] = {
    "SwissKnifOS": (
        *(MenuItem(feature.label, "module", feature.script, feature.args) for feature in features_for("Recon")),
        MenuItem("Attacks", "Attacks"),
        MenuItem("Wardrive", "Wardrive"),
        MenuItem("SDR", "SDR"),
        MenuItem("System", "System"),
    ),
    "Attacks": (
        *(MenuItem(feature.label, "module", feature.script, feature.args) for feature in features_for("Attacks")),
        MenuItem("Back", "back"),
    ),
    "Wardrive": (
        *(MenuItem(feature.label, "module", feature.script, feature.args) for feature in features_for("Wardrive")),
        MenuItem("Back", "back"),
    ),
    "SDR": (
        MenuItem("Waterfall", "sdr-mode", args=("spectrum",)),
        MenuItem("Tune MHz", "sdr-tune"),
        MenuItem("Listen", "sdr-mode", args=("audio",)),
        MenuItem("Record IQ 30s", "sdr-mode", args=("record",)),
        MenuItem("ADS-B", "sdr-mode", args=("adsb",)),
        MenuItem("Next dongle", "sdr-device"),
        MenuItem("Settings", "SDR settings"),
        MenuItem("Back", "back"),
    ),
    "SDR settings": (
        MenuItem("Gain", "sdr-setting", args=("gain",)),
        MenuItem("PPM", "sdr-setting", args=("ppm",)),
        MenuItem("Span", "sdr-setting", args=("span",)),
        MenuItem("IQ rate", "sdr-setting", args=("rate",)),
        MenuItem("Back", "back"),
    ),
    "System": (
        MenuItem("About", "about"),
        MenuItem("Pi Commands", "Pi Commands"),
        MenuItem("Back", "back"),
    ),
    "Pi Commands": (
        MenuItem("USB devices", "module", "RPi_LCD_HAT/pi_commands.py", ("usb",)),
        MenuItem("Interfaces", "module", "RPi_LCD_HAT/pi_commands.py", ("interfaces",)),
        MenuItem("WiFi scan", "module", "RPi_LCD_HAT/pi_commands.py", ("wifi-scan",)),
        MenuItem("WiFi connect", "module", "RPi_LCD_HAT/pi_commands.py", ("wifi-connect",)),
        MenuItem("Saved networks", "module", "RPi_LCD_HAT/pi_commands.py", ("profiles",)),
        MenuItem("Activate network", "module", "RPi_LCD_HAT/pi_commands.py", ("activate",)),
        MenuItem("Disconnect", "module", "RPi_LCD_HAT/pi_commands.py", ("disconnect",)),
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
        self.about_page = 0
        self.menu_stack = ["SwissKnifOS"]
        self.menu_selection: dict[str, int] = {name: 0 for name in MENUS}
        self.module: ModuleProcess | None = None
        self.module_name = ""
        self.pi_command = False
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
        self.sdr: SDRSession | None = None
        self.sdr_error = ""
        self.sdr_busy = False
        self.sdr_pending_stop = False
        self.sdr_worker: threading.Thread | None = None
        self.sdr_step_hz = 100_000
        self.sdr_last_frame = None
        self.sdr_last_check = 0.0
        self.sdr_selected_mode = "spectrum"
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
        self.pi_command = item.script == "RPi_LCD_HAT/pi_commands.py"
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

    def _sdr_session(self) -> SDRSession:
        if self.sdr is None:
            self.sdr = SDRSession()
        return self.sdr

    def _refresh_sdr_devices(self) -> None:
        try:
            self._sdr_session().refresh_devices()
        except Exception as exc:
            self.sdr_error = str(exc)
        self.dirty = True

    def _sdr_action(self, action: str, **changes) -> None:
        if self.sdr_busy:
            if action == "stop":
                self.sdr_pending_stop = True
            return
        self.sdr_busy = True
        self.sdr_error = ""

        def worker() -> None:
            try:
                session = self._sdr_session()
                if not session.devices and action != "stop":
                    if not session.refresh_devices():
                        raise RuntimeError("No RTL-SDR dongle detected")
                previous = session.mode
                if action == "retune" and previous in {"record", "adsb"}:
                    raise RuntimeError("Stop recording or ADS-B before retuning")
                if changes:
                    session.update_config(restart=action == "retune", **changes)
                if action == "spectrum":
                    session.start_spectrum()
                elif action == "audio":
                    session.start_audio()
                elif action == "record":
                    session.start_recording(seconds=30)
                elif action == "adsb":
                    session.start_adsb()
                elif action == "stop":
                    session.stop()
                elif action == "retune" and previous == "audio":
                    session.start_audio()
                if action in {"spectrum", "audio", "record", "adsb"}:
                    self.sdr_selected_mode = action
            except Exception as exc:
                self.sdr_error = str(exc)
            finally:
                try:
                    if self.sdr_pending_stop:
                        self.sdr_pending_stop = False
                        self.sdr.stop()
                finally:
                    self.sdr_busy = False
                    self.dirty = True

        self.sdr_worker = threading.Thread(target=worker, daemon=True)
        self.sdr_worker.start()

    def _sdr_key(self, key: str) -> None:
        session = self._sdr_session()
        if key == "K3":
            self._sdr_action("stop")
            self.screen = "menu"
        elif key in {"LEFT", "RIGHT"}:
            current = min(range(len(PRESETS)), key=lambda index: abs(PRESETS[index][1] - session.config.center_hz))
            index = (current + (-1 if key == "LEFT" else 1)) % len(PRESETS)
            _, center, span = PRESETS[index]
            self._sdr_action("spectrum", center_hz=center, span_hz=span)
        elif key in {"UP", "DOWN", "L", "R"}:
            direction = 1 if key in {"UP", "R"} else -1
            step = self.sdr_step_hz * (10 if key in {"L", "R"} else 1)
            self._sdr_action("retune", center_hz=session.config.center_hz + direction * step)
        elif key == "K1":
            self.sdr_step_hz = {10_000: 100_000, 100_000: 1_000_000, 1_000_000: 10_000}[self.sdr_step_hz]
        elif key == "K2":
            index = (MODULATIONS.index(session.config.modulation) + 1) % len(MODULATIONS)
            self._sdr_action("retune", modulation=MODULATIONS[index])
        elif key in {"OK", "K4"}:
            self._sdr_action("stop" if session.mode not in {"idle", "error"} else self.sdr_selected_mode)
        self.dirty = True

    def _sdr_tune_key(self, key: str) -> None:
        if key == "K1":
            self.screen = "menu"
        elif key == "K2":
            self.keyboard.value = self.keyboard.value[:-1]
        elif key in {"UP", "DOWN", "LEFT", "RIGHT"}:
            self.keyboard.move(key)
        elif key in {"OK", "K4"}:
            action = "submit" if key == "K4" else self.keyboard.activate()
            if action == "submit":
                try:
                    frequency = round(float(self.keyboard.value) * 1_000_000)
                    from dataclasses import replace
                    replace(self._sdr_session().config, center_hz=frequency).validate()
                except ValueError as exc:
                    self.sdr_error = str(exc)
                    self.sdr_last_frame = self._sdr_session().snapshot()
                    self.screen = "sdr"
                else:
                    self.screen = "sdr"
                    self._sdr_action("spectrum", center_hz=frequency)
        self.dirty = True

    def _menu_action(self, item: MenuItem) -> None:
        if item.target == "module":
            self._launch(item)
        elif item.target == "sdr-mode":
            self._sdr_action(item.args[0])
            self.screen = "sdr"
            self.dirty = True
        elif item.target == "sdr-tune":
            if self.sdr_busy:
                self.sdr_error = "SDR is stopping; try again"
                self.screen = "sdr"
                self.dirty = True
                return
            self.keyboard = Keyboard()
            self.keyboard.value = f"{self._sdr_session().config.center_hz / 1e6:.3f}"
            self.screen = "sdr_tune"
            self.dirty = True
        elif item.target == "sdr-device":
            if self.sdr_busy:
                self.sdr_error = "SDR is stopping; try again"
                self.screen = "sdr"
                self.dirty = True
                return
            session = self._sdr_session()
            count = len(session.devices)
            if count:
                session.update_config(device=(session.config.device + 1) % count)
            else:
                self.sdr_error = "No dongle detected"
            self.dirty = True
        elif item.target == "sdr-setting":
            if self.sdr_busy:
                self.sdr_error = "SDR is stopping; try again"
                self.screen = "sdr"
                self.dirty = True
                return
            session = self._sdr_session()
            config = session.config
            try:
                if item.args[0] == "gain":
                    gains = (None, 0.0, 10.0, 20.0, 30.0, 40.0)
                    session.update_config(gain_db=gains[((gains.index(config.gain_db) if config.gain_db in gains else -1) + 1) % len(gains)])
                elif item.args[0] == "ppm":
                    values = (0, 1, 2, 5, 10, -1, -2, -5, -10)
                    session.update_config(ppm=values[((values.index(config.ppm) if config.ppm in values else -1) + 1) % len(values)])
                elif item.args[0] == "span":
                    spans = (200_000, 2_000_000, 20_000_000)
                    session.update_config(span_hz=spans[((spans.index(config.span_hz) if config.span_hz in spans else -1) + 1) % len(spans)])
                elif item.args[0] == "rate":
                    rates = (1_024_000, 2_048_000, 2_400_000)
                    session.update_config(sample_rate=rates[((rates.index(config.sample_rate) if config.sample_rate in rates else -1) + 1) % len(rates)])
            except (ValueError, RuntimeError) as exc:
                self.sdr_error = str(exc)
                self.sdr_last_frame = session.snapshot()
                self.screen = "sdr"
            self.dirty = True
        elif item.target == "back":
            self._back_menu()
        elif item.target in MENUS:
            self.menu_stack.append(item.target)
            self.screen = "menu"
            self.dirty = True
            if item.target == "SDR":
                self._sdr_session()
                threading.Thread(target=self._refresh_sdr_devices, daemon=True).start()
        elif item.target == "about":
            self.about_page = 0
            self.screen = "about"
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
        if self.module.returncode is not None and not self.module_done and (
            not self.pi_command or getattr(self.module, "output_complete", True)
        ):
            self.pending_reads = 0
            if self.screen in {"keyboard", "choices"}:
                self.screen = "output"
            if not self.pi_command:
                self.output.feed(f"\nExit code: {self.module.returncode}\n")
            elif self.module.returncode and not any(line.startswith("Error:") for line in self.output.visible_lines()):
                self.output.feed(f"\nCommand failed (code {self.module.returncode}).\n")
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
        if self.screen == "sdr":
            self._sdr_key(key)
            return
        if self.screen == "sdr_tune":
            self._sdr_tune_key(key)
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
            if key == "K1":
                self.about_page = 1 - self.about_page
            elif key in {"OK", "K4", "LEFT"}:
                self.screen = "menu"
            self.dirty = True
        else:
            self._module_key(key)

    def _frame(self):
        if self.screen == "boot":
            return self.renderer.boot()
        if self.screen == "menu":
            items = MENUS[self.menu_name]
            labels = [item.label for item in items]
            if self.menu_name == "SDR settings" and self.sdr is not None:
                config = self.sdr.config
                labels = [f"Gain: {config.gain_db if config.gain_db is not None else 'auto'}", f"PPM: {config.ppm}", f"Span: {config.span_hz / 1e6:g}M", f"IQ rate: {config.sample_rate // 1000}k", "Back"]
            return self.renderer.menu(self.menu_name, labels, self.menu_selection[self.menu_name])
        if self.screen == "about":
            return self.renderer.about_qr() if self.about_page else self.renderer.about_info()
        if self.screen == "sdr":
            return self.renderer.sdr(self.sdr_last_frame, self.sdr_error, self.sdr_step_hz)
        if self.screen == "sdr_tune":
            return self.renderer.keyboard("Frequency MHz", self.keyboard)
        if self.screen == "choices":
            return self.renderer.choices(self.module_name, self.prompt, self.choices, self.choice_selection)
        if self.screen == "keyboard":
            return self.renderer.keyboard(self.prompt, self.keyboard)
        finished = self.module is None or self.module.returncode is not None
        if finished:
            hint = "OK back  UP/DN scroll"
        elif self.pending_reads and "stop" in self.prompt.casefold():
            hint = "OK stop  UP/DN scroll"
        elif self.pending_reads:
            hint = "OK continue  K2 input"
        else:
            hint = "UP/DN scroll  K3 stop"
        state = "END" if finished else ("IN" if self.pending_reads else "RUN")
        return self.renderer.output(self.module_name, self.output, self.scroll, hint, state)

    def run(self) -> None:
        revision = git_revision()
        next_revision_check = time.monotonic() + 3
        try:
            while self.running:
                self._poll_module()
                now = time.monotonic()
                if self.screen == "sdr" and self.sdr is not None and now - self.sdr_last_check >= 0.25:
                    self.sdr_last_check = now
                    self.sdr_last_frame = self.sdr.snapshot()
                    self.dirty = True
                if revision and now >= next_revision_check:
                    next_revision_check = now + 3
                    updated = git_revision()
                    if updated and updated != revision and (
                        self.module is None or self.module.returncode is not None
                    ) and (self.sdr is None or self.sdr.snapshot().mode in {"idle", "error"}):
                        # systemd Restart=always starts the updated application.
                        self.running = False
                        break
                for key in self.hardware.poll():
                    self._handle_key(key)
                if self.dirty:
                    self.hardware.show(self._frame())
                    self.dirty = False
                time.sleep(0.04)
        finally:
            if self.module is not None:
                self.module.terminate()
            if self.sdr is not None:
                if self.sdr_busy:
                    self.sdr_pending_stop = True
                    if self.sdr_worker:
                        self.sdr_worker.join(timeout=5)
                self.sdr.close()
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
    renderer.about_info().save(path / "about.png")
    renderer.about_qr().save(path / "about-qr.png")
    sdr = SDRSession(demo=True)
    sdr.start_spectrum()
    renderer.sdr(sdr.snapshot(), "", 100_000).save(path / "sdr-waterfall.png")
    sdr.close()
    renderer.choices("Portal", "SSID source:", [Choice("s", "Scan networks"), Choice("m", "Manual SSID")], 0).save(path / "portal-mode.png")
    renderer.choices("Portal", "Scan duration:", [Choice(str(value), f"{value} seconds") for value in (5, 15, 30, 60)], 1).save(path / "scan-duration.png")
    networks = TerminalBuffer()
    networks.feed("Observed networks:\n  1) Lab AP (AA:BB:CC:DD:EE:FF) - ch 6 | WPA2 | -54 dBm | clients 3\n")
    renderer.output("Recon", networks, 0, "UP/DN scroll  OK back", "END").save(path / "scan-results.png")
    sniffer = TerminalBuffer()
    sniffer.feed("\fSniffer on wlan1\nPackets: 234\nProbes: 12\nUnique SSIDs: 5\nStatus: RUNNING\nOK: stop sniffer\n")
    renderer.output("Recon", sniffer, 0, "OK stop  UP/DN scroll", "RUN").save(path / "sniffer-live.png")


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
