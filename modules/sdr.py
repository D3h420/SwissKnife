#!/usr/bin/env python3
"""Shared RTL-SDR receiver for CLI, LCD HAT and Cardputer Zero.

One dongle is used by one mode at a time. No interface keeps a second SDR
implementation: they all consume the snapshots produced here.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from core.paths import DATA_DIR
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from core.paths import DATA_DIR


SDR_DIR = DATA_DIR / "sub-ghz"
MIN_HZ = 24_000_000
MAX_HZ = 1_766_000_000
PRESETS = (
    ("FM", 98_000_000, 20_000_000),
    ("AIR", 127_500_000, 19_000_000),
    ("433", 433_920_000, 2_000_000),
    ("868", 868_300_000, 2_000_000),
    ("ADSB", 1_090_000_000, 2_000_000),
)
MODULATIONS = ("wbfm", "fm", "am", "usb", "lsb")
DEVICE_LINE = re.compile(r"^\s*(\d+):\s*(.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class SDRConfig:
    device: int = 0
    center_hz: int = 433_920_000
    span_hz: int = 2_000_000
    sample_rate: int = 1_024_000
    gain_db: float | None = None
    ppm: int = 0
    modulation: str = "fm"

    def validate(self) -> None:
        if not 0 <= self.device <= 31:
            raise ValueError("Device index must be 0-31")
        if not MIN_HZ <= self.center_hz <= MAX_HZ:
            raise ValueError("Frequency must be 24-1766 MHz (dongle range may differ)")
        if not 100_000 <= self.span_hz <= 50_000_000:
            raise ValueError("Waterfall span must be 0.1-50 MHz")
        if self.center_hz - self.span_hz // 2 < MIN_HZ or self.center_hz + self.span_hz // 2 > MAX_HZ:
            raise ValueError("Waterfall band exceeds supported tuning range")
        if not 225_001 <= self.sample_rate <= 3_200_000:
            raise ValueError("Sample rate must be 225001-3200000 samples/s")
        if self.gain_db is not None and not 0 <= self.gain_db <= 60:
            raise ValueError("Gain must be 0-60 dB or automatic")
        if not -200 <= self.ppm <= 200:
            raise ValueError("PPM correction must be -200..200")
        if self.modulation not in MODULATIONS:
            raise ValueError("Unsupported modulation")


@dataclass(frozen=True)
class SDRSnapshot:
    mode: str
    config: SDRConfig
    waterfall: tuple[tuple[float, ...], ...]
    message: str
    devices: tuple[str, ...]
    recording: str = ""
    aircraft: tuple[str, ...] = ()
    simulated: bool = False


def parse_power_row(line: str) -> tuple[str, float, float, list[float]] | None:
    """Parse the documented rtl_power CSV format; reject partial or bad rows."""
    try:
        fields = next(csv.reader([line]))
        if len(fields) < 7:
            return None
        low, high, step = (float(fields[index].strip()) for index in (2, 3, 4))
        levels = [float(value.strip()) for value in fields[6:]]
        if not levels or step <= 0 or high <= low or any(not math.isfinite(value) for value in levels):
            return None
        return f"{fields[0].strip()} {fields[1].strip()}", low, step, levels
    except (ValueError, csv.Error, StopIteration):
        return None


def spectrum_bins(segments: list[tuple[float, float, list[float]]], low_hz: float, high_hz: float, width: int = 128) -> tuple[float, ...]:
    if width < 1:
        raise ValueError("width must be positive")
    values: list[list[float]] = [[] for _ in range(width)]
    for first, step, levels in segments:
        for index, level in enumerate(levels):
            frequency = first + index * step
            column = int((frequency - low_hz) / (high_hz - low_hz) * width)
            if 0 <= column < width:
                values[column].append(level)
    result = [sum(cell) / len(cell) if cell else float("nan") for cell in values]
    known = [index for index, value in enumerate(result) if math.isfinite(value)]
    if not known:
        return ()
    for index, value in enumerate(result):
        if not math.isfinite(value):
            closest = min(known, key=lambda item: abs(item - index))
            result[index] = result[closest]
    return tuple(result)


def discover_devices(*, demo: bool = False) -> tuple[str, ...]:
    if demo:
        return ("[SIMULATED] RTL-SDR #0", "[SIMULATED] RTL-SDR #1")
    if not shutil.which("rtl_test"):
        return ()
    try:
        result = subprocess.run(["rtl_test", "-t"], capture_output=True, text=True, timeout=4, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ()
    lines = DEVICE_LINE.findall(result.stdout + "\n" + result.stderr)
    return tuple(f"{index}: {name}" for index, name in lines)


class SDRSession:
    def __init__(self, config: SDRConfig | None = None, *, demo: bool = False, data_dir: Path = SDR_DIR) -> None:
        self.config = config or SDRConfig()
        self.config.validate()
        self.demo = demo
        self.data_dir = Path(data_dir)
        self.mode = "idle"
        self.message = "[SIMULATED] SDR ready" if demo else "SDR ready"
        self.devices: tuple[str, ...] = ()
        self.recording = ""
        self.waterfall: deque[tuple[float, ...]] = deque(maxlen=96)
        self._processes: list[subprocess.Popen[Any]] = []
        self._stderr: deque[str] = deque(maxlen=12)
        self._lock = threading.RLock()
        self._power_segments: list[tuple[float, float, list[float]]] = []
        self._power_stamp = ""
        self._adsb_dir: Path | None = None
        self._last_demo = 0.0
        self._record_deadline = 0.0
        self._generation = 0

    def refresh_devices(self) -> tuple[str, ...]:
        devices = discover_devices(demo=self.demo)
        with self._lock:
            self.devices = devices
            if not devices:
                self.message = "No RTL-SDR dongle detected; check USB and rtl_test"
        return devices

    def _require(self, *commands: str) -> None:
        if self.demo:
            return
        missing = [command for command in commands if not shutil.which(command)]
        if missing:
            raise RuntimeError("Missing SDR tools: " + ", ".join(missing))

    def _stderr_reader(self, process: subprocess.Popen[Any], generation: int) -> None:
        if process.stderr is None:
            return
        try:
            for raw in process.stderr:
                line = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
                line = line.strip()
                if line:
                    with self._lock:
                        if generation != self._generation:
                            return
                        self._stderr.append(line)
        except (OSError, ValueError):
            pass

    def _watch(self, process: subprocess.Popen[Any]) -> None:
        threading.Thread(target=self._stderr_reader, args=(process, self._generation), daemon=True).start()

    def _launch(self, command: list[str], *, stdout: Any = subprocess.DEVNULL, stdin: Any = None) -> subprocess.Popen[Any]:
        process = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=subprocess.PIPE, bufsize=0, umask=0o077)
        self._watch(process)
        self._processes.append(process)
        return process

    def stop(self) -> None:
        with self._lock:
            processes, self._processes = self._processes, []
            self.mode = "idle"
            self._power_segments.clear()
            self._power_stamp = ""
            self._record_deadline = 0.0
            self._generation += 1
            self._stderr.clear()
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
            for stream in (process.stdout, process.stderr, process.stdin):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        with self._lock:
            self.message = "Stopped"

    def close(self) -> None:
        self.stop()

    def update_config(self, *, restart: bool = True, **changes: Any) -> None:
        config = replace(self.config, **changes)
        config.validate()
        self.config = config
        if restart and self.mode == "spectrum":
            self.start_spectrum()

    def _power_reader(self, process: subprocess.Popen[Any], low: int, high: int, generation: int) -> None:
        assert process.stdout is not None
        try:
            for raw in process.stdout:
                parsed = parse_power_row(raw.decode(errors="replace"))
                if not parsed:
                    continue
                stamp, first, step, levels = parsed
                with self._lock:
                    if generation != self._generation:
                        return
                    if self._power_stamp and stamp != self._power_stamp:
                        row = spectrum_bins(self._power_segments, low, high)
                        if row:
                            self.waterfall.append(row)
                        self._power_segments.clear()
                    self._power_stamp = stamp
                    self._power_segments.append((first, step, levels))
        except (OSError, ValueError):
            pass

    def start_spectrum(self) -> None:
        self.config.validate()
        self._require("rtl_power")
        self.stop()
        self.waterfall.clear()
        low = self.config.center_hz - self.config.span_hz // 2
        high = self.config.center_hz + self.config.span_hz // 2
        bin_hz = max(1_000, self.config.span_hz // 128)
        command = ["rtl_power", "-d", str(self.config.device), "-f", f"{low}:{high}:{bin_hz}", "-i", "1s", "-p", str(self.config.ppm)]
        if self.config.gain_db is not None:
            command += ["-g", str(self.config.gain_db)]
        command.append("-")
        if not self.demo:
            process = self._launch(command, stdout=subprocess.PIPE)
            threading.Thread(target=self._power_reader, args=(process, low, high, self._generation), daemon=True).start()
        with self._lock:
            self.mode = "spectrum"
            self.message = "[SIMULATED] Waterfall" if self.demo else "Waterfall running"

    def start_audio(self) -> None:
        self.config.validate()
        self._require("rtl_fm", "aplay")
        self.stop()
        rate = 32_000 if self.config.modulation == "wbfm" else 24_000
        command = ["rtl_fm", "-d", str(self.config.device), "-f", str(self.config.center_hz), "-M", self.config.modulation,
                   "-s", "170000" if self.config.modulation == "wbfm" else "24000", "-r", str(rate), "-p", str(self.config.ppm)]
        if self.config.gain_db is not None:
            command += ["-g", str(self.config.gain_db)]
        command.append("-")
        if not self.demo:
            receiver = self._launch(command, stdout=subprocess.PIPE)
            assert receiver.stdout is not None
            try:
                self._launch(["aplay", "-q", "-r", str(rate), "-f", "S16_LE", "-t", "raw", "-c", "1"], stdin=receiver.stdout)
            except Exception:
                self.stop()
                raise
            receiver.stdout.close()
        with self._lock:
            self.mode = "audio"
            self.message = f"[SIMULATED] Listening {self.config.modulation}" if self.demo else f"Listening {self.config.modulation}"

    def start_recording(self, *, seconds: int = 30) -> Path:
        self.config.validate()
        if not 1 <= seconds <= 120:
            raise ValueError("Recording duration must be 1-120 seconds")
        self._require("rtl_sdr")
        self.stop()
        if not self.demo:
            self.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        required_bytes = self.config.sample_rate * seconds * 2
        if not self.demo and shutil.disk_usage(self.data_dir).free < required_bytes + 50_000_000:
            raise RuntimeError("Not enough free space for IQ recording")
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        path = self.data_dir / f"iq-{self.config.center_hz}-{stamp}.cu8"
        metadata = {"format": "unsigned 8-bit interleaved I/Q", "center_hz": self.config.center_hz,
                    "sample_rate": self.config.sample_rate, "device": self.config.device,
                    "gain_db": self.config.gain_db, "ppm": self.config.ppm, "seconds_limit": seconds,
                    "created": datetime.now().isoformat(timespec="seconds")}
        if not self.demo:
            command = ["rtl_sdr", "-d", str(self.config.device), "-f", str(self.config.center_hz),
                       "-s", str(self.config.sample_rate), "-p", str(self.config.ppm),
                       "-n", str(self.config.sample_rate * seconds)]
            if self.config.gain_db is not None:
                command += ["-g", str(self.config.gain_db)]
            command.append(str(path))
            self._launch(command)
            try:
                path.with_suffix(".json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
            except OSError:
                self.stop()
                raise
        with self._lock:
            self.mode = "record"
            self.recording = str(path)
            self._record_deadline = time.monotonic() + seconds if self.demo else 0.0
            self.message = "[SIMULATED] Recording IQ" if self.demo else f"Recording IQ to {path.name}"
        return path

    def start_adsb(self) -> None:
        decoder = shutil.which("dump1090-mutability") or shutil.which("dump1090")
        if not self.demo and decoder is None:
            raise RuntimeError("Missing SDR tool: dump1090-mutability")
        self.stop()
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        directory = self.data_dir / f"adsb-{stamp}"
        if not self.demo:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            command = [decoder, "--device-index", str(self.config.device), "--ppm", str(self.config.ppm), "--write-json", str(directory), "--quiet"]
            if self.config.gain_db is not None:
                command += ["--gain", str(self.config.gain_db)]
            self._launch(command)
        with self._lock:
            self._adsb_dir = directory
            self.mode = "adsb"
            self.message = "[SIMULATED] ADS-B 1090 MHz" if self.demo else "ADS-B 1090 MHz"

    def _aircraft(self) -> tuple[str, ...]:
        if self.demo:
            return ("[SIMULATED] ABC123  12000 ft", "[SIMULATED] DEF456  26000 ft")
        if self._adsb_dir is None:
            return ()
        try:
            data = json.loads((self._adsb_dir / "aircraft.json").read_text(encoding="utf-8"))
            aircraft = data.get("aircraft", [])
            return tuple(f"{str(item.get('flight') or item.get('hex') or '?').strip()}  {item.get('alt_baro', item.get('altitude', '?'))} ft" for item in aircraft[:20] if isinstance(item, dict))
        except (OSError, ValueError, TypeError, AttributeError):
            return ()

    def snapshot(self) -> SDRSnapshot:
        with self._lock:
            if self.demo and self.mode == "record" and self._record_deadline and time.monotonic() >= self._record_deadline:
                self.mode = "idle"
                self.message = "[SIMULATED] Recording complete"
            if self.demo and self.mode == "spectrum" and time.monotonic() - self._last_demo > 0.35:
                phase = len(self.waterfall) * 0.25
                self.waterfall.append(tuple(-72 + 12 * math.sin(index * 0.17 + phase) + 28 * math.exp(-((index - 74) / 7) ** 2) for index in range(128)))
                self._last_demo = time.monotonic()
            if self._processes and self.mode != "idle" and all(process.poll() is not None for process in self._processes):
                codes = [process.returncode for process in self._processes]
                self.mode = "idle" if all(code == 0 for code in codes) else "error"
                self.message = "Operation finished" if self.mode == "idle" else "SDR stopped: " + (self._stderr[-1] if self._stderr else str(codes))
            mode, config, waterfall, message, devices, recording = self.mode, self.config, tuple(self.waterfall), self.message, self.devices, self.recording
        aircraft = self._aircraft() if mode == "adsb" else ()
        return SDRSnapshot(mode, config, waterfall, message, devices, recording, aircraft, self.demo)


def _cli() -> int:
    parser = argparse.ArgumentParser(description="SwissKnife SDR: RTL-SDR receiver")
    parser.add_argument("--demo", action="store_true", help="labelled simulation without radio hardware")
    parser.add_argument("--device", type=int, default=0)
    parser.add_argument("--frequency", type=float, default=433.92, help="MHz")
    parser.add_argument("--span", type=float, default=2, help="MHz")
    parser.add_argument("--mode", choices=("menu", "spectrum", "listen", "record", "adsb"), default="menu")
    parser.add_argument("--modulation", choices=MODULATIONS, default="fm")
    parser.add_argument("--gain", type=float, help="manual tuner gain in dB; omit for auto")
    parser.add_argument("--ppm", type=int, default=0, help="frequency correction")
    parser.add_argument("--sample-rate", type=int, default=1_024_000, help="I/Q samples per second")
    parser.add_argument("--seconds", type=int, default=30, help="recording limit")
    args = parser.parse_args()
    try:
        config = SDRConfig(device=args.device, center_hz=round(args.frequency * 1_000_000), span_hz=round(args.span * 1_000_000), modulation=args.modulation, gain_db=args.gain, ppm=args.ppm, sample_rate=args.sample_rate)
        config.validate()
    except (ValueError, OverflowError) as exc:
        parser.error(str(exc))
    session = SDRSession(config, demo=args.demo)
    try:
        if args.mode == "menu":
            devices = session.refresh_devices()
            print("RTL-SDR devices:", ", ".join(devices) if devices else "none")
            while True:
                print("\n1 Waterfall  2 Listen  3 Record IQ  4 ADS-B  5 Frequency  6 Span  7 Modulation  8 Gain  9 PPM  10 Sample rate  0 Back")
                choice = input("SDR> ").strip()
                if choice == "0":
                    return 0
                if choice == "5":
                    session.update_config(center_hz=round(float(input("Frequency MHz: ")) * 1_000_000))
                    continue
                if choice == "6":
                    session.update_config(span_hz=round(float(input("Span MHz: ")) * 1_000_000))
                    continue
                if choice == "7":
                    session.update_config(modulation=input("Modulation (wbfm/fm/am/usb/lsb): ").strip().lower())
                    continue
                if choice == "8":
                    answer = input("Gain dB (empty=auto): ").strip()
                    session.update_config(gain_db=float(answer) if answer else None)
                    continue
                if choice == "9":
                    session.update_config(ppm=int(input("PPM correction: ")))
                    continue
                if choice == "10":
                    session.update_config(sample_rate=int(input("IQ sample rate samples/s: ")))
                    continue
                args.mode = {"1": "spectrum", "2": "listen", "3": "record", "4": "adsb"}.get(choice, "menu")
                if args.mode == "menu":
                    continue
                _run_cli_mode(session, args.mode, args.seconds)
                args.mode = "menu"
        else:
            _run_cli_mode(session, args.mode, args.seconds)
    except (KeyboardInterrupt, EOFError):
        print("\nStopping SDR")
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"SDR error: {exc}")
        return 1
    finally:
        session.close()
    return 0


def _run_cli_mode(session: SDRSession, mode: str, seconds: int) -> None:
    if mode == "spectrum":
        session.start_spectrum()
    elif mode == "listen":
        session.start_audio()
    elif mode == "record":
        path = session.start_recording(seconds=seconds)
        print("[SIMULATED] Would save" if session.demo else "Saving", path)
    elif mode == "adsb":
        session.start_adsb()
    print("Ctrl+C to stop; one dongle runs one mode at a time")
    try:
        while True:
            state = session.snapshot()
            if state.mode in {"idle", "error"}:
                print(state.message)
                break
            if mode == "spectrum" and state.waterfall:
                row = state.waterfall[-1]
                print("".join(" .:-=+*#%@"[max(0, min(9, int((value + 100) / 8)))] for value in row[::2]))
            elif mode == "adsb":
                print("Aircraft:", ", ".join(state.aircraft) or "none yet")
            else:
                print(state.message)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        session.stop()


if __name__ == "__main__":
    raise SystemExit(_cli())
