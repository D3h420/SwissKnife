#!/usr/bin/env python3

from __future__ import annotations

import os
import signal
import shutil
import subprocess
import tempfile
import time
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, TextIO


@dataclass(frozen=True)
class ApModeConfig:
    interface: str
    ssid: str = "SwissKnife-Control"
    channel: int = 6
    ap_ip: str = "10.10.0.1"
    cidr_prefix: int = 24
    dhcp_start: str = "10.10.0.10"
    dhcp_end: str = "10.10.0.200"
    dhcp_lease: str = "12h"


def list_wireless_interfaces() -> list[str]:
    result = subprocess.run(
        ["iw", "dev"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    interfaces: list[str] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("Interface "):
            iface = line.split("Interface", 1)[1].strip()
            if iface:
                interfaces.append(iface)
    return interfaces


def interface_is_usb(interface: str) -> bool:
    device_path = Path("/sys/class/net") / interface / "device"
    try:
        resolved = device_path.resolve()
    except OSError:
        return False
    return "usb" in resolved.as_posix().lower()


def detect_builtin_wireless_interface() -> str:
    interfaces = list_wireless_interfaces()
    if not interfaces:
        raise RuntimeError("No wireless interfaces found for AP mode.")

    builtin = [iface for iface in interfaces if not interface_is_usb(iface)]
    if builtin:
        return sorted(builtin)[0]
    raise RuntimeError(
        "No built-in Wi-Fi interface detected. AP mode requires an internal adapter."
    )


class AccessPointManager:
    def __init__(self, config: ApModeConfig) -> None:
        self.config = config
        self.runtime_dir: Optional[Path] = None
        self.hostapd_process: Optional[subprocess.Popen] = None
        self.dnsmasq_process: Optional[subprocess.Popen] = None
        self._hostapd_log_handle: Optional[TextIO] = None
        self._dnsmasq_log_handle: Optional[TextIO] = None
        self.hostapd_log_path: Optional[Path] = None
        self.dnsmasq_log_path: Optional[Path] = None

    def start(self) -> None:
        if os.geteuid() != 0:
            raise RuntimeError("AP mode requires root privileges.")

        self._ensure_tool("ip")
        self._ensure_tool("hostapd")
        self._ensure_tool("dnsmasq")

        try:
            self.runtime_dir = Path(tempfile.mkdtemp(prefix="swissknife_ap_"))
            hostapd_conf = self.runtime_dir / "hostapd.conf"
            dnsmasq_conf = self.runtime_dir / "dnsmasq.conf"
            self.hostapd_log_path = self.runtime_dir / "hostapd.log"
            self.dnsmasq_log_path = self.runtime_dir / "dnsmasq.log"

            hostapd_conf.write_text(self._hostapd_config(), encoding="utf-8")
            dnsmasq_conf.write_text(self._dnsmasq_config(), encoding="utf-8")

            self._run_checked(["ip", "link", "set", self.config.interface, "down"])
            self._run_checked(["ip", "addr", "flush", "dev", self.config.interface])
            self._run_checked(
                [
                    "ip",
                    "addr",
                    "add",
                    f"{self.config.ap_ip}/{self.config.cidr_prefix}",
                    "dev",
                    self.config.interface,
                ]
            )
            self._run_checked(["ip", "link", "set", self.config.interface, "up"])

            self._hostapd_log_handle = open(self.hostapd_log_path, "a", encoding="utf-8")
            self._dnsmasq_log_handle = open(self.dnsmasq_log_path, "a", encoding="utf-8")

            self.hostapd_process = subprocess.Popen(
                ["hostapd", str(hostapd_conf)],
                stdout=self._hostapd_log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            self.dnsmasq_process = self._start_dnsmasq(dnsmasq_conf)

            time.sleep(0.8)

            if self.hostapd_process.poll() is not None:
                output = self._read_log_tail(self.hostapd_log_path)
                raise RuntimeError(f"hostapd failed to start.\n{output}")
            if self.dnsmasq_process.poll() is not None:
                output = self._read_log_tail(self.dnsmasq_log_path)
                raise RuntimeError(f"dnsmasq failed to start.\n{output}")
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        self._stop_process(self.dnsmasq_process)
        self._stop_process(self.hostapd_process)

        self.dnsmasq_process = None
        self.hostapd_process = None

        if self._dnsmasq_log_handle:
            self._dnsmasq_log_handle.close()
            self._dnsmasq_log_handle = None
        if self._hostapd_log_handle:
            self._hostapd_log_handle.close()
            self._hostapd_log_handle = None

        if self.config.interface:
            try:
                self._run_checked(["ip", "addr", "flush", "dev", self.config.interface])
            except RuntimeError:
                pass

        if self.runtime_dir and self.runtime_dir.exists():
            shutil.rmtree(self.runtime_dir, ignore_errors=True)
            self.runtime_dir = None

    def _run_checked(self, cmd: list[str]) -> None:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        if result.returncode != 0:
            detail = result.stdout.strip()
            raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{detail}")

    def _ensure_tool(self, tool: str) -> None:
        if shutil.which(tool):
            return
        raise RuntimeError(f"Missing required tool for AP mode: {tool}")

    def _stop_process(self, process: Optional[subprocess.Popen]) -> None:
        if not process or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except Exception:
            try:
                process.terminate()
            except Exception:
                return
        try:
            process.wait(timeout=2.0)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except Exception:
            try:
                process.kill()
            except Exception:
                return
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass

    def _hostapd_config(self) -> str:
        return "\n".join(
            [
                f"interface={self.config.interface}",
                "driver=nl80211",
                f"ssid={self.config.ssid}",
                "hw_mode=g",
                f"channel={self.config.channel}",
                "auth_algs=1",
                "ignore_broadcast_ssid=0",
                "",
            ]
        )

    def _dnsmasq_config(self) -> str:
        netmask = self._cidr_to_netmask(self.config.cidr_prefix)
        return "\n".join(
            [
                f"interface={self.config.interface}",
                f"dhcp-range={self.config.dhcp_start},{self.config.dhcp_end},{netmask},{self.config.dhcp_lease}",
                f"dhcp-option=3,{self.config.ap_ip}",
                f"dhcp-option=6,{self.config.ap_ip}",
                f"address=/#/{self.config.ap_ip}",
                "server=8.8.8.8",
                "log-queries",
                "log-dhcp",
                "",
            ]
        )

    def _start_dnsmasq(self, conf_path: Path) -> subprocess.Popen:
        if self._dnsmasq_log_handle is None:
            raise RuntimeError("dnsmasq log handle is not initialized.")

        commands = [
            ["dnsmasq", "-C", str(conf_path), "--no-daemon"],
            ["dnsmasq", "-C", str(conf_path), "-k"],
            ["dnsmasq", f"--conf-file={conf_path}", "--no-daemon"],
            ["dnsmasq", f"--conf-file={conf_path}", "-k"],
        ]

        last_output = ""
        last_cmd = ""

        for cmd in commands:
            process = subprocess.Popen(
                cmd,
                stdout=self._dnsmasq_log_handle,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            time.sleep(0.6)
            if process.poll() is None:
                return process

            last_cmd = " ".join(cmd)
            last_output = self._read_log_tail(self.dnsmasq_log_path)
            self._stop_process(process)

            lower = last_output.lower()
            if "junk found in command line" in lower or "unknown option" in lower:
                continue
            if "bad command line options" in lower:
                continue

        raise RuntimeError(
            "dnsmasq failed to start with available command variants.\n"
            f"last command: {last_cmd}\n"
            f"{last_output}"
        )

    @staticmethod
    def _cidr_to_netmask(prefix: int) -> str:
        try:
            network = ipaddress.IPv4Network(f"0.0.0.0/{prefix}", strict=False)
            return str(network.netmask)
        except Exception:
            return "255.255.255.0"

    @staticmethod
    def _read_log_tail(path: Optional[Path], max_lines: int = 30) -> str:
        if not path or not path.is_file():
            return "(log file not found)"
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return "(failed to read log file)"
        if not lines:
            return "(no log output)"
        return "\n".join(lines[-max_lines:])
