#!/usr/bin/env python3

from __future__ import annotations

import ipaddress
import os
import signal
import shutil
import subprocess
import tempfile
import time
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


def get_interface_type(interface: str) -> str:
    result = subprocess.run(
        ["iw", "dev", interface, "info"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return ""
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("type "):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1].lower()
    return ""


def looks_like_virtual_aux_interface(interface: str) -> bool:
    name = interface.lower()
    if name.startswith("p2p") or name.startswith("p2p-"):
        return True
    if name.endswith("mon"):
        return True
    if "monitor" in name:
        return True
    return False


def detect_builtin_wireless_interface() -> str:
    interfaces = list_wireless_interfaces()
    if not interfaces:
        raise RuntimeError("No wireless interfaces found for AP mode.")

    builtin = [iface for iface in interfaces if not interface_is_usb(iface)]
    if not builtin:
        raise RuntimeError(
            "No built-in Wi-Fi interface detected. AP mode requires an internal adapter."
        )

    def priority(iface: str) -> tuple[int, str]:
        score = 0
        name = iface.lower()
        iface_type = get_interface_type(iface)

        if not (name.startswith("wlan") or name.startswith("wl")):
            score += 5
        if looks_like_virtual_aux_interface(iface):
            score += 20
        if iface_type in ("managed", "station"):
            score += 0
        elif iface_type == "ap":
            score += 3
        elif iface_type == "monitor":
            score += 25
        elif iface_type:
            score += 10
        else:
            score += 8

        return score, iface

    return sorted(builtin, key=priority)[0]


def nmcli_exists() -> bool:
    return shutil.which("nmcli") is not None


def set_nm_interface_managed(interface: str, managed: bool) -> bool:
    if not nmcli_exists():
        return False
    state = "yes" if managed else "no"
    commands = [
        ["nmcli", "device", "set", interface, "managed", state],
        ["nmcli", "dev", "set", interface, "managed", state],
    ]
    for command in commands:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return True
    return False


def disconnect_interface(interface: str) -> None:
    subprocess.run(
        ["iw", "dev", interface, "disconnect"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )


def candidate_ap_channels(primary: int) -> list[int]:
    defaults = [primary, 1, 6, 11]
    channels: list[int] = []
    for channel in defaults:
        if not isinstance(channel, int):
            continue
        if channel <= 0:
            continue
        if channel not in channels:
            channels.append(channel)
    return channels


def hostapd_channel_failure(log_text: str) -> bool:
    lower = log_text.lower()
    patterns = [
        "could not set channel",
        "failed to set beacon parameters",
        "hardware does not support configured mode",
        "interface initialization failed",
        "nl80211: failed to set channel",
        "failed to start ap",
    ]
    return any(pattern in lower for pattern in patterns)


def log_message(handle: Optional[TextIO], message: str) -> None:
    if not handle:
        return
    handle.write(f"{message}\n")
    handle.flush()


class AccessPointManager:
    def __init__(self, config: ApModeConfig) -> None:
        self.config = config
        self.active_channel = config.channel
        self.network_manager_unmanaged = False
        self.dns_enabled = True
        self.dhcp_enabled = True
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

            self._prepare_interface_for_ap()

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

            self.hostapd_process = self._start_hostapd(hostapd_conf)
            dnsmasq_conf.write_text(self._dnsmasq_config(enable_dns=True), encoding="utf-8")
            self.dnsmasq_process = self._start_dnsmasq(dnsmasq_conf)

            time.sleep(1.0)

            if self.hostapd_process.poll() is not None:
                output = self._read_log_tail(self.hostapd_log_path)
                raise RuntimeError(f"hostapd failed to stay running.\n{output}")
            if self.dnsmasq_process and self.dnsmasq_process.poll() is not None:
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

        self._restore_network_manager()

        if self.runtime_dir and self.runtime_dir.exists():
            shutil.rmtree(self.runtime_dir, ignore_errors=True)
            self.runtime_dir = None

    def _set_network_manager_managed(self, managed: bool) -> None:
        changed = set_nm_interface_managed(self.config.interface, managed)
        if changed:
            self.network_manager_unmanaged = not managed

    def _restore_network_manager(self) -> None:
        if not self.network_manager_unmanaged:
            return
        self._set_network_manager_managed(True)
        self.network_manager_unmanaged = False

    def _prepare_interface_for_ap(self) -> None:
        disconnect_interface(self.config.interface)
        self._set_network_manager_managed(False)
        time.sleep(0.25)

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

    def _hostapd_config(self, channel: Optional[int] = None) -> str:
        active_channel = channel if channel is not None else self.config.channel
        return "\n".join(
            [
                f"interface={self.config.interface}",
                "driver=nl80211",
                f"ssid={self.config.ssid}",
                "hw_mode=g",
                f"channel={active_channel}",
                "auth_algs=1",
                "ignore_broadcast_ssid=0",
                "wmm_enabled=1",
                "ieee80211n=1",
                "country_code=US",
                "ieee80211d=1",
                "",
            ]
        )

    def _start_hostapd(self, conf_path: Path) -> subprocess.Popen:
        if self._hostapd_log_handle is None:
            raise RuntimeError("hostapd log handle is not initialized.")

        channels = candidate_ap_channels(self.config.channel)
        last_output = ""
        last_command = ""

        for channel in channels:
            conf_path.write_text(self._hostapd_config(channel), encoding="utf-8")
            commands = [
                ["hostapd", str(conf_path)],
                ["hostapd", "-d", str(conf_path)],
            ]
            for command in commands:
                process = subprocess.Popen(
                    command,
                    stdout=self._hostapd_log_handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                    start_new_session=True,
                )
                time.sleep(0.9)
                if process.poll() is None:
                    self.active_channel = channel
                    log_message(
                        self._hostapd_log_handle,
                        f"[webui] hostapd active on channel {self.active_channel}",
                    )
                    return process

                last_command = " ".join(command)
                last_output = self._read_log_tail(self.hostapd_log_path)
                self._stop_process(process)

                if hostapd_channel_failure(last_output):
                    break

        raise RuntimeError(
            "hostapd failed to start with available channel/command variants.\n"
            f"last command: {last_command}\n"
            f"{last_output}"
        )

    def _dnsmasq_config(self, enable_dns: bool = True) -> str:
        netmask = self._cidr_to_netmask(self.config.cidr_prefix)
        lines = [
            f"interface={self.config.interface}",
            "bind-interfaces",
            f"listen-address={self.config.ap_ip}",
            "except-interface=lo",
            f"dhcp-range={self.config.dhcp_start},{self.config.dhcp_end},{netmask},{self.config.dhcp_lease}",
            f"dhcp-option=3,{self.config.ap_ip}",
        ]
        if enable_dns:
            lines.extend(
                [
                    f"dhcp-option=6,{self.config.ap_ip}",
                    f"address=/#/{self.config.ap_ip}",
                    "server=8.8.8.8",
                    "log-queries",
                ]
            )
        else:
            # Keep DHCP while disabling DNS listener when local port 53 is occupied.
            lines.append("port=0")

        lines.extend(["log-dhcp", ""])
        return "\n".join(lines)

    def _start_dnsmasq(self, conf_path: Path) -> Optional[subprocess.Popen]:
        try:
            process = self._start_dnsmasq_with_variants(conf_path)
            self.dns_enabled = True
            self.dhcp_enabled = True
            return process
        except RuntimeError as exc:
            if not self._is_bind_conflict(str(exc)):
                raise

            # Fallback: run DHCP only when DNS port 53 is already in use by another service.
            conf_path.write_text(self._dnsmasq_config(enable_dns=False), encoding="utf-8")
            try:
                process = self._start_dnsmasq_with_variants(conf_path)
                self.dns_enabled = False
                self.dhcp_enabled = True
                log_message(
                    self._dnsmasq_log_handle,
                    "[webui] dnsmasq started in DHCP-only mode (DNS disabled due bind conflict).",
                )
                return process
            except RuntimeError as second_exc:
                if not self._is_bind_conflict(str(second_exc)):
                    raise
                # Last resort: keep AP alive without dnsmasq (manual IP config needed on client).
                self.dns_enabled = False
                self.dhcp_enabled = False
                log_message(
                    self._dnsmasq_log_handle,
                    "[webui] dnsmasq disabled due bind conflicts; AP runs without DHCP/DNS.",
                )
                return None

    def _start_dnsmasq_with_variants(self, conf_path: Path) -> subprocess.Popen:
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
    def _is_bind_conflict(text: str) -> bool:
        lower = text.lower()
        return "address already in use" in lower and (
            "failed to create listening socket" in lower
            or "address already in use" in lower
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
