#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import secrets
import shlex
import subprocess
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Allow running as both module (`python -m webui.server`) and file (`python webui/server.py`).
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel, Field
except ModuleNotFoundError as exc:
    requirements_path = Path(__file__).resolve().parent / "requirements.txt"
    module_name = exc.name or "unknown"
    raise SystemExit(
        f"Missing Python package '{module_name}'.\n"
        f"Install Web UI dependencies with:\n"
        f"{sys.executable or 'python3'} -m pip install -r {requirements_path}"
    ) from exc

from webui.ap_mode import (
    AccessPointManager,
    ApModeConfig,
    detect_builtin_wireless_interface,
    list_wireless_interfaces,
)
from webui.process_manager import ProcessManager, TaskError


LOG = logging.getLogger("swissknife.webui")
TOKEN_HEADER = "X-SwissKnife-Token"
TOKEN_ENV_VAR = "SWISSKNIFE_WEBUI_TOKEN"
STATIC_DIR = Path(__file__).resolve().parent / "static"
LOG_DIR = PROJECT_ROOT / "log"
HTML_DIR = PROJECT_ROOT / "html"
MENU_SCHEMA = {
    "main": [
        {
            "id": "recon",
            "label": "Recon",
            "icon": "RCN",
            "type": "group",
            "description": "Passive discovery of APs and clients.",
            "items": [
                {
                    "id": "recon_scan",
                    "label": "Scanner",
                    "type": "module",
                    "module_id": "recon_scan",
                    "description": "Timed scan of nearby APs and stations.",
                    "controls": [
                        {
                            "id": "interface",
                            "label": "Interface",
                            "kind": "select",
                            "source": "tool_interfaces",
                            "arg": "--interface",
                            "required": True,
                            "default": "auto",
                        },
                        {
                            "id": "duration",
                            "label": "Timeout",
                            "kind": "range",
                            "arg": "--duration",
                            "min": 8,
                            "max": 120,
                            "step": 2,
                            "default": 24,
                            "suffix": "s",
                        },
                    ],
                },
                {
                    "id": "recon_sniff",
                    "label": "Sniffer",
                    "type": "module",
                    "module_id": "recon_sniff",
                    "description": "Channel-hopping sniffer with timed stop.",
                    "controls": [
                        {
                            "id": "interface",
                            "label": "Interface",
                            "kind": "select",
                            "source": "tool_interfaces",
                            "arg": "--interface",
                            "required": True,
                            "default": "auto",
                        },
                        {
                            "id": "duration",
                            "label": "Timeout",
                            "kind": "range",
                            "arg": "--duration",
                            "min": 15,
                            "max": 300,
                            "step": 5,
                            "default": 90,
                            "suffix": "s",
                        },
                        {
                            "id": "update_interval",
                            "label": "Refresh",
                            "kind": "range",
                            "arg": "--update-interval",
                            "min": 0.2,
                            "max": 2.0,
                            "step": 0.1,
                            "default": 0.8,
                            "suffix": "s",
                        },
                    ],
                },
            ],
        },
        {
            "id": "attacks",
            "label": "Attacks",
            "icon": "ATK",
            "type": "group",
            "description": "Attack workflows available in SwissKnife.",
            "items": [
                {
                    "id": "deauth",
                    "label": "Deauth",
                    "type": "module",
                    "module_id": "deauth",
                    "description": "Deauthentication workflow.",
                    "controls": [
                        {
                            "id": "interface",
                            "label": "Interface",
                            "kind": "select",
                            "source": "tool_interfaces",
                            "default": "auto",
                        },
                        {
                            "id": "scan_depth",
                            "label": "Scan Depth",
                            "kind": "range",
                            "min": 10,
                            "max": 90,
                            "step": 5,
                            "default": 25,
                            "suffix": "s",
                        },
                    ],
                },
                {
                    "id": "portal",
                    "label": "Portal",
                    "type": "module",
                    "module_id": "portal",
                    "description": "Captive portal workflow.",
                    "controls": [
                        {
                            "id": "ap_interface",
                            "label": "AP Interface",
                            "kind": "select",
                            "source": "tool_interfaces",
                            "default": "auto",
                            "arg": "--ap-interface",
                        },
                        {
                            "id": "scan_duration",
                            "label": "Scan Time",
                            "kind": "range",
                            "min": 10,
                            "max": 120,
                            "step": 5,
                            "default": 25,
                            "suffix": "s",
                            "arg": "--scan-duration",
                        },
                        {
                            "id": "ap_ssid",
                            "label": "AP Name",
                            "kind": "text",
                            "default": "",
                            "placeholder": "np. Free_WiFi",
                            "arg": "--ap-ssid",
                        },
                        {
                            "id": "portal_file",
                            "label": "Portal",
                            "kind": "select",
                            "source": "portal_templates",
                            "options": [{"value": "portal.html", "label": "portal.html"}],
                            "default": "portal.html",
                            "arg": "--portal-file",
                        },
                    ],
                },
                {
                    "id": "twins",
                    "label": "Evil Twin",
                    "type": "module",
                    "module_id": "twins",
                    "description": "Rogue AP + portal workflow.",
                    "controls": [
                        {
                            "id": "attack_interface",
                            "label": "Attack Interface",
                            "kind": "select",
                            "source": "tool_interfaces",
                            "default": "auto",
                        },
                        {
                            "id": "ap_interface",
                            "label": "AP Interface",
                            "kind": "select",
                            "source": "tool_interfaces",
                            "default": "auto",
                        },
                        {
                            "id": "scan_duration",
                            "label": "Recon Time",
                            "kind": "range",
                            "min": 10,
                            "max": 120,
                            "step": 5,
                            "default": 25,
                            "suffix": "s",
                        },
                    ],
                },
                {
                    "id": "handshaker",
                    "label": "Handshaker",
                    "type": "module",
                    "module_id": "handshaker",
                    "description": "Under construction module.",
                    "under_construction": True,
                    "controls": [
                        {
                            "id": "interface",
                            "label": "Interface",
                            "kind": "select",
                            "source": "tool_interfaces",
                            "default": "auto",
                        },
                        {
                            "id": "scan_duration",
                            "label": "Scan Time",
                            "kind": "range",
                            "min": 10,
                            "max": 120,
                            "step": 5,
                            "default": 25,
                            "suffix": "s",
                        },
                    ],
                },
                {
                    "id": "karma",
                    "label": "Karma",
                    "type": "module",
                    "description": "Under construction module.",
                    "disabled": True,
                    "under_construction": True,
                },
            ],
        },
        {
            "id": "bluetooth",
            "label": "Bluetooth",
            "icon": "BT",
            "type": "module",
            "module_id": "bluetooth",
            "description": "Bluetooth and BLE workflows.",
            "controls": [
                {
                    "id": "scan_mode",
                    "label": "Mode",
                    "kind": "select",
                    "options": [
                        {"value": "bt", "label": "Bluetooth"},
                        {"value": "ble", "label": "BLE"},
                    ],
                    "default": "bt",
                },
                {
                    "id": "timeout",
                    "label": "Timeout",
                    "kind": "range",
                    "min": 10,
                    "max": 180,
                    "step": 5,
                    "default": 30,
                    "suffix": "s",
                },
            ],
        },
        {
            "id": "loot",
            "label": "Loot",
            "icon": "LOT",
            "type": "info",
            "description": "Captured files and logs from /log.",
        },
    ]
}


def list_portal_templates() -> List[str]:
    if not HTML_DIR.is_dir():
        return []
    files = [
        path.name
        for path in HTML_DIR.iterdir()
        if path.is_file() and path.suffix.lower() == ".html"
    ]
    files.sort(key=lambda name: (name.lower() != "portal.html", name.lower()))
    return files


def list_loot_files() -> List[dict]:
    if not LOG_DIR.is_dir():
        return []
    files: List[dict] = []
    for path in LOG_DIR.iterdir():
        if not path.is_file():
            continue
        stat = path.stat()
        files.append(
            {
                "name": path.name,
                "size_bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            }
        )
    files.sort(key=lambda item: item["modified_at"], reverse=True)
    return files


def resolve_loot_file(raw_name: str, must_exist: bool = True) -> Path:
    name = Path((raw_name or "").strip()).name
    if not name:
        raise HTTPException(status_code=400, detail="Loot file name cannot be empty.")

    log_root = LOG_DIR.resolve()
    path = (log_root / name).resolve()
    if path.parent != log_root:
        raise HTTPException(status_code=400, detail="Invalid loot file path.")
    if must_exist and (not path.is_file() or not path.exists()):
        raise HTTPException(status_code=404, detail=f"Loot file not found: {name}")
    return path


def _read_interface_driver(interface: str) -> tuple[str, str]:
    try:
        result = subprocess.run(
            ["ethtool", "-i", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return "unknown", ""
    if result.returncode != 0:
        return "unknown", ""

    driver = "unknown"
    bus_info = ""
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("driver:"):
            value = line.split(":", 1)[1].strip()
            if value:
                driver = value
        if line.startswith("bus-info:"):
            value = line.split(":", 1)[1].strip()
            if value:
                bus_info = value
    return driver, bus_info


def _interface_payload(interface: str, builtin_iface: str) -> dict:
    driver, bus_info = _read_interface_driver(interface)
    label = f"{interface} · {driver}" if driver else interface
    if bus_info:
        label = f"{label} ({bus_info})"
    return {
        "name": interface,
        "driver": driver,
        "bus_info": bus_info,
        "is_builtin": interface == builtin_iface,
        "label": label,
    }


def collect_interface_payload() -> dict:
    try:
        builtin_iface = detect_builtin_wireless_interface()
    except RuntimeError:
        builtin_iface = ""

    all_wireless = list_wireless_interfaces()
    all_details = [_interface_payload(iface, builtin_iface) for iface in all_wireless]
    tool_details = [entry for entry in all_details if not entry["is_builtin"]]

    return {
        "builtin_interface": builtin_iface,
        "all_wireless": [entry["name"] for entry in all_details],
        "all_interfaces": all_details,
        "tool_interfaces": tool_details,
        "tool_interface_names": [entry["name"] for entry in tool_details],
    }


class StartTaskRequest(BaseModel):
    module_id: str
    args: List[str] = Field(default_factory=list)
    raw_args: str = ""


class TaskInputRequest(BaseModel):
    text: str


def create_app(
    manager: ProcessManager,
    auth_token: Optional[str],
    ap_manager: Optional[AccessPointManager],
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if ap_manager:
            ap_manager.start()
            cfg = ap_manager.config
            active_channel = getattr(ap_manager, "active_channel", cfg.channel)
            if ap_manager.dhcp_enabled and ap_manager.dns_enabled:
                LOG.info(
                    "AP mode started on %s (%s) channel %s with DHCP+DNS",
                    cfg.interface,
                    cfg.ap_ip,
                    active_channel,
                )
            elif ap_manager.dhcp_enabled:
                LOG.warning(
                    "AP mode started on %s (%s) channel %s in DHCP-only mode (DNS port 53 busy). "
                    "Open panel by IP: http://%s",
                    cfg.interface,
                    cfg.ap_ip,
                    active_channel,
                    cfg.ap_ip,
                )
            else:
                LOG.warning(
                    "AP mode started on %s (%s) channel %s in AP-only mode (no DHCP/DNS due socket conflicts). "
                    "Set client static IP in %s/%s and open http://%s",
                    cfg.interface,
                    cfg.ap_ip,
                    active_channel,
                    cfg.ap_ip,
                    cfg.cidr_prefix,
                    cfg.ap_ip,
                )
        try:
            yield
        finally:
            manager.shutdown()
            if ap_manager:
                ap_manager.stop()

    app = FastAPI(
        title="SwissKnife Web UI",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def _require_auth(request: Request) -> None:
        if not auth_token:
            return
        provided = request.headers.get(TOKEN_HEADER, "")
        if not provided or not secrets.compare_digest(provided, auth_token):
            raise HTTPException(status_code=401, detail="Unauthorized")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/meta")
    async def api_meta():
        return {
            "auth_required": bool(auth_token),
            "token_header": TOKEN_HEADER,
            "active_task_id": manager.active_task_id,
        }

    @app.get("/api/menu", dependencies=[Depends(_require_auth)])
    async def api_menu():
        return MENU_SCHEMA

    @app.get("/api/modules", dependencies=[Depends(_require_auth)])
    async def api_modules():
        return {"modules": manager.list_modules()}

    @app.get("/api/interfaces", dependencies=[Depends(_require_auth)])
    async def api_interfaces():
        return collect_interface_payload()

    @app.get("/api/portals", dependencies=[Depends(_require_auth)])
    async def api_portals():
        return {"templates": list_portal_templates()}

    @app.get("/api/loot", dependencies=[Depends(_require_auth)])
    async def api_loot():
        return {"files": list_loot_files()}

    @app.get("/api/loot/view", dependencies=[Depends(_require_auth)])
    async def api_loot_view(
        name: str = Query(default="", min_length=1),
        tail: int = Query(default=300, ge=20, le=5000),
    ):
        path = resolve_loot_file(name, must_exist=True)
        stat = path.stat()
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        truncated = False
        if len(lines) > tail:
            lines = lines[-tail:]
            truncated = True
        return {
            "name": path.name,
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            "line_count": len(lines),
            "truncated": truncated,
            "text": "\n".join(lines),
        }

    @app.delete("/api/loot", dependencies=[Depends(_require_auth)])
    async def api_loot_delete(name: str = Query(default="", min_length=1)):
        path = resolve_loot_file(name, must_exist=True)
        path.unlink(missing_ok=False)
        return {"deleted": path.name}

    @app.get("/api/tasks", dependencies=[Depends(_require_auth)])
    async def api_tasks():
        return {
            "tasks": manager.list_tasks(),
            "active_task_id": manager.active_task_id,
        }

    @app.get("/api/tasks/{task_id}", dependencies=[Depends(_require_auth)])
    async def api_task(task_id: str):
        try:
            return {"task": manager.get_task_snapshot(task_id)}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/tasks/{task_id}/result", dependencies=[Depends(_require_auth)])
    async def api_task_result(task_id: str):
        try:
            return {"result": manager.get_task_result(task_id)}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/tasks/start", dependencies=[Depends(_require_auth)])
    async def api_start_task(payload: StartTaskRequest):
        args = list(payload.args)
        if payload.raw_args.strip():
            try:
                args.extend(shlex.split(payload.raw_args))
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"Invalid args string: {exc}") from exc

        try:
            task = manager.start_task(payload.module_id, args=args)
            return {"task": task}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except TaskError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/tasks/{task_id}/stop", dependencies=[Depends(_require_auth)])
    async def api_stop_task(task_id: str):
        try:
            task = manager.stop_task(task_id)
            return {"task": task}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/tasks/{task_id}/input", dependencies=[Depends(_require_auth)])
    async def api_task_input(task_id: str, payload: TaskInputRequest):
        try:
            task = manager.send_input(task_id, payload.text)
            return {"task": task}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except TaskError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/tasks/{task_id}/logs", dependencies=[Depends(_require_auth)])
    async def api_task_logs(
        task_id: str,
        since: int = Query(default=0, ge=0),
        wait: bool = Query(default=False),
        timeout: float = Query(default=0.0, ge=0.0, le=10.0),
    ):
        effective_timeout = timeout if wait else 0.0
        try:
            entries, cursor, first_seq, running = manager.wait_for_logs(
                task_id,
                since=since,
                timeout=effective_timeout,
            )
            return {
                "entries": entries,
                "cursor": cursor,
                "first_seq": first_seq,
                "running": running,
            }
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.websocket("/ws/tasks/{task_id}")
    async def ws_task_logs(websocket: WebSocket, task_id: str) -> None:
        if auth_token:
            provided = websocket.query_params.get("token", "")
            if not provided or not secrets.compare_digest(provided, auth_token):
                await websocket.close(code=1008)
                return

        await websocket.accept()

        since_param = websocket.query_params.get("since", "0")
        try:
            since = max(int(since_param), 0)
        except ValueError:
            since = 0

        sent_stopped = False

        while True:
            try:
                entries, cursor, first_seq, running = await asyncio.to_thread(
                    manager.wait_for_logs,
                    task_id,
                    since,
                    1.0,
                )
            except KeyError:
                await websocket.send_json({"type": "error", "message": "Task not found"})
                await websocket.close(code=1008)
                return
            except WebSocketDisconnect:
                return

            if entries:
                await websocket.send_json(
                    {
                        "type": "logs",
                        "entries": entries,
                        "cursor": cursor,
                        "first_seq": first_seq,
                    }
                )
                since = cursor

            if not running and not sent_stopped:
                sent_stopped = True
                try:
                    snapshot = manager.get_task_snapshot(task_id)
                except KeyError:
                    snapshot = None
                await websocket.send_json({"type": "task", "task": snapshot})

            try:
                # Keep the socket responsive to disconnects/pings from the browser.
                await asyncio.wait_for(websocket.receive_text(), timeout=0.01)
            except asyncio.TimeoutError:
                pass
            except WebSocketDisconnect:
                return

    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SwissKnife Web UI server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--token", default="", help="Auth token for API access")
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable token auth (not recommended on exposed networks).",
    )
    parser.add_argument(
        "--max-log-lines",
        type=int,
        default=5000,
        help="Maximum in-memory log lines per task (default: 5000).",
    )

    parser.add_argument(
        "--ap-interface",
        default="builtin",
        help="AP interface selector; must be 'builtin' (default).",
    )
    parser.add_argument("--ap-ssid", default="SwissKnife-Control", help="SSID for AP mode")
    parser.add_argument("--ap-channel", type=int, default=6, help="Wi-Fi channel for AP mode")
    parser.add_argument("--ap-ip", default="10.10.0.1", help="AP gateway IP")
    parser.add_argument("--ap-cidr", type=int, default=24, help="CIDR prefix for AP network")
    parser.add_argument("--ap-dhcp-start", default="10.10.0.10", help="DHCP pool start")
    parser.add_argument("--ap-dhcp-end", default="10.10.0.200", help="DHCP pool end")
    parser.add_argument("--ap-dhcp-lease", default="12h", help="DHCP lease time")
    return parser.parse_args()


def resolve_auth_token(cli_token: str, no_auth: bool) -> Optional[str]:
    if no_auth:
        return None
    if cli_token:
        return cli_token
    env_token = os.environ.get(TOKEN_ENV_VAR, "").strip()
    if env_token:
        return env_token
    return secrets.token_urlsafe(20)


def build_ap_manager(args: argparse.Namespace) -> AccessPointManager:
    ap_interface = (args.ap_interface or "").strip().lower()
    if ap_interface in ("builtin", "internal", "auto"):
        interface = detect_builtin_wireless_interface()
    else:
        raise RuntimeError(
            "AP interface is fixed to built-in Wi-Fi. Use --ap-interface builtin."
        )
    if not interface:
        raise RuntimeError("AP interface cannot be empty.")
    config = ApModeConfig(
        interface=interface,
        ssid=args.ap_ssid,
        channel=args.ap_channel,
        ap_ip=args.ap_ip,
        cidr_prefix=args.ap_cidr,
        dhcp_start=args.ap_dhcp_start,
        dhcp_end=args.ap_dhcp_end,
        dhcp_lease=args.ap_dhcp_lease,
    )
    return AccessPointManager(config)


def main() -> None:
    args = parse_args()
    auth_token = resolve_auth_token(args.token.strip(), args.no_auth)

    manager = ProcessManager(max_log_lines=args.max_log_lines)
    try:
        ap_manager = build_ap_manager(args)
    except RuntimeError as exc:
        raise SystemExit(f"[webui] AP mode setup failed: {exc}") from exc
    app = create_app(manager, auth_token, ap_manager)

    if auth_token:
        print(f"[webui] token required in header {TOKEN_HEADER}: {auth_token}")
    else:
        print("[webui] auth disabled")
    display_host = args.host if args.host not in ("0.0.0.0", "::") else "<device-ip>"
    print(f"[webui] panel url: http://{display_host}:{args.port}")
    if ap_manager:
        print(
            f"[webui] AP mode requested: ssid={ap_manager.config.ssid} ip={ap_manager.config.ap_ip} "
            f"iface={ap_manager.config.interface}"
        )
        print(f"[webui] AP panel url: http://{ap_manager.config.ap_ip}:{args.port}")

    import uvicorn

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level="info",
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()
