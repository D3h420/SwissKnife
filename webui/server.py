#!/usr/bin/env python3

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import secrets
import shlex
import sys
from contextlib import asynccontextmanager
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
                },
                {
                    "id": "portal",
                    "label": "Portal",
                    "type": "module",
                    "module_id": "portal",
                    "description": "Captive portal workflow.",
                },
                {
                    "id": "twins",
                    "label": "Evil Twin",
                    "type": "module",
                    "module_id": "twins",
                    "description": "Rogue AP + portal workflow.",
                },
                {
                    "id": "handshaker",
                    "label": "Handshaker",
                    "type": "module",
                    "module_id": "handshaker",
                    "description": "Under construction module.",
                    "under_construction": True,
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
        },
        {
            "id": "exit",
            "label": "Exit",
            "icon": "EXT",
            "type": "info",
            "description": "Equivalent to exit option in CLI launcher.",
        },
    ]
}


def collect_interface_payload() -> dict:
    try:
        builtin_iface = detect_builtin_wireless_interface()
    except RuntimeError:
        builtin_iface = ""

    all_wireless = list_wireless_interfaces()
    tool_wireless = [iface for iface in all_wireless if iface != builtin_iface]

    return {
        "builtin_interface": builtin_iface,
        "all_wireless": all_wireless,
        "tool_interfaces": tool_wireless,
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
            if ap_manager.dhcp_enabled and ap_manager.dns_enabled:
                LOG.info("AP mode started on %s (%s) with DHCP+DNS", cfg.interface, cfg.ap_ip)
            elif ap_manager.dhcp_enabled:
                LOG.warning(
                    "AP mode started on %s (%s) in DHCP-only mode (DNS port 53 busy). "
                    "Open panel by IP: http://%s",
                    cfg.interface,
                    cfg.ap_ip,
                    cfg.ap_ip,
                )
            else:
                LOG.warning(
                    "AP mode started on %s (%s) in AP-only mode (no DHCP/DNS due socket conflicts). "
                    "Set client static IP in %s/%s and open http://%s",
                    cfg.interface,
                    cfg.ap_ip,
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
