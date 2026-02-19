# SwissKnife Web UI

Web control panel that launches existing SwissKnife scripts without rewriting
module logic. It manages processes and forwards interactive input (`input()`)
through the browser console.

Recon has dedicated non-interactive Web UI actions:
- `recon_scan` (`webui/actions/recon_scan.py`)
- `recon_sniff` (`webui/actions/recon_sniff.py`)

These are designed for click-through control (no numeric menu prompts).
Recon results are exposed as structured payloads and displayed in a fixed UI panel.

## Install

```bash
cd /path/to/SwissKnife
python3 -m venv .venv
source .venv/bin/activate
pip install -r webui/requirements.txt
```

## Run

```bash
sudo python3 -m webui.server --host 0.0.0.0 --port 8000
```

The server prints an auth token in terminal output.
Open `http://<device-ip>:8000`, paste the token, then start modules.
If you join AP mode SSID (`SwissKnife-Control`), open `http://10.10.0.1:8000`.

When started from `swiss_knife.py`, token is persisted in `webui/.webui_token`,
so browser login is typically needed only once per device/browser.

Default AP behavior:
- AP mode is enabled by default.
- Interface is auto-selected as built-in Wi-Fi (`--ap-interface builtin`).
- This leaves external adapters (for example `wlan1`, `wlan2`) free for modules.

Interface API:
- `GET /api/interfaces` returns built-in AP interface and tool-capable adapters.

## API auth

- Header name: `X-SwissKnife-Token`
- Env override: `SWISSKNIFE_WEBUI_TOKEN`
- Disable auth (local trusted lab only): `--no-auth`

## AP mode options

Built-in interface selection (default):

```bash
sudo python3 -m webui.server \
  --host 0.0.0.0 \
  --port 8000 \
  --ap-interface builtin \
  --ap-ssid SwissKnife-Control \
  --ap-ip 10.10.0.1 \
  --ap-cidr 24 \
  --ap-dhcp-start 10.10.0.10 \
  --ap-dhcp-end 10.10.0.200
```

AP mode needs `hostapd`, `dnsmasq`, and `ip`.

## Notes

- Run as root for wireless operations and module compatibility.
- Only one module task can run at a time to avoid RF interface conflicts.
- Logs are buffered in memory (default: 5000 lines per task).
