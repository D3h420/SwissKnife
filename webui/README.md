# SwissKnife Web UI

Web control panel that launches existing SwissKnife scripts without rewriting
module logic. It manages processes and forwards interactive input (`input()`)
through the browser console.

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

## API auth

- Header name: `X-SwissKnife-Token`
- Env override: `SWISSKNIFE_WEBUI_TOKEN`
- Disable auth (local trusted lab only): `--no-auth`

## Optional AP mode

This can create a local AP for the control panel itself.

```bash
sudo python3 -m webui.server \
  --host 0.0.0.0 \
  --port 8000 \
  --ap-interface wlan1 \
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

