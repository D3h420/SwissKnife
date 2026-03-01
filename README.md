<img alt="CAA34C68-2185-46F5-BA61-2F88DF8FEC73" src="https://github.com/user-attachments/assets/d56f9519-c044-4daf-a3f7-2de0f2e82a32" />

# SwissKnife 🧰

Wireless "swiss knife" that bundles multiple workflows into one menu-driven tool.
The main entry point is `swiss_knife.py`. Control the chaos with
[Lab5](https://github.com/C5Lab) (responsibly).

## Functions ✨

- Recon - passive discovery of nearby APs/clients
- Deauth - network deauthentication workflow
- Portal - phishing-style portal with logging
- Evil Twin - rogue AP + portal workflow
- Bluetooth - BT scan workflow
- Handshaker - PCAP capture + 4-way EAPOL validation
- ARP scan - ARP table discovery (IP/MAC/OUI vendor)
- IP.CAM finder - camera discovery by Wi-Fi OUI + LAN neighbor scan
- ~~Karma - rogue AP auto-responder~~ (🚧 under construction 🚧)

## Quick start ⚡

```bash
git clone https://github.com/D3h420/SwissKnife
cd SwissKnife
sudo chmod +x swiss_knife.py
python3 swiss_knife.py
```

Run as root (required for wireless operations). The menu lets you choose which
attack to run and guides you through the steps.

`swiss_knife.py` now auto-starts Web UI in background on launch (port `8000`).
The launcher now keeps a persistent Web UI token in `webui/.webui_token`.
After first login in browser, token entry is automatic on next runs.
When connecting through the SwissKnife AP, use `http://10.10.0.1:8000`.

## Web UI control panel 🌐

Web UI starts automatically with `swiss_knife.py`, but you can also run it
standalone:

```bash
pip install -r webui/requirements.txt
sudo python3 -m webui.server --host 0.0.0.0 --port 8000
```

Open `http://<device-ip>:8000` and start/stop modules from the panel.
On first launch, use the token shown in terminal (or from `webui/.webui_token`);
later runs reuse the same token automatically via browser storage.
Existing module logic is unchanged.

Web UI now starts with an intro/login screen:
- default panel password: `SwissKnife`
- default password is defined in code as `PANEL_DEFAULT_PASSWORD` in `webui/server.py`
- intro password field is intentionally empty (no suggested value in input box)
- password can be changed from the top-right settings gear
- `Turn off` in settings requests full launcher shutdown (equivalent to CLI exit)
- password hash is stored in `webui/.webui_password.json`
- dev cache mode is enabled by default (`SWISSKNIFE_WEBUI_DEV_NOCACHE=1`) to force fresh UI files and avoid stale browser cache during Web UI work
- to disable dev cache mode: run with `SWISSKNIFE_WEBUI_DEV_NOCACHE=0`

Recon in Web UI is now click-first:
- `Scanner` action: interface selector + timeout slider
- `Sniffer` action: interface selector + timeout/refresh sliders
- no numeric `input()` menu selection required for these recon actions
- results are rendered in a fixed Recon Results panel (without infinite live-log growth)

By default, Web UI AP mode starts on the built-in Wi-Fi interface (`--ap-interface builtin`).
This keeps external adapters (for example `wlan1`, `wlan2`) free for modules.

Full options are documented in `webui/README.md`.

## Logs and captures 🧾

Captive Portal and Evil Twin store captured submissions in `log/` (created on
first run). Filenames are based on the selected SSID.

## HTML portals 🎨

Portal files are stored in `html/`. You can add your own custom portals there.

## Requirements 🧩

Core:
- Python 3
- Linux with a wireless adapter that supports monitor mode
- Root privileges
- Built-in Wi-Fi interface reserved for Web UI/AP communication
- Additional adapters (for example `wlan1`, `wlan2`) for recon/attack workflows

Python packages for Web UI:
- `fastapi`
- `uvicorn`

System tools used by launcher/modules:
- `iw`
- `ip` (from `iproute2`)
- `ethtool`
- `arp-scan`
- `aireplay-ng` (Aircrack-ng suite)
- `airodump-ng` (Aircrack-ng suite)
- `mdk4`
- `hostapd`
- `dnsmasq`
- `iptables`
- `bluetoothctl` (BlueZ)
- `btmgmt` (BlueZ)

Extra tools used by specific paths/fallbacks:
- `iwlist` (wireless-tools fallback scans)
- `nmcli` (NetworkManager scan fallback)
- `ifconfig` and `iwconfig` (legacy mode fallback in deauth)
- `hciconfig` and `hcitool` (Bluetooth legacy operations)
- `rfkill` (Bluetooth unblock)
- `systemctl` (Bluetooth service control on systemd hosts)

Optional tools:
- `bully`
- `avahi-daemon` (for `<hostname>.local` discovery in local network)

Optional for Handshaker:
- `scapy`

Optional for IP.CAM finder:
- `rich`

ARP module dependency install (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install -y arp-scan
```

## Recon vendor lookup (optional)

If you want vendor names in recon results, add an OUI file at `modules/oui.txt`
or set `SWISSKNIFE_VENDOR_DB` to a custom path.

## Legal note ⚠️

Use only on networks you own or have explicit permission to test.

/LAB5/
