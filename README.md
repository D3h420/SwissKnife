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
- Bluetooth - BT scan + BLE Poet workflow
- ~~Handshaker - PCAP capture~~ (🚧 under construction 🚧)
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
The CLI header shows panel URLs and the current auth token.
When connecting through the SwissKnife AP, use `http://10.10.0.1:8000`.

## Web UI control panel 🌐

Web UI starts automatically with `swiss_knife.py`, but you can also run it
standalone:

```bash
pip install -r webui/requirements.txt
sudo python3 -m webui.server --host 0.0.0.0 --port 8000
```

Open `http://<device-ip>:8000`, paste the token printed in terminal output, and
start/stop modules from the panel. Existing module logic is unchanged.

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
- `aireplay-ng` (Aircrack-ng suite)
- `airodump-ng` (Aircrack-ng suite)
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
- `mdk4`
- `bully`
- `avahi-daemon` (for `<hostname>.local` discovery in local network)

Optional for Handshaker:
- `scapy`

## Recon vendor lookup (optional)

If you want vendor names in recon results, add an OUI file at `modules/oui.txt`
or set `SWISSKNIFE_VENDOR_DB` to a custom path.

## Legal note ⚠️

Use only on networks you own or have explicit permission to test.
