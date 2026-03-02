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
- WiFi Poet - SSID beacon spam (chaos/custom mode)
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
- Additional adapters (for example `wlan1`, `wlan2`) for recon/attack workflows

Runtime Python packages (launcher checks/installs on startup):
- `scapy` (required by Handshaker)

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
- `wpa_supplicant` + DHCP client (`dhclient` or `dhcpcd` or `udhcpc`) as connect fallback in ARP/IP.CAM modules
- `ifconfig` and `iwconfig` (legacy mode fallback in deauth)
- `hciconfig` and `hcitool` (Bluetooth legacy operations)
- `rfkill` (Bluetooth unblock)
- `systemctl` (Bluetooth service control on systemd hosts)

Optional tools:
- `bully`
- `avahi-daemon` (for `<hostname>.local` discovery in local network)

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
