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
- Dragon Drain - single-target Dragon Drain attack (BSSID + channel)
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

- Linux + Python 3 + root access
- Wi-Fi adapter(s) that support monitor mode (recommended: dedicated attack adapter)
- Runtime Python dependency: `scapy` (launcher checks/installs automatically when possible)

Debian/Ubuntu quick install:
```bash
sudo apt update
sudo apt install -y aircrack-ng iproute2 ethtool arp-scan hostapd dnsmasq iptables bluez rfkill wireless-tools network-manager avahi-daemon bully
```

Notes:
- Dragon Drain has its own in-module installer/build flow.
- `rich` is optional (only for prettier output in selected modules).

## Dev architecture 🛠️

Wi-Fi interface primitives are now centralized in `core/wifi_iface.py`
(`list/get mode/chipset`, monitor/managed switching, restore helpers).
Attack modules consume this shared layer to reduce duplicated logic and
keep interface handling behavior consistent.

## Recon vendor lookup (optional)

If you want vendor names in recon results, add an OUI file at `modules/oui.txt`

## Legal note ⚠️

Use only on networks you own or have explicit permission to test.

/LAB5/
