<p align="center">
  <img alt="SwissKnife Hero" src="https://github.com/user-attachments/assets/d56f9519-c044-4daf-a3f7-2de0f2e82a32" />
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="Linux" src="https://img.shields.io/badge/OS-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" />
  <img alt="Root Required" src="https://img.shields.io/badge/Privileges-root_required-CC0000?style=for-the-badge&logo=gnu-bash&logoColor=white" />
  <img alt="Auto Dependencies" src="https://img.shields.io/badge/Dependencies-auto_check_%26_install-0A7E07?style=for-the-badge" />
</p>

# SwissKnife 🧰

SwissKnife is a menu-driven wireless security toolkit that combines recon, Wi-Fi attacks, captive portal workflows, Bluetooth scanning, and LAN-side utilities in one place. ⚡

## Attacks & Features 🔥

| Module | Category | Status | Description |
|---|---|---|---|
| `Recon` | Recon | ✅ | Live AP/client discovery + sniffer mode (`aircrack-ng` based). |
| `Deauth` | Wi-Fi Attack | ✅ | Multi-method deauth (`aireplay-ng`, `mdk4`, optional `bully`). |
| `Portal` | Captive Portal | ✅ | Rogue AP + `hostapd`/`dnsmasq` + credential capture logs. |
| `Evil Twin` | Captive + Deauth | ✅ | Deauth + cloned AP + portal workflow with restart loop. |
| `Handshaker` | Capture | ✅ | 4-way handshake capture to PCAP (Scapy-based validation). |
| `Dragon Drain` | WPA3 | ✅ | Bootstrap/build + single-target Dragon Drain workflow. |
| `Bluetooth` | BT Recon | ✅ | Live Bluetooth scan (`bluetoothctl`/`btmgmt` backends). |
| `Karma` | Rogue AP | 🟡 MVP | SSID impersonation helper + captive portal launch flow. |
| `ARP Scan` | LAN Internal | ✅ | ARP host discovery with vendor lookup support. |
| `IP.CAM Finder` | LAN Internal | ✅ | Camera candidate detection by OUI/SSID + LAN correlation. |
| `WiFi Poet` | Beacon Spam | 🧪 | Test-edition SSID beacon spam (chaos/custom sets). |

## Quick Start 🚀

```bash
git clone https://github.com/D3h420/SwissKnife
cd SwissKnife
sudo chmod +x swiss_knife.py
sudo python3 swiss_knife.py
```

## Requirements ✅

- Linux
- Python `3.10+`
- Root privileges
- Wi-Fi adapter(s) with monitor mode support
- Python runtime dependency: `scapy`
- Missing tools are auto-detected at startup and can be installed automatically.

Debian/Ubuntu example:

```bash
sudo apt update
sudo apt install -y aircrack-ng iproute2 ethtool arp-scan hostapd dnsmasq iptables bluez rfkill wireless-tools network-manager avahi-daemon bully
```

## Project Layout 📁

- `swiss_knife.py` - main launcher, menus, dependency checks
- `modules/` - all workflows/modules
- `core/wifi_iface.py` - shared Wi-Fi interface helpers
- `html/` - captive portal templates
- `log/` - captured submissions, handshakes, and runtime artifacts

## Notes 📝

- `Dragon Drain` keeps its own build/install flow inside the module.
- `rich` is optional (used for nicer output in selected modules).
- Vendor lookups can be backed by `modules/oui.txt`.

## Legal ⚠️

Use only on infrastructure you own or have explicit permission to test.

/LAB5/
