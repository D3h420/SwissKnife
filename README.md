<p align="center">
  <img alt="SwissKnife Hero" src="https://github.com/user-attachments/assets/d56f9519-c044-4daf-a3f7-2de0f2e82a32" />
</p>

<p align="center">
  <a href="#quick-start">
    <img alt="Quick Start" src="https://img.shields.io/badge/Quick_Start-%E2%9A%A1-111111?style=for-the-badge" />
  </a>
  <a href="#attacks--features">
    <img alt="Attacks & Features" src="https://img.shields.io/badge/Attacks_%26_Features-%F0%9F%94%A5-111111?style=for-the-badge" />
  </a>
  <a href="#dependency-auto-setup">
    <img alt="Dependency Auto Setup" src="https://img.shields.io/badge/Dependency_Auto_Setup-%F0%9F%9B%A0%EF%B8%8F-111111?style=for-the-badge" />
  </a>
</p>

# SwissKnife 🧰

`SwissKnife` is a menu-driven wireless security toolkit that bundles recon, attack workflows, captive portal modules, Bluetooth scanning, and LAN-side utilities into one launcher.

## Attacks & Features

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

## Quick Start

```bash
git clone https://github.com/D3h420/SwissKnife
cd SwissKnife
sudo chmod +x swiss_knife.py
sudo python3 swiss_knife.py
```

`root` is required for wireless operations.

## Dependency Auto-Setup

At startup, the launcher now performs a full dependency check and reports:

- `Required tools` (needed for core workflows)
- `Recommended tools` (for full module/feature coverage)

If you run the launcher as root, it can automatically install missing tools via your package manager (`apt`, `dnf`, `yum`, `pacman`, `zypper`, `apk` where possible).

## Project Layout

- `swiss_knife.py` - main launcher, menus, dependency checks
- `modules/` - all workflows/modules
- `core/wifi_iface.py` - shared Wi-Fi interface helpers
- `html/` - captive portal templates
- `log/` - captured submissions, handshakes, and runtime artifacts

## Requirements

- Linux + Python 3
- Root privileges
- Wi-Fi adapter(s) with monitor mode support
- Python runtime dependency: `scapy`

Debian/Ubuntu example:

```bash
sudo apt update
sudo apt install -y aircrack-ng iproute2 ethtool arp-scan hostapd dnsmasq iptables bluez rfkill wireless-tools network-manager avahi-daemon bully
```

## Notes

- `Dragon Drain` keeps its own build/install flow inside the module.
- `rich` is optional (used for nicer output in selected modules).
- Vendor lookups can be backed by `modules/oui.txt`.

## Legal

Use only on infrastructure you own or have explicit permission to test.

/LAB5/
