<p align="center">
  <img width="1536" height="1024" alt="swissknife_banner" src="https://github.com/user-attachments/assets/fab355b9-d7d0-4431-b486-61795bdfee6d" />
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="OS" src="https://img.shields.io/badge/OS-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" />
  <img alt="Root" src="https://img.shields.io/badge/Privileges-root_required-CC0000?style=for-the-badge&logo=gnu-bash&logoColor=white" />
  <img alt="Deps" src="https://img.shields.io/badge/Dependencies-auto_check_%26_install-0A7E07?style=for-the-badge" />
</p>

# SwissKnife 🧰

SwissKnife is a menu-driven wireless security toolkit for recon, attack workflows, captive portals, and wardriving in one place ⚡

## Attacks & Features 🔥

| Module | Category | Status | Description |
|---|---|---|---|
| `Recon` | Recon | ✅ | Live AP/client discovery + sniffer mode (`aircrack-ng` based). |
| `Deauth` | Wi-Fi Attack | ✅ | Multi-method deauth (`aireplay-ng`, `mdk4`, optional `bully`). |
| `Portal` | Captive Portal | ✅ | Rogue AP + `hostapd`/`dnsmasq` + credential capture logs. |
| `Evil Twin` | Captive + Deauth | ✅ | Deauth + cloned AP + portal workflow with restart loop. |
| `Handshaker` | Capture | ✅ | 4-way handshake capture to PCAP (Scapy-based validation). |
| `Dragon Drain` | WPA3 | ✅ | Bootstrap/build + single-target Dragon Drain workflow. |
| `Wardrive` | GPS + Wi-Fi Survey | ✅ | Wigle-format logging (`wardrive_1.log`, `wardrive_2.log`, ...) with GPS fix validation. |
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
- USB GPS dongle (for wardrive GPS tagging)
- Python runtime dependency: `scapy`
- Missing tools are auto-detected at startup and can be installed automatically.

Debian/Ubuntu example:

```bash
sudo apt update
sudo apt install -y aircrack-ng iproute2 ethtool arp-scan hostapd dnsmasq iptables usbutils rfkill wireless-tools network-manager avahi-daemon bully
```

## Project Layout 📁

- `swiss_knife.py` - main launcher, menus, dependency checks
- `modules/` - all attack/workflow modules
- `core/wifi_iface.py` - shared Wi-Fi interface helpers
- `html/` - portal templates
- `log/` - captured submissions, handshakes, wardrive logs

## Notes 📝

- `Dragon Drain` keeps its own build/install flow inside the module.
- `rich` is optional (used for nicer output in selected modules).
- Vendor lookups can be backed by `modules/oui.txt`.

## Troubleshooting: DHCP/AP Conflict on Raspberry Pi 🧯

If `Evil Twin`/`Portal` fails with:

`dnsmasq: failed to bind DHCP server socket: Address already in use`

you are usually running into a double-DHCP situation:
- one `dnsmasq` already runs for Raspberry AP/hotspot (`wlan0`),
- second `dnsmasq` is started by the module for another interface.

In short: one port `67/udp`, two services, zero chill 😅

### What happened (real-world pain summary)

- AP on built-in `wlan0` was active (`rpi-ap` via NetworkManager).
- `dnsmasq` was already listening on `0.0.0.0:67`.
- attack module tried to spawn another `dnsmasq`.
- result: instant fail + evening burned in terminal 🔥🫠

### Quick diagnostics

```bash
sudo ss -lunp 'sport = :67'
sudo lsof -nP -iUDP:67
nmcli device status
nmcli -t -f NAME,TYPE connection show
```

### Stable fix path (Ethernet-only operation)

Use this when you want zero AP/hotspot conflicts and operate only over `eth0`:

```bash
sudo nmcli con down rpi-ap 2>/dev/null || true
sudo nmcli con delete rpi-ap 2>/dev/null || true
sudo systemctl stop hostapd dnsmasq 2>/dev/null || true
sudo systemctl disable hostapd dnsmasq 2>/dev/null || true
sudo pkill -f hostapd 2>/dev/null || true
sudo pkill -f dnsmasq 2>/dev/null || true
sudo ss -lunp 'sport = :67'
ip -br a show eth0
ip route
ping -c 3 8.8.8.8
```

Expected:
- no listener on `:67`,
- `eth0` has IP and default route,
- ping works.

### Recommended interface model

- `wlan0` (built-in): optional management AP only.
- `wlan1`/`wlan2` (USB): tooling interfaces (`unmanaged` in NM).
- `eth0`: primary stable control path.

If you mix multiple AP/DHCP managers at once, chaos engineering will mix you back 🤖💥

## Legal ⚠️

This toolkit is for authorized security testing, research, and lab use only.

By using SwissKnife, you agree that:
- You will test only systems you own or have explicit written authorization to assess.
- You are solely responsible for complying with local, national, and international laws.
- You accept full responsibility for any misuse, damage, service disruption, or legal consequences.

If you are unsure whether you are authorized, do not run the tool.

/LAB5/
