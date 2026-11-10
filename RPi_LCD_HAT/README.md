# RPi_LCD_HAT

RPi_LCD_HAT is the small-screen interface for SwissKnife on a Raspberry Pi Zero 2 W. It shows the project logo until any button is pressed, lets you browse menus with the HAT's joystick, and provides an on-screen keyboard where a workflow needs text input. The existing SwissKnife modules still perform the actual work; their external Wi-Fi adapter and tool requirements remain in force.

The target HAT is the **Seengreat 1.44-inch LCD Display for Raspberry Pi**, with a 128 × 128 ST7735S panel, SPI interface, six buttons, and a five-direction joystick. It is a different HAT from the Waveshare display used by RaspyJack. Pin numbers below use **BCM GPIO numbering**, as in the [Seengreat hardware guide](https://seengreat.com/wiki/68/1-44inch-lcd-display).

## Hardware connections

| Function | BCM GPIO |
| --- | ---: |
| LCD SPI MOSI / SCK / CE0 | 10 / 11 / 8 |
| LCD data/command / reset / backlight | 25 / 27 / 24 |
| Buttons K1 / K2 / K3 / K4 | 17 / 18 / 22 / 23 |
| Buttons R / L | 20 / 21 |
| Joystick left / down / center / up | 5 / 26 / 6 / 13 |
| Joystick right | 19 |

The Seengreat guide labels BCM 19 as a second **DOWN**, but the manufacturer's [key demo](https://github.com/seengreat/1.44inch-LCD-Display/blob/main/lgpio/python/key_demo.py) explicitly assigns **RIGHT** to BCM 19 and **DOWN** to BCM 26. Button inputs use pull-ups and are active when pressed.

## Install on Raspberry Pi OS

The installer targets **Raspberry Pi Zero 2 W** with the Seengreat 1.44-inch ST7735S LCD HAT on a Debian-based Raspberry Pi OS. Bookworm and newer are the intended releases. The script checks the Pi model and enables SPI using `raspi-config`; it cannot identify the HAT electronically, so check the board and seating yourself. A reboot is required if SPI was disabled. Confirm `/dev/spidev0.0` after reboot.

Clone the repository on the Pi and run the installer from the clone:

```bash
git clone https://github.com/D3h420/SwissKnife.git
cd SwissKnife
sudo bash RPi_LCD_HAT/install.sh
```

The installer creates a **Git clone** at `/opt/SwissKnife`, installs required LCD and core workflow packages, and enables `swissknifos.service`. It stores logs, captures, and downloaded Dragon Drain build files under `/var/lib/swissknife` (root-only). The source clone can be removed after installation. If `/opt/SwissKnife` already contains a Git clone, running the installer from a different, updated clone fast-forwards the installed clone from it; running from `/opt/SwissKnife` repairs the dependencies and service. Both clones must be on the same branch and the installed clone must have no local changes. An existing non-Git directory at that path is left untouched and causes an error.

The old `SwissKnifOS_RPi` path remains as a compatibility symlink to `RPi_LCD_HAT`. It lets an already installed service continue to start after `git pull`; rerunning the installer updates the service to the new path. If Git refuses the rename because of untracked files in the old directory (for example a custom logo), move those files into the corresponding location under `RPi_LCD_HAT` before pulling.

Only committed content is cloned into `/opt/SwissKnife`; commit local edits before first installation. The workflow catalogue lives in `core/features.py`. Adding a workflow there makes its menu entry appear in both terminal and LCD interfaces after an update. Changes to the workflow's prompts or output should still be checked on the 128 × 128 screen.

It does not modify network profiles, DHCP services, or adapter roles. NetworkManager is required for the Pi Commands Wi-Fi actions; if it is absent, install it explicitly with `sudo bash RPi_LCD_HAT/install.sh --install-network-manager`. This may change how the Pi manages network connections, so use local access when changing network management. Optional `bully` and Dragon Drain build dependencies can be installed with `--with-optional-tools`. Dragon Drain still performs its own source build when selected. Wardrive GPS tagging needs a USB GPS receiver. Wi-Fi workflows need suitable external adapters with monitor mode support.

The required package set is `python3-pil`, `python3-spidev`, `python3-lgpio`, `python3-scapy`, `fonts-dejavu-core`, `aircrack-ng`, `iproute2`, `ethtool`, `arp-scan`, `hostapd`, `dnsmasq`, `iptables`, `iw`, `iputils-ping`, `usbutils`, `rfkill`, `wireless-tools`, and `mdk4`. The optional set is `bully`, `git`, `autoconf`, `automake`, `libtool`, `shtool`, `libssl-dev`, `pkg-config`, and `build-essential`. The installer uses the Raspberry Pi OS Python packages; it does not use `pip --break-system-packages`.

Start the LCD interface from the repository root:

```bash
sudo python3 RPi_LCD_HAT/app.py
```

To inspect sample screens without SPI or GPIO, run `python3 RPi_LCD_HAT/app.py --preview /tmp/swissknifos-preview`. This saves sample PNG files and requires Pillow. The module bridge and menu logic can be checked with `python3 -m unittest discover -s RPi_LCD_HAT -p 'test_*.py'`.

The bundled intro image is `RPi_LCD_HAT/assets/logo-128.png`, prepared at the LCD's native 128 × 128 resolution. The current asset was reconstructed from the shared logo preview. For an exact match, save the original PNG as `RPi_LCD_HAT/assets/logo-source.png`; the interface automatically prefers it and scales it to fit the display. Text is drawn in whole pixels with a monospaced font and no grayscale antialiasing, which makes the small display sharper. The intro stays visible until **any** button is pressed; that press only opens the menu and does not activate its first item.

Root access is needed by SwissKnife's networking workflows. If the interface starts but the display stays blank, first check SPI, the HAT seating, and the GPIO map. Hardware behavior still needs validation on the physical Seengreat HAT.

## Controls

| Control | In menus and workflows |
| --- | --- |
| Joystick up/down | Move through the current list |
| Joystick left/right | Move between options or keyboard keys |
| Joystick center | Select / OK |
| K1 | Back or show the current log; toggle QR on About |
| K2 | Open the on-screen keyboard when text is requested |
| K3 | Interrupt the active workflow |
| K4 | Enter / confirm |
| L / R | Previous / next page |

At the logo screen, any button opens the main menu. In menus, the active item is orange; the number at the top right shows its position in the list.

## System and Pi Commands

**System → About** shows the project address and “D3h420 from LAB5”. Press **K1** to show a scannable QR code for `https://github.com/D3h420/SwissKnife`; press **K1** again to close it. **Left** returns to System from either page. The QR image is loaded once; a missing or damaged asset displays a fallback message instead of restarting the interface.

**System → Pi Commands** includes:

| Item | Action |
| --- | --- |
| USB devices | Show `lsusb` output |
| Interfaces | Show NetworkManager devices and IP addresses |
| WiFi scan | Scan available SSIDs on a selected Wi-Fi adapter |
| WiFi connect | Choose an SSID or type one, then enter its password on the LCD keyboard |
| Saved networks | Show saved NetworkManager profiles |
| Activate network | Activate a saved profile on a selected interface |
| Disconnect | Disconnect a selected interface after confirmation |

These actions execute the actual `lsusb`, `ip`, and `nmcli` binaries on the Raspberry Pi, as root under the existing service. The LCD prints each command and its result, or a clear missing-tool/error message. Wi-Fi passwords are concealed on the LCD; NetworkManager's `wifi connect ... password ...` command briefly receives them as process arguments. The Wi-Fi connection action covers open and personal-password networks. Enterprise Wi-Fi configuration and the full `sudo nmtui` editor require an SSH terminal: `nmtui` uses curses and does not fit the 128 × 128 LCD. Changing or disconnecting the interface used for SSH can drop the SSH session; the LCD interface remains available.

On the on-screen keyboard, use the joystick to select a character and press the center button to type it. **K3** deletes the last character, **K4** inserts a space, and **R** confirms the entry. **K1** shows the log while keeping the question open; press **K2** to return to the keyboard. In a workflow's numbered list, **K4** submits an empty answer, which lets the module use its default. To interrupt a workflow while typing, first press **K1**, then **K3**. The screen is only 128 × 128 pixels, so long output appears in pages or a scrollable log.

The LCD presents scanned networks as separate blocks: SSID, BSSID, radio details and client count appear on distinct lines. The live Recon sniffer refreshes one compact status screen rather than stacking terminal boxes. Use **Up/Down** to scroll previous result rows and **L/R** to move faster. Choice screens show three large options at a time.

Common CLI questions are mapped to buttons throughout the modules. **Portal → SSID source** offers **Scan** and **Manual SSID**; **Scan duration** offers **5, 15, 30 and 60 seconds**. Network selections include **Rescan**, **Manual SSID** and **Exit** where the underlying module supports them. Yes/no questions and common capture windows also use choices. The keyboard remains for free-form data such as a manually entered SSID, a new Wi-Fi password, custom multi-target selections and the Handshaker confirmation phrase; **K2** is available as an advanced manual entry option on a choice screen.

ARP scanner and IP.CAM finder print their interface and scanned-network lists in a plain numbered format when launched from the LCD. This lets the joystick select an interface or network even when Rich terminal formatting is installed on the Pi.

## Update and service control

After installation, update the **installed clone**, not the original download:

```bash
cd /opt/SwissKnife
git pull
```

The running LCD application checks the Git revision. After a successful pull it exits when no workflow is active; systemd starts the new version automatically. An active workflow is allowed to finish or be stopped from the HAT first. The terminal launcher uses the new files on its next invocation. If an update introduces new system packages or changes the service definition, rerun `sudo bash RPi_LCD_HAT/install.sh` from `/opt/SwissKnife` once. Do not run `git pull` with `sudo`; the installed clone is owned by the user who ran the installer with `sudo`.

For startup errors, inspect `journalctl -u swissknifos.service -b`. To stop autostart while keeping code and data, use `sudo bash RPi_LCD_HAT/install.sh --disable-autostart`. To remove only the service, use `sudo bash RPi_LCD_HAT/install.sh --uninstall-service`. Neither command removes `/opt/SwissKnife` or `/var/lib/swissknife`.

## Status and scope

The user has confirmed the boot screen and menu update on a physical Pi. The new About and Pi Commands screens still need a hardware check. Use SwissKnife only on networks and devices you own or are explicitly authorized to test.
