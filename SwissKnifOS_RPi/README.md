# SwissKnifOS_RPi

SwissKnifOS_RPi is the small-screen interface for SwissKnife on a Raspberry Pi Zero 2 W. It shows a splash screen, lets you browse menus with the HAT's joystick, and provides an on-screen keyboard where a workflow needs text input. The existing SwissKnife modules still perform the actual work; their external Wi-Fi adapter and tool requirements remain in force.

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

Use Raspberry Pi OS Bookworm or newer on the Pi Zero 2 W. Enable SPI with `sudo raspi-config` (**Interface Options → SPI → Enable**), then reboot. Confirm that `/dev/spidev0.0` exists. Seengreat recommends `lgpio` for Bookworm, Trixie, and newer releases.

From the repository root, install the display and Python dependencies:

```bash
sudo apt update
sudo apt install -y python3-pil python3-spidev python3-lgpio python3-scapy
```

SwissKnife modules also need the system tools listed in the [main README](../README.md#requirements-). Install the tools used by your workflows and connect a supported external Wi-Fi adapter. Some modules have additional setup requirements, such as a GPS receiver for wardriving or a module-specific build step for Dragon Drain. The Pi's built-in Wi-Fi can serve as a management connection, while compatible external adapters handle workflows that need monitor mode.

Start the LCD interface from the repository root:

```bash
sudo python3 SwissKnifOS_RPi/app.py
```

To inspect sample screens without SPI or GPIO, run `python3 SwissKnifOS_RPi/app.py --preview /tmp/swissknifos-preview`. This saves five PNG files and requires Pillow. The module bridge and menu logic can be checked with `python3 -m unittest discover -s SwissKnifOS_RPi -p 'test_*.py'`.

Root access is needed by SwissKnife's networking workflows. If the interface starts but the display stays blank, first check SPI, the HAT seating, and the GPIO map. Hardware behavior still needs validation on the physical Seengreat HAT.

## Controls

| Control | In menus and workflows |
| --- | --- |
| Joystick up/down | Move through the current list |
| Joystick left/right | Move between options or keyboard keys |
| Joystick center | Select / OK |
| K1 | Back or show the current log |
| K2 | Open the on-screen keyboard when text is requested |
| K3 | Interrupt the active workflow |
| K4 | Enter / confirm |
| L / R | Previous / next page |

On the on-screen keyboard, use the joystick to select a character and press the center button to type it. **K3** deletes the last character, **K4** inserts a space, and **R** confirms the entry. **K1** shows the log while keeping the question open; press **K2** to return to the keyboard. In a workflow's numbered list, **K4** submits an empty answer, which lets the module use its default. To interrupt a workflow while typing, first press **K1**, then **K3**. The screen is only 128 × 128 pixels, so long output appears in pages or a scrollable log.

## Start automatically at boot

The included `swissknifos.service` starts the interface after boot. Its `WorkingDirectory` and `ExecStart` point to `/opt/SwissKnife`; place your clone there or change both paths before installing it:

```bash
sudo cp SwissKnifOS_RPi/swissknifos.service /etc/systemd/system/swissknifos.service
sudo systemctl daemon-reload
sudo systemctl enable --now swissknifos.service
sudo systemctl status swissknifos.service
```

For startup errors, inspect `journalctl -u swissknifos.service -b`. Use `sudo systemctl disable --now swissknifos.service` to stop automatic startup.

## Status and scope

This interface is being developed in the repository. It has not been tested on the physical Seengreat HAT in this session. Check display orientation and button behavior on your hardware before field use. Use SwissKnife only on networks and devices you own or are explicitly authorized to test.
