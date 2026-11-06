"""Seengreat 1.44-inch ST7735S LCD and button driver for Raspberry Pi Zero 2 W.

The board uses SPI0 CE0 and BCM numbering.  The manufacturer's wiki lists
BCM 19 as a second DOWN key, but its key_demo.py confirms BCM 19 is RIGHT.
Set SWISSKNIFOS_RIGHT_GPIO if a board revision wires it differently.

Pin table: https://seengreat.com/wiki/68/1-44inch-lcd-display
Official driver: https://github.com/seengreat/1.44inch-LCD-Display/blob/main/lgpio/python/lcd_1inch44.py
"""

from __future__ import annotations

import os
import time
from contextlib import suppress
from dataclasses import dataclass

from PIL import Image


WIDTH = 128
HEIGHT = 128
DC_GPIO = 25
RESET_GPIO = 27
BACKLIGHT_GPIO = 24

# The wiki labels both BCM 26 and BCM 19 "DOWN"; the official key_demo.py
# confirms BCM 19 is RIGHT.
RIGHT_GPIO = int(os.environ.get("SWISSKNIFOS_RIGHT_GPIO", "19"))
BUTTON_PINS = {
    "UP": 13,
    "DOWN": 26,
    "LEFT": 5,
    "RIGHT": RIGHT_GPIO,
    "OK": 6,
    "K1": 17,
    "K2": 18,
    "K3": 22,
    "K4": 23,
    "L": 21,
    "R": 20,
}

DEBOUNCE_SECONDS = 0.03
REPEAT_DELAY_SECONDS = 0.4
REPEAT_INTERVAL_SECONDS = 0.12
REPEAT_KEYS = frozenset(("UP", "DOWN", "LEFT", "RIGHT"))

# Seengreat's ST7735S driver uses MADCTL 0x68 and these GRAM offsets.
LCD_X_OFFSET = 1
LCD_Y_OFFSET = 2
LCD_MADCTL = 0x68


@dataclass
class _ButtonState:
    candidate: bool = False
    stable: bool = False
    changed_at: float = 0.0
    repeat_at: float = 0.0


class SeengreatHardware:
    """Drive the LCD and return debounced, active-low button press events.

    ``poll`` should be called regularly (about every 20-50 ms).  Arrow keys
    repeat while held; OK and K1-K4/L/R emit only one event per press.
    """

    def __init__(self) -> None:
        try:
            import lgpio
            import spidev
        except ImportError as exc:
            raise RuntimeError(
                "Seengreat hardware requires python3-lgpio, python3-spidev "
                "and enabled SPI0 (/dev/spidev0.0)"
            ) from exc

        self._gpio = lgpio
        self._chip: int | None = None
        self._spi = None
        self._buttons = {name: _ButtonState() for name in BUTTON_PINS}

        try:
            self._chip = lgpio.gpiochip_open(0)
            lgpio.gpio_claim_output(self._chip, DC_GPIO, 0)
            lgpio.gpio_claim_output(self._chip, RESET_GPIO, 1)
            lgpio.gpio_claim_output(self._chip, BACKLIGHT_GPIO, 0)
            for pin in BUTTON_PINS.values():
                lgpio.gpio_claim_input(self._chip, pin, lgpio.SET_PULL_UP)

            self._spi = spidev.SpiDev()
            self._spi.open(0, 0)
            self._spi.mode = 0
            self._spi.max_speed_hz = 8_000_000

            self._reset()
            self._init_lcd()
            self.show(Image.new("RGB", (WIDTH, HEIGHT), "black"))
            lgpio.gpio_write(self._chip, BACKLIGHT_GPIO, 1)
        except Exception:
            self.close()
            raise

    def _reset(self) -> None:
        assert self._chip is not None
        for level in (1, 0, 1):
            self._gpio.gpio_write(self._chip, RESET_GPIO, level)
            time.sleep(0.01)

    def _command(self, command: int, data: bytes = b"") -> None:
        assert self._chip is not None and self._spi is not None
        self._gpio.gpio_write(self._chip, DC_GPIO, 0)
        self._spi.writebytes2(bytes((command,)))
        if data:
            self._gpio.gpio_write(self._chip, DC_GPIO, 1)
            self._spi.writebytes2(data)

    def _init_lcd(self) -> None:
        # Register order and values follow the Seengreat lgpio Python demo.
        self._command(0x01)  # Software reset.
        time.sleep(0.02)
        self._command(0x11)  # Sleep out.
        time.sleep(0.05)

        settings = (
            (0xB1, b"\x02\x35\x36"),
            (0xB2, b"\x02\x35\x36"),
            (0xB3, b"\x02\x35\x36\x02\x35\x36"),
            (0xB4, b"\x03"),
            (0xC0, b"\xa2\x02\x84"),
            (0xC1, b"\xc5"),
            (0xC2, b"\x0d\x00"),
            (0xC3, b"\x8d\x2a"),
            (0xC4, b"\x8d\xee"),
            (0xC5, b"\x0a"),
            (0x36, bytes((LCD_MADCTL,))),
            (0xE0, b"\x12\x1c\x10\x18\x33\x2c\x25\x28\x28\x27\x2f\x3c\x00\x03\x03\x10"),
            (0xE1, b"\x12\x1c\x10\x18\x2d\x28\x23\x28\x28\x26\x2f\x3b\x00\x03\x03\x10"),
            (0xF0, b"\x01"),
            (0xF6, b"\x00"),
            (0x3A, b"\x05"),  # RGB565.
        )
        for command, data in settings:
            self._command(command, data)
        self._command(0x29)  # Display on.
        time.sleep(0.05)

    def show(self, image: Image.Image) -> None:
        """Draw a 128x128 PIL image on the screen in RGB565 format."""
        if image.size != (WIDTH, HEIGHT):
            raise ValueError(f"Image must be {WIDTH}x{HEIGHT} pixels")
        if self._spi is None or self._chip is None:
            raise RuntimeError("Seengreat hardware is closed")

        rgb = image.convert("RGB").tobytes()
        pixels = bytearray(WIDTH * HEIGHT * 2)
        for source in range(0, len(rgb), 3):
            destination = (source // 3) * 2
            red, green, blue = rgb[source : source + 3]
            pixels[destination] = (red & 0xF8) | (green >> 5)
            pixels[destination + 1] = ((green & 0x1C) << 3) | (blue >> 3)

        x_end = LCD_X_OFFSET + WIDTH - 1
        y_end = LCD_Y_OFFSET + HEIGHT - 1
        self._command(0x2A, bytes((0, LCD_X_OFFSET, 0, x_end)))
        self._command(0x2B, bytes((0, LCD_Y_OFFSET, 0, y_end)))
        self._command(0x2C)
        self._gpio.gpio_write(self._chip, DC_GPIO, 1)
        self._spi.writebytes2(pixels)

    def poll(self) -> list[str]:
        """Return button events since this call, including held arrow repeats."""
        if self._chip is None:
            raise RuntimeError("Seengreat hardware is closed")

        now = time.monotonic()
        events: list[str] = []
        for name, pin in BUTTON_PINS.items():
            state = self._buttons[name]
            pressed = self._gpio.gpio_read(self._chip, pin) == 0
            if pressed != state.candidate:
                state.candidate = pressed
                state.changed_at = now
            if state.candidate != state.stable:
                if now - state.changed_at >= DEBOUNCE_SECONDS:
                    state.stable = state.candidate
                    if state.stable:
                        events.append(name)
                        state.repeat_at = now + REPEAT_DELAY_SECONDS
                    else:
                        state.repeat_at = 0.0
            elif state.stable and name in REPEAT_KEYS and now >= state.repeat_at:
                events.append(name)
                state.repeat_at = now + REPEAT_INTERVAL_SECONDS
        return events

    def close(self) -> None:
        """Turn off the backlight and release SPI and GPIO resources."""
        if self._spi is not None:
            with suppress(Exception):
                self._spi.close()
            self._spi = None
        if self._chip is not None:
            with suppress(Exception):
                self._gpio.gpio_write(self._chip, BACKLIGHT_GPIO, 0)
            with suppress(Exception):
                self._gpio.gpiochip_close(self._chip)
            self._chip = None
