"""SPI and button contract checks with fake hardware."""

import sys
import types
import unittest
from unittest.mock import patch


class FakeGPIO(types.ModuleType):
    SET_PULL_UP = 1

    def __init__(self):
        super().__init__("lgpio")
        self.levels = {}
        self.closed = False

    def gpiochip_open(self, _chip):
        return 1

    def gpiochip_close(self, _handle):
        self.closed = True

    def gpio_claim_output(self, _handle, pin, level):
        self.levels[pin] = level

    def gpio_claim_input(self, _handle, pin, _flags):
        self.levels[pin] = 1

    def gpio_write(self, _handle, pin, level):
        self.levels[pin] = level

    def gpio_read(self, _handle, pin):
        return self.levels[pin]


class FakeSPI:
    def __init__(self):
        self.writes = []
        self.closed = False

    def open(self, _bus, _device):
        pass

    def writebytes2(self, value):
        self.writes.append(bytes(value))

    def close(self):
        self.closed = True


class HardwareTests(unittest.TestCase):
    def test_lcd_frame_and_button(self):
        try:
            from PIL import Image
            from SwissKnifOS_RPi import hardware
        except ImportError:
            self.skipTest("Pillow is not installed in this environment")

        gpio = FakeGPIO()
        spi = FakeSPI()
        spi_module = types.ModuleType("spidev")
        spi_module.SpiDev = lambda: spi
        with patch.dict(sys.modules, {"lgpio": gpio, "spidev": spi_module}), patch.object(hardware.time, "sleep"):
            device = hardware.SeengreatHardware()
            try:
                self.assertEqual(spi.max_speed_hz, 8_000_000)
                self.assertEqual(spi.writes[0], b"\x01")
                self.assertEqual(spi.writes[1], b"\x11")
                self.assertEqual(gpio.levels[hardware.BACKLIGHT_GPIO], 1)
                self.assertEqual(hardware.BUTTON_PINS["RIGHT"], 19)

                device.show(Image.new("RGB", (128, 128), "red"))
                self.assertEqual(len(spi.writes[-1]), 128 * 128 * 2)
                self.assertEqual(spi.writes[-1][:4], b"\xf8\x00\xf8\x00")

                gpio.levels[hardware.BUTTON_PINS["OK"]] = 0
                with patch.object(hardware.time, "monotonic", side_effect=[1.0, 1.04]):
                    self.assertEqual(device.poll(), [])
                    self.assertEqual(device.poll(), ["OK"])
            finally:
                device.close()
        self.assertTrue(spi.closed)
        self.assertTrue(gpio.closed)


if __name__ == "__main__":
    unittest.main()
