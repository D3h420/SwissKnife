"""ARP/IPcam must expose real button choices on the LCD."""

import io
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from modules.arp_scanner import ArpScanner
from modules.ipcam_finder import IpCamFinder
from RPi_LCD_HAT.logic import TerminalBuffer, input_mode


class InterfaceChoicesTests(unittest.TestCase):
    def test_both_modules_publish_numbered_interface_options(self):
        for cls in (ArpScanner, IpCamFinder):
            with self.subTest(module=cls.__name__):
                module = cls()
                module.running = True
                screen = io.StringIO()
                with (
                    patch.dict(os.environ, {"SWISSKNIFOS_LCD": "1"}),
                    patch.object(module, "_list_wifi_interfaces", return_value=["wlan0", "wlan1"]),
                    patch.object(module, "_build_interface_profiles", return_value={}),
                    patch.object(module, "_get_interface_mode", return_value="managed"),
                    patch("builtins.input", return_value="2"),
                    redirect_stdout(screen),
                ):
                    self.assertEqual(module._select_interface(), "wlan1")
                buffer = TerminalBuffer()
                buffer.feed(screen.getvalue() + "Select interface (number): ")
                mode, options = input_mode(buffer)
                self.assertEqual(mode, "choices")
                self.assertEqual([(option.key, option.label.split(" - ")[0]) for option in options],
                                 [("1", "wlan0"), ("2", "wlan1")])


if __name__ == "__main__":
    unittest.main()
