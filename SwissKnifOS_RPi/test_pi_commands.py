"""Checks for the LCD NetworkManager workflow."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from SwissKnifOS_RPi import pi_commands


class PiCommandsTests(unittest.TestCase):
    def test_connect_selected_wifi_on_selected_adapter(self):
        devices = [pi_commands.Device("wlan1", "wifi", "disconnected")]
        networks = [pi_commands.Network("Lab WiFi", "83", "WPA2")]
        screen = io.StringIO()
        with (
            patch.object(pi_commands, "devices", return_value=devices),
            patch.object(pi_commands, "wifi_networks", return_value=networks),
            patch("builtins.input", side_effect=["1", "1"]),
            patch("getpass.getpass", return_value="lab-password"),
            patch.object(pi_commands, "command", return_value="connected") as command,
            redirect_stdout(screen),
        ):
            pi_commands.connect_wifi()
        self.assertNotIn("lab-password", screen.getvalue())
        command.assert_called_once_with(
            "nmcli", "--wait", "60", "device", "wifi", "connect", "Lab WiFi",
            "password", "lab-password", "ifname", "wlan1", timeout=70,
        )

    def test_disconnect_requires_confirmation(self):
        screen = io.StringIO()
        with (
            patch.object(pi_commands, "choose_device", return_value=pi_commands.Device("wlan0", "wifi", "connected")),
            patch("builtins.input", return_value="2"),
            patch.object(pi_commands, "command") as command,
            redirect_stdout(screen),
        ):
            pi_commands.disconnect_device()
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
