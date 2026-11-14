"""Mode changes must not strand an adapter in the disabled state."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from core import wifi_iface
from core import hardware
from modules import deauth


class WiFiInterfaceRecoveryTests(unittest.TestCase):
    def test_matching_active_mode_does_not_reset_adapter(self):
        with patch.object(wifi_iface, "get_interface_mode", return_value="managed"), \
             patch.object(wifi_iface, "is_interface_up", return_value=True), \
             patch.object(wifi_iface.subprocess, "run") as run:
            self.assertEqual(wifi_iface.set_interface_type("wlan1", "managed"), (True, None))
        run.assert_not_called()

    def test_mode_change_failure_reenables_adapter(self):
        outcomes = [
            SimpleNamespace(returncode=0, stderr=""),
            SimpleNamespace(returncode=1, stderr="driver rejected mode"),
            SimpleNamespace(returncode=0, stderr=""),
        ]
        with patch.object(wifi_iface, "get_interface_mode", return_value="managed"), \
             patch.object(wifi_iface, "is_interface_up", return_value=True), \
             patch.object(wifi_iface.subprocess, "run", side_effect=outcomes) as run:
            ok, error = wifi_iface.set_interface_type("wlan1", "monitor", settle_seconds=0)
        self.assertFalse(ok)
        self.assertIn("driver rejected mode", error)
        self.assertEqual([item.args[0] for item in run.call_args_list], [
            ["ip", "link", "set", "wlan1", "down"],
            ["iw", "dev", "wlan1", "set", "type", "monitor"],
            ["ip", "link", "set", "wlan1", "up"],
        ])

    def test_failed_reenable_is_reported(self):
        outcomes = [
            SimpleNamespace(returncode=0, stderr=""),
            SimpleNamespace(returncode=1, stderr="driver rejected mode"),
            SimpleNamespace(returncode=1, stderr="device gone"),
        ]
        with patch.object(wifi_iface, "get_interface_mode", return_value="managed"), \
             patch.object(wifi_iface, "is_interface_up", return_value=True), \
             patch.object(wifi_iface.subprocess, "run", side_effect=outcomes):
            ok, error = wifi_iface.set_interface_type("wlan1", "monitor", settle_seconds=0)
        self.assertFalse(ok)
        self.assertIn("device gone", error)

    def test_inventory_tracks_unplug_and_replug_without_cached_adapter(self):
        states = iter([
            (["wlan0", "wlan1"], ["wlan0", "wlan1"], ("USB Wi-Fi",)),
            (["wlan0"], ["wlan0"], ()),
            (["wlan0", "wlan2"], ["wlan0", "wlan2"], ("USB Wi-Fi",)),
        ])
        with patch.object(hardware, "get_interface_mode", return_value="managed"), \
             patch.object(hardware, "get_interface_chipset", return_value="test-driver"), \
             patch.object(hardware, "_monitor_support", return_value=True), \
             patch.object(hardware, "_command", return_value=""), \
             patch.object(hardware.glob, "glob", return_value=[]):
            names = []
            for interfaces, wireless, usb in states:
                with patch.object(hardware, "list_network_interfaces", return_value=interfaces), \
                     patch.object(hardware, "list_wireless_interfaces", return_value=wireless), \
                     patch.object(hardware, "_usb_devices", return_value=usb):
                    names.append(tuple(item.name for item in hardware.detect_hardware().wifi))
        self.assertEqual(names, [("wlan0", "wlan1"), ("wlan0",), ("wlan0", "wlan2")])

    def test_cleanup_stops_child_before_restoring_interface(self):
        steps = []
        with patch.object(deauth, "SELECTED_INTERFACE", "wlan1"), \
             patch.object(deauth, "stop_attack", side_effect=lambda: steps.append("stop")), \
             patch.object(deauth, "restore_managed_mode", side_effect=lambda _iface: steps.append("restore") or True):
            deauth.cleanup()
        self.assertEqual(steps, ["stop", "restore"])


if __name__ == "__main__":
    unittest.main()
