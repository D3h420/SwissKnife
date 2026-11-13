"""Attacks expose scan data to GUI without changing terminal selections."""

import unittest
from unittest.mock import patch

from modules import deauth, portal, twins, dragon_drain


class AttackEventTests(unittest.TestCase):
    def test_scan_results_are_structured_before_selection(self):
        cases = (
            (deauth, "select_network", "scan_wireless_networks", {"ssid": "Lab", "bssid": "02:00:00:00:00:01", "channel": 6, "signal": -55, "security": "WPA2"}, "Deauth"),
            (portal, "select_network_ssid", "scan_wireless_networks", {"ssid": "Lab", "bssid": "02:00:00:00:00:01", "channel": 6, "signal": -55, "security": "WPA2"}, "Portal"),
            (twins, "select_networks", "scan_wireless_networks", {"ssid": "Lab", "bssid": "02:00:00:00:00:01", "channel": 6, "signal": -55, "security": "WPA2"}, "Evil Twin"),
            (dragon_drain, "select_target_ap", "scan_networks", dragon_drain.AccessPoint("Lab", "02:00:00:00:00:01", 6, -55, "WPA2", 1), "Dragon Drain"),
        )
        for module, selection, scanner, network, label in cases:
            with self.subTest(module=label), patch.object(module, scanner, return_value=[network]), patch.object(module, "gui_emit") as emit, patch("builtins.input", return_value="1"):
                selected = getattr(module, selection)("wlan1", 15)
                self.assertIsNotNone(selected)
                if label == "Evil Twin":
                    self.assertEqual(len(selected), 1)
                matching = [call for call in emit.call_args_list if call.args and call.args[0] == "workflow_networks"]
                self.assertEqual(len(matching), 1)
                self.assertEqual(matching[0].kwargs["module"], label)
                self.assertEqual(matching[0].kwargs["records"][0]["ssid"], "Lab")


if __name__ == "__main__":
    unittest.main()
