import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from core.wifi_scan import scan_command


HELPER = Path(__file__).resolve().parents[1] / "packaging/scan-wifi"


class WiFiScanTests(unittest.TestCase):
    def test_cli_and_cardputer_choose_expected_command(self):
        with patch.dict(os.environ, {"SWISSKNIFE_WIFI_SCAN_HELPER": ""}):
            self.assertEqual(scan_command("wlan0"), ["iw", "dev", "wlan0", "scan"])
        with patch.dict(os.environ, {"SWISSKNIFE_WIFI_SCAN_HELPER": "/usr/libexec/swissknife-cardputer/scan-wifi"}):
            self.assertEqual(scan_command("wlan1"), ["sudo", "-n", "/usr/libexec/swissknife-cardputer/scan-wifi", "wlan1"])

    def test_privileged_helper_rejects_invalid_interfaces(self):
        for interface in ("wlan0;id", "../wlan0", "", "a" * 16):
            result = subprocess.run([sys.executable, str(HELPER), interface], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
