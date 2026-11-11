import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from CardputerZero.app.controller import Controller, MAIN
from RPi_LCD_HAT.app import MENUS
from core.engine import SwissKnifeEngine
from modules.sdr import SDRConfig, SDRSession, discover_devices, parse_power_row, spectrum_bins


class SDRTests(unittest.TestCase):
    def test_documented_power_csv_format(self):
        parsed = parse_power_row("2026-11-10, 12:00:00, 433000000, 434000000, 10000, 32, -85.5, -62.0")
        self.assertEqual(parsed[0], "2026-11-10 12:00:00")
        self.assertEqual(parsed[3], [-85.5, -62.0])
        self.assertIsNone(parse_power_row("bad,row"))

    def test_waterfall_frequency_mapping(self):
        bins = spectrum_bins([(433_000_000, 100_000, [-90, -60, -30])], 433_000_000, 433_400_000, width=4)
        self.assertEqual(bins[:3], (-90, -60, -30))

    def test_config_rejects_bad_values(self):
        with self.assertRaises(ValueError):
            SDRConfig(center_hz=2_000_000).validate()
        with self.assertRaises(ValueError):
            SDRConfig(modulation="bad").validate()

    def test_missing_tool_is_reported_without_starting_process(self):
        session = SDRSession()
        with patch("modules.sdr.shutil.which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "rtl_power"):
                session.start_spectrum()
        self.assertEqual(session.snapshot().mode, "idle")

    def test_discovery_uses_rtl_test_device_indices(self):
        from subprocess import CompletedProcess
        output = "Found 2 device(s):\n  0: Generic RTL2832U OEM\n  1: RTL-SDR Blog V4\n"
        with patch("modules.sdr.shutil.which", return_value="/usr/bin/rtl_test"), \
             patch("modules.sdr.subprocess.run", return_value=CompletedProcess([], 0, "", output)):
            self.assertEqual(discover_devices(), ("0: Generic RTL2832U OEM", "1: RTL-SDR Blog V4"))

    def test_demo_waterfall_and_recording_do_not_write_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sub-ghz"
            session = SDRSession(demo=True, data_dir=path)
            self.assertEqual(len(session.refresh_devices()), 2)
            session.start_spectrum()
            self.assertTrue(session.snapshot().waterfall)
            self.assertEqual(session.snapshot().mode, "spectrum")
            recording = session.start_recording(seconds=1)
            self.assertFalse(recording.exists())
            self.assertFalse(path.exists())
            time.sleep(1.05)
            self.assertEqual(session.snapshot().mode, "idle")
            session.close()

    def test_demo_adsb_is_labelled(self):
        session = SDRSession(demo=True)
        session.start_adsb()
        self.assertTrue(all("[SIMULATED]" in value for value in session.snapshot().aircraft))
        session.close()

    def test_stop_terminates_child_process(self):
        session = SDRSession(demo=True)
        process = session._launch([sys.executable, "-c", "import time; time.sleep(10)"])
        session.mode = "audio"
        session.stop()
        self.assertIsNotNone(process.poll())

    def test_unplugged_receiver_surfaces_error(self):
        session = SDRSession(demo=True)
        session.mode = "spectrum"
        session._stderr.append("Device disconnected")
        session._processes.append(SimpleNamespace(poll=lambda: 1, returncode=1))
        state = session.snapshot()
        self.assertEqual(state.mode, "error")
        self.assertIn("Device disconnected", state.message)
        session._processes.clear()

    def test_all_three_menus_expose_sdr(self):
        from swiss_knife import MAIN_MENU, PACKAGE_MAPS, REQUIRED_TOOLS
        self.assertEqual(MAIN_MENU["4"]["name"], "SDR")
        self.assertIn("SDR", MAIN)
        self.assertIn("SDR", [item.label for item in MENUS["SwissKnifOS"]])
        self.assertIn("rtl_power", REQUIRED_TOOLS)
        self.assertEqual(PACKAGE_MAPS["apt-get"]["rtl_power"], "rtl-sdr")

    def test_cardputer_demo_navigation_and_record(self):
        controller = Controller(SwissKnifeEngine(demo=True))
        controller.handle("ENTER")
        controller.handle("DOWN")
        controller.handle("ENTER")
        self.assertEqual(controller.screen, "sdr")
        deadline = time.monotonic() + 2
        while controller.sdr_busy and time.monotonic() < deadline:
            time.sleep(0.01)
        controller.tick()
        self.assertEqual(controller.sdr_snapshot.mode, "spectrum")
        controller.handle("TEXT", "r")
        while controller.sdr_busy and time.monotonic() < deadline:
            time.sleep(0.01)
        while time.monotonic() < deadline:
            controller.tick()
            if controller.sdr_snapshot.mode == "record":
                break
            time.sleep(0.02)
        self.assertEqual(controller.sdr_snapshot.mode, "record")
        controller.handle("ESC")
        controller.close()
        self.assertEqual(controller.screen, "main")

    def test_cardputer_tune_entry_and_validation(self):
        controller = Controller(SwissKnifeEngine(demo=True))
        controller.handle("ENTER")
        controller.handle("DOWN")
        controller.handle("ENTER")
        deadline = time.monotonic() + 2
        while controller.sdr_busy and time.monotonic() < deadline:
            time.sleep(0.01)
        controller.handle("TEXT", "t")
        self.assertEqual(controller.screen, "sdr_tune")
        controller.sdr_tune_text = "433.92"
        controller.handle("ENTER")
        while controller.sdr_busy and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(controller.sdr.config.center_hz, 433_920_000)
        controller.close()


if __name__ == "__main__":
    unittest.main()
