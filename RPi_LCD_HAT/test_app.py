"""Controller tests that run without an LCD or Pillow."""

import unittest
import time
from unittest.mock import patch

from core.features import features_for
from RPi_LCD_HAT.app import MENUS, MenuItem, SwissKnifOS
from modules.sdr import SDRSession


class FakeProcess:
    def __init__(self, _script, _args):
        self.events = []
        self.sent = []
        self.rc = None
        self.interrupted = False

    def start(self):
        pass

    def poll(self):
        events, self.events = self.events, []
        return events

    @property
    def returncode(self):
        return self.rc

    def send(self, value):
        self.sent.append(value)

    def interrupt(self):
        self.interrupted = True

    def terminate(self):
        self.rc = 0


class FakeRenderer:
    def max_scroll(self, _buffer):
        return 2

    def boot(self):
        return object()


class FakeHardware:
    def __init__(self):
        self.closed = False

    def poll(self):
        return []

    def show(self, _frame):
        pass

    def close(self):
        self.closed = True


class AppTests(unittest.TestCase):
    def test_sdr_menu_uses_shared_session_and_returns(self):
        app = SwissKnifOS(hardware=None, renderer=FakeRenderer())
        app.sdr = SDRSession(demo=True)
        app._menu_action(MenuItem("Waterfall", "sdr-mode", args=("spectrum",)))
        deadline = time.monotonic() + 2
        while app.sdr_busy and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(app.sdr.snapshot().mode, "spectrum")
        app._handle_key("K3")
        while app.sdr_busy and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(app.screen, "menu")
        self.assertEqual(app.sdr.snapshot().mode, "idle")

    def test_sdr_frequency_keyboard(self):
        app = SwissKnifOS(hardware=None, renderer=FakeRenderer())
        app.sdr = SDRSession(demo=True)
        app._menu_action(MenuItem("Tune MHz", "sdr-tune"))
        self.assertEqual(app.screen, "sdr_tune")
        app.keyboard.value = "868.3"
        app._handle_key("K4")
        deadline = time.monotonic() + 2
        while app.sdr_busy and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(app.sdr.config.center_hz, 868_300_000)
        app.sdr.close()

    def test_git_update_restarts_idle_app(self):
        hardware = FakeHardware()
        app = SwissKnifOS(hardware, renderer=FakeRenderer())
        with patch("RPi_LCD_HAT.app.git_revision", side_effect=["old", "new"]), \
             patch("RPi_LCD_HAT.app.time.monotonic", side_effect=[0, 4]):
            app.run()
        self.assertFalse(app.running)
        self.assertTrue(hardware.closed)

    def test_shared_workflow_catalogue_matches_lcd_menu(self):
        for category in ("Recon", "Attacks", "Wardrive"):
            menu_name = "SwissKnifOS" if category == "Recon" else category
            actual = [(item.label, item.script, item.args) for item in MENUS[menu_name] if item.script.startswith("modules/")]
            expected = [(feature.label, feature.script, feature.args) for feature in features_for(category)]
            self.assertEqual(actual, expected)

    def test_system_about_and_pi_commands(self):
        self.assertEqual([item.label for item in MENUS["System"]], ["About", "Pi Commands", "Back"])
        app = SwissKnifOS(hardware=None, renderer=FakeRenderer())
        app.screen = "menu"
        app.menu_stack.append("System")
        app._handle_key("OK")
        self.assertEqual((app.screen, app.about_page), ("about", 0))
        app._handle_key("DOWN")
        self.assertEqual(app.about_page, 0)
        app._handle_key("K1")
        self.assertEqual(app.about_page, 1)
        app._handle_key("K1")
        self.assertEqual(app.about_page, 0)
        app._handle_key("K1")
        self.assertEqual(app.about_page, 1)
        app._handle_key("LEFT")
        self.assertEqual(app.screen, "menu")
        app._handle_key("DOWN")
        app._handle_key("OK")
        self.assertEqual(app.menu_name, "Pi Commands")

    def test_intro_waits_for_any_button(self):
        app = SwissKnifOS(hardware=None, renderer=FakeRenderer())
        self.assertEqual(app.screen, "boot")
        self.assertFalse(hasattr(app, "boot_until"))
        app._handle_key("K2")
        self.assertEqual(app.screen, "menu")
        self.assertEqual(app.menu_selection["SwissKnifOS"], 0)

    def test_menu_prompt_keyboard_and_return(self):
        app = SwissKnifOS(hardware=None, renderer=FakeRenderer())
        app.screen = "menu"
        app._handle_key("DOWN")
        app._handle_key("OK")
        self.assertEqual(app.menu_name, "Attacks")
        self.assertEqual(app.menu_selection["SwissKnifOS"], 1)

        with patch("RPi_LCD_HAT.app.ModuleProcess", FakeProcess):
            app._handle_key("OK")
        self.assertEqual(app.module_name, "Deauth")
        self.assertEqual(app.screen, "output")

        app.module.events = [
            ("text", "Available interfaces:\n  1) wlan0\n  2) wlan1\nSelect interface (number or name): "),
            ("input", False),
        ]
        app._poll_module()
        self.assertEqual(app.screen, "choices")
        app._handle_key("DOWN")
        app._handle_key("OK")
        self.assertEqual(app.module.sent, ["2"])
        self.assertEqual(app.pending_reads, 0)

        app.module.events = [("text", "Enter SSID: "), ("input", False)]
        app._poll_module()
        self.assertEqual(app.screen, "keyboard")
        app._handle_key("OK")  # type a
        app._handle_key("R")   # submit
        self.assertEqual(app.module.sent, ["2", "a"])

        app.module.rc = 0
        app._poll_module()
        app._handle_key("OK")
        self.assertEqual(app.screen, "menu")
        self.assertEqual(app.menu_name, "Attacks")

    def test_interrupt_clears_pending_input(self):
        app = SwissKnifOS(hardware=None, renderer=FakeRenderer())
        app.screen = "output"
        app.module = FakeProcess(None, None)
        app.pending_reads = 1
        app.choices = []
        app._handle_key("K3")
        self.assertTrue(app.module.interrupted)
        self.assertEqual(app.pending_reads, 0)

    def test_portal_buttons_and_scan_duration(self):
        app = SwissKnifOS(hardware=None, renderer=FakeRenderer())
        app.screen = "output"
        app.module = FakeProcess(None, None)
        app.module.events = [("text", "SSID source - Scan (S) or Manual (M): "), ("input", False)]
        app._poll_module()
        self.assertEqual((app.screen, [choice.key for choice in app.choices]), ("choices", ["s", "m"]))
        app._handle_key("DOWN")
        app._handle_key("OK")
        self.assertEqual(app.module.sent, ["m"])

        app.module.events = [("text", "Scan duration in seconds (Enter for 15): "), ("input", False)]
        app._poll_module()
        self.assertEqual(app.screen, "choices")
        app._handle_key("DOWN")
        app._handle_key("OK")
        self.assertEqual(app.module.sent, ["m", "15"])

    def test_pi_command_result_keeps_command_output(self):
        app = SwissKnifOS(hardware=None, renderer=FakeRenderer())
        app.screen = "output"
        app.pi_command = True
        app.module = FakeProcess(None, None)
        app.module.events = [("text", "$ lsusb\nBus 001 Device 002: USB WiFi\n")]
        app.module.rc = 0
        app._poll_module()
        self.assertIn("Bus 001 Device 002: USB WiFi", app.output.visible_lines())
        self.assertFalse(any("Exit code" in line for line in app.output.visible_lines()))

    def test_scroll_stops_at_available_output(self):
        app = SwissKnifOS(hardware=None, renderer=FakeRenderer())
        app._scroll_key("L")
        self.assertEqual(app.scroll, 2)
        app._scroll_key("R")
        self.assertEqual(app.scroll, 0)


if __name__ == "__main__":
    unittest.main()
