"""Controller tests that run without an LCD or Pillow."""

import unittest
from unittest.mock import patch

from SwissKnifOS_RPi.app import SwissKnifOS


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


class AppTests(unittest.TestCase):
    def test_menu_prompt_keyboard_and_return(self):
        app = SwissKnifOS(hardware=None, renderer=FakeRenderer())
        app.screen = "menu"
        app._handle_key("DOWN")
        app._handle_key("OK")
        self.assertEqual(app.menu_name, "Attacks")
        self.assertEqual(app.menu_selection["SwissKnifOS"], 1)

        with patch("SwissKnifOS_RPi.app.ModuleProcess", FakeProcess):
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

    def test_scroll_stops_at_available_output(self):
        app = SwissKnifOS(hardware=None, renderer=FakeRenderer())
        app._scroll_key("L")
        self.assertEqual(app.scroll, 2)
        app._scroll_key("R")
        self.assertEqual(app.scroll, 0)


if __name__ == "__main__":
    unittest.main()
