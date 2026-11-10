import time
import unittest

from CardputerZero.app.controller import Controller
from core.engine import SwissKnifeEngine


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.controller = Controller(SwissKnifeEngine(demo=True))
        deadline = time.monotonic() + 2
        while self.controller.hardware is None and time.monotonic() < deadline:
            self.controller.tick()
            time.sleep(0.01)

    def test_navigation_and_keyboard_filter(self):
        c = self.controller
        c.handle("ENTER")
        self.assertEqual(c.screen, "main")
        c.handle("ENTER")
        c.handle("ENTER")
        c.handle("ENTER")
        self.assertEqual(c.module.key, "Recon")
        c.handle("ENTER")
        self.assertEqual(c.screen, "config")
        c.handle("DOWN")
        c.handle("DOWN")
        c.handle("TEXT", "L")
        c.handle("TEXT", "5")
        c.handle("BACKSPACE")
        self.assertEqual(c.filter_text, "L")
        c.handle("HOME")
        self.assertEqual(c.screen, "main")

    def test_information_only_module_cannot_start(self):
        c = self.controller
        c.screen = "detail"
        c.module = next(item for item in c.engine.modules() if item.key == "Deauth")
        c.handle("ENTER")
        self.assertEqual(c.screen, "detail")

    def test_demo_operation_returns_results(self):
        c = self.controller
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.screen = "config"
        c.interface_index = 1
        c.selected = len(c._config_rows()) - 1
        c.handle("ENTER")
        self.assertEqual(c.screen, "running")
        deadline = time.monotonic() + 2
        while c.screen == "running" and time.monotonic() < deadline:
            c.tick()
            time.sleep(0.01)
        self.assertEqual(c.screen, "results")
        self.assertTrue(any("[SIMULATED]" in line for line in c.logs))

    def test_missing_hardware_shows_error(self):
        c = self.controller
        c.hardware = None
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c._start_operation()
        self.assertEqual(c.screen, "error")

    def test_cannot_start_while_previous_operation_is_stopping(self):
        c = self.controller
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.interface_index = 1
        c._start_operation()
        self.assertEqual(c.screen, "running")
        c.handle("HOME")
        c._start_operation()
        self.assertEqual(c.screen, "error")
        self.assertIn("still stopping", c.error)
        c.operation.thread.join(timeout=2)

    def test_adapter_disappearing_clamps_configuration(self):
        c = self.controller
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.screen = "config"
        c.interface_index = 1
        c.selected = len(c._config_rows()) - 1
        c._hardware_events.put(c.hardware.__class__((), (), (), (), "", False, c.hardware.tools))
        c.tick()
        self.assertEqual(c.interface_index, 0)
        self.assertLess(c.selected, len(c._config_rows()))
        c.handle("ENTER")
        self.assertEqual(c.screen, "error")


if __name__ == "__main__":
    unittest.main()
