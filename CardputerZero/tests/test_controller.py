import time
import unittest
from types import SimpleNamespace

from CardputerZero.app.controller import Controller, MAIN, SUBMENUS, SPLASH_DELAY
from core.engine import EngineEvent, SwissKnifeEngine
from swiss_knife import MAIN_MENU, ATTACKS_MENU, WARDRIVE_MENU


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.controller = Controller(SwissKnifeEngine(demo=True))
        deadline = time.monotonic() + 2
        while self.controller.hardware is None and time.monotonic() < deadline:
            self.controller.tick()
            time.sleep(0.01)

    def test_navigation_to_terminal_workflow(self):
        c = self.controller
        c.handle("ENTER")
        self.assertEqual(c.screen, "splash")
        c.splash_started -= SPLASH_DELAY
        c.tick()
        self.assertTrue(c.view().show_prompt)
        c.handle("ENTER")
        self.assertEqual(c.screen, "menu")
        c.handle("ENTER")
        self.assertEqual(c.module.key, "Recon")
        c.handle("ENTER")
        self.assertEqual(c.screen, "confirm")
        c.handle("ENTER")
        self.assertEqual(c.screen, "running")
        c.handle("HOME")
        self.assertEqual(c.screen, "menu")
        self.assertEqual(c.menu, "main")

    def test_menu_hierarchy_matches_terminal(self):
        c = self.controller
        self.assertEqual(MAIN, tuple(item["name"] for item in MAIN_MENU.values()))
        self.assertEqual(SUBMENUS["Attacks"], tuple(item["name"] for item in ATTACKS_MENU.values()))
        self.assertEqual(SUBMENUS["Wardrive"], tuple(item["name"] for item in WARDRIVE_MENU.values()))
        c.splash_started -= SPLASH_DELAY
        c.tick()
        c.handle("TEXT", "x")
        self.assertEqual(c.screen, "menu")
        c.handle("DOWN")
        c.handle("ENTER")
        self.assertEqual(c.menu, "Attacks")
        self.assertEqual(c.view().rows, list(SUBMENUS["Attacks"]))
        c.handle("ESC")
        self.assertEqual(c.menu, "main")
        c.handle("DOWN")
        c.handle("DOWN")
        c.handle("ENTER")
        self.assertEqual(c.view().rows, list(SUBMENUS["Wardrive"]))
        c.handle("DOWN")
        c.handle("DOWN")
        c.handle("ENTER")
        self.assertEqual(c.menu, "main")

    def test_all_catalogue_modules_can_open_confirmation(self):
        c = self.controller
        c.screen = "detail"
        c.module = next(item for item in c.engine.modules() if item.key == "Deauth")
        c.handle("ENTER")
        self.assertEqual(c.screen, "confirm")

    def test_demo_operation_returns_results(self):
        c = self.controller
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.screen = "confirm"
        c.handle("ENTER")
        self.assertEqual(c.screen, "running")
        deadline = time.monotonic() + 2
        while c.screen == "running" and time.monotonic() < deadline:
            c.tick()
            time.sleep(0.01)
        self.assertEqual(c.screen, "results")
        self.assertTrue(any("[SIMULATED]" in line for line in c.logs))

    def test_module_wizard_can_report_missing_hardware_itself(self):
        c = self.controller
        c.hardware = None
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c._start_operation()
        self.assertEqual(c.screen, "running")

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

    def test_adapter_disappearing_does_not_break_menu(self):
        c = self.controller
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.screen = "detail"
        c._hardware_events.put(c.hardware.__class__((), (), (), (), "", False, c.hardware.tools))
        c.tick()
        self.assertEqual(c.hardware.wifi, ())
        c.handle("ENTER")
        self.assertEqual(c.screen, "confirm")

    def test_terminal_prompt_accepts_text_and_hides_secret(self):
        c = self.controller
        answers = []
        c.screen = "running"
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.operation = SimpleNamespace(state="running", send=answers.append)
        c.awaiting_input = True
        c.secret_input = True
        c.handle("TEXT", "s")
        c.handle("TEXT", "e")
        c.handle("BACKSPACE")
        self.assertTrue(c.view().secret_input)
        c.handle("ENTER")
        self.assertEqual(answers, ["s"])
        self.assertFalse(c.awaiting_input)

    def test_recon_structured_result_becomes_network_cards(self):
        c = self.controller
        c.screen = "running"
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        events = [EngineEvent("data", "recon_networks", {"mode": "scan", "networks": [{"ssid": "LAB5", "bssid": "02:00:00:00:00:01", "channel": 6, "rssi": -51, "encryption": "WPA2", "clients": 1}], "remaining": None})]
        c.operation = SimpleNamespace(state="running", poll=lambda: [events.pop(0)] if events else [])
        c.tick()
        self.assertEqual(c.view().screen, "networks")
        self.assertEqual(c.view().records[0]["ssid"], "LAB5")


if __name__ == "__main__":
    unittest.main()
