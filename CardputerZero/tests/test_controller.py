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
        self.assertEqual(c.screen, "recon_modes")
        c.handle("ENTER")
        self.assertEqual(c.screen, "recon_scan_setup")
        c.handle("ENTER")
        self.assertEqual(c.screen, "running")
        c.handle("HOME")
        self.assertEqual(c.screen, "menu")
        self.assertEqual(c.menu, "main")

    def test_menu_hierarchy_matches_terminal(self):
        c = self.controller
        self.assertEqual(MAIN, tuple(item["name"] for item in MAIN_MENU.values()))
        self.assertEqual(SUBMENUS["Attacks"], tuple(item["name"] for item in ATTACKS_MENU.values() if item["name"] != "Back"))
        self.assertEqual(SUBMENUS["Wardrive"], tuple(item["name"] for item in WARDRIVE_MENU.values() if item["name"] != "Back"))
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
        c.handle("ESC")
        self.assertEqual(c.menu, "main")

    def test_module_starts_directly_from_description(self):
        c = self.controller
        c.screen = "detail"
        c.module = next(item for item in c.engine.modules() if item.key == "Deauth")
        c.handle("ENTER")
        self.assertEqual(c.screen, "running")

    def test_demo_operation_returns_results(self):
        c = self.controller
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.screen = "detail"
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
        self.assertEqual(c.screen, "running")

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

    def test_recon_auto_confirms_setup_after_interface(self):
        c = self.controller
        c.screen = "running"
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.recon_mode = "1"
        c.workflow_interface_selected = True
        answers = []
        events = [
            EngineEvent("input", "Input required", {"prompt": "Press Enter to switch wlan1 to monitor mode...", "secret": False}),
            EngineEvent("input", "Input required", {"prompt": "Scan duration in seconds (Enter for 12): ", "secret": False}),
            EngineEvent("input", "Input required", {"prompt": "Press Enter to start scaner on wlan1...", "secret": False}),
        ]
        c.operation = SimpleNamespace(state="running", poll=lambda: [events.pop(0)] if events else [], send=answers.append)
        for _ in range(3):
            c.tick()
        self.assertEqual(answers, ["", "", ""])
        self.assertFalse(c.awaiting_input)
        c.scan_durations["Recon"] = 25
        events.append(EngineEvent("input", "Input required", {"prompt": "Scan duration in seconds (Enter for 12): ", "secret": False}))
        c.tick()
        self.assertEqual(answers[-1], "25")

    def test_recon_color_prompt_and_stop_remain_distinct(self):
        c = self.controller
        c.screen = "running"
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.recon_mode = "2"
        c.workflow_interface_selected = True
        answers = []
        events = [
            EngineEvent("input", "Input required", {"prompt": "\x1b[32mPress Enter\x1b[0m to start sniffer on wlan1..."}),
            EngineEvent("input", "Input required", {"prompt": "Press Enter to stop sniffer: "}),
        ]
        c.operation = SimpleNamespace(state="running", poll=lambda: [events.pop(0)] if events else [], send=answers.append)
        c.tick()
        self.assertEqual(answers, [""])
        c.tick()
        self.assertTrue(c.awaiting_input)
        self.assertEqual(answers, [""])

    def test_wardrive_setup_is_automatic_but_gps_retry_is_manual(self):
        c = self.controller
        c.module = next(item for item in c.engine.modules() if item.key == "Start Wardrive")
        c.workflow_interface_selected = True
        self.assertEqual(c._automatic_answer("Press Enter to switch wlan1 to managed mode"), "")
        self.assertEqual(c._automatic_answer("Scan window in seconds (Enter for 8): "), "")
        c.scan_durations["Start Wardrive"] = 20
        self.assertEqual(c._automatic_answer("Scan window in seconds (Enter for 8): "), "20")
        self.assertEqual(c._automatic_answer("Press Enter to run GPS setup before wardrive"), "")
        self.assertIsNone(c._automatic_answer("Retry GPS setup (R) or Exit (E): "))

    def test_lan_scan_duration_uses_default_or_custom_value(self):
        c = self.controller
        for key in ("ARP scan", "IP.CAM finder"):
            c.module = next(item for item in c.engine.modules() if item.key == key)
            self.assertEqual(c._automatic_answer("Scan duration in seconds (Enter for 15): "), "")
            c.scan_durations[key] = 27
            self.assertEqual(c._automatic_answer("Scan duration in seconds (Enter for 15): "), "27")

    def test_recon_custom_duration_is_second_action(self):
        c = self.controller
        c.screen = "recon_scan_setup"
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.handle("TEXT", "t")
        self.assertEqual(c.screen, "duration_input")
        c.duration_text = ""
        c.handle("TEXT", "3")
        c.handle("TEXT", "0")
        c.handle("ENTER")
        self.assertEqual(c.scan_durations["Recon"], 30)
        self.assertEqual(c.screen, "recon_scan_setup")

    def test_recon_mode_and_scan_followup_are_automatic(self):
        c = self.controller
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.recon_mode = "1"
        self.assertEqual(c._automatic_answer("Your choice (0-2): "), "1")
        self.assertEqual(c._automatic_answer("Press Enter to return."), "")
        self.assertEqual(c._automatic_answer("Your choice (0-2): "), "0")

    def test_sniffer_live_stop_probes_resume_and_exit(self):
        c = self.controller
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.recon_mode = "2"
        c.screen = "running"
        answers = []
        events = [
            EngineEvent("input", "Input required", {"prompt": "Press Enter to stop sniffer: "}),
            EngineEvent("data", "recon_networks", {"mode": "sniffer", "networks": [{"ssid": "AP"}], "packets": 5, "probes": 2, "probe_records": [{"ssid": "LAB", "count": 2}]}),
        ]
        c.operation = SimpleNamespace(state="running", poll=lambda: [events.pop(0)] if events else [], send=answers.append)
        c.tick()
        c.tick()
        self.assertEqual(c.screen, "sniffer_live")
        self.assertEqual(c.view().probes, 2)
        c.handle("RIGHT")
        c.handle("ENTER")
        self.assertEqual(c.screen, "sniffer_probes")
        c.handle("ESC")
        c.handle("LEFT")
        c.handle("ENTER")
        self.assertEqual(answers, [""])
        self.assertEqual(c.screen, "sniffer_stopped")
        events.append(EngineEvent("input", "Input required", {"prompt": "Your choice (0/2): "}))
        c.tick()
        self.assertTrue(c.sniffer_post_choice_ready)
        c.handle("RIGHT")
        c.handle("RIGHT")
        c.handle("ENTER")
        self.assertEqual(answers, ["", "2"])
        events.append(EngineEvent("input", "Input required", {"prompt": "Press Enter to stop sniffer: "}))
        c.tick()
        c.handle("ENTER")
        events.append(EngineEvent("input", "Input required", {"prompt": "Your choice (0/2): "}))
        c.tick()
        c.handle("RIGHT")
        c.handle("RIGHT")
        c.handle("RIGHT")
        c.handle("ENTER")
        self.assertEqual(answers, ["", "2", "", "0"])
        self.assertEqual(c.screen, "menu")

    def test_sniffer_nearby_ap_list(self):
        c = self.controller
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        c.recon_mode = "2"
        c.screen = "sniffer_live"
        c.sniffer_active = True
        c.records = [{"ssid": "LAB5", "channel": 6}]
        c.handle("RIGHT")
        c.handle("RIGHT")
        c.handle("ENTER")
        self.assertEqual(c.screen, "sniffer_aps")
        self.assertEqual(c.view().records[0]["ssid"], "LAB5")
        c.handle("ESC")
        self.assertEqual(c.screen, "sniffer_live")

    def test_about_shortcut_and_qr_navigation(self):
        c = self.controller
        c.screen = "menu"
        c.handle("TEXT", "a")
        self.assertEqual(c.screen, "about")
        c.handle("ENTER")
        self.assertEqual(c.screen, "about_qr")
        c.handle("ESC")
        self.assertEqual(c.screen, "about")

    def test_esc_uses_module_back_choice_without_showing_back_card(self):
        c = self.controller
        c.screen = "running"
        c.module = next(item for item in c.engine.modules() if item.key == "Recon")
        answers = []
        events = [EngineEvent("input", "Input required", {"prompt": "Your choice (0-2): "})]
        c.console.feed("  [1] Scaner\n  [2] Sniffer\n  [0] Back\n")
        c.operation = SimpleNamespace(state="running", poll=lambda: [events.pop(0)] if events else [], send=answers.append)
        c.tick()
        self.assertEqual([label for _, label in c.choices], ["Scaner", "Sniffer"])
        c.handle("ESC")
        self.assertEqual(answers, ["0"])


if __name__ == "__main__":
    unittest.main()
