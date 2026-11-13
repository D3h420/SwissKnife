import time
import unittest
from unittest.mock import patch

from core.engine import SwissKnifeEngine, available_modules, compatibility_issues, module_status
from core.hardware import HardwareSnapshot, WiFiAdapter


def hardware(*, wifi=True, gps=True, tools=None, route="wlan0"):
    return HardwareSnapshot(
        ("wlan0", "wlan1") if wifi else (),
        (WiFiAdapter("wlan0", "test", "managed", False, None), WiFiAdapter("wlan1", "test", "managed", True, True)) if wifi else (),
        (), ("/dev/ttyUSB0",) if gps else (), route, False,
        frozenset(tools if tools is not None else {"iw", "ip", "ping", "stty"}),
    )


class EngineTests(unittest.TestCase):
    def test_catalogue_uses_shared_feature_registry(self):
        from core.features import FEATURES
        self.assertEqual([module.label for module in available_modules()], [feature.label for feature in FEATURES])
        self.assertEqual(len(available_modules()), 11)

    def test_dependency_and_hardware_status(self):
        recon = next(module for module in available_modules() if module.key == "Recon")
        self.assertEqual(module_status(recon, hardware(tools=set()))[0], "missing_dependency")
        self.assertEqual(module_status(recon, hardware(wifi=False))[0], "missing_hardware")
        self.assertEqual(module_status(recon, hardware())[0], "needs_device_test")

    def test_every_terminal_module_has_a_cardputer_entry(self):
        from pathlib import Path
        from core.features import FEATURES

        root = Path(__file__).resolve().parents[2]
        modules = {module.key: module for module in available_modules()}
        self.assertEqual(set(modules), {feature.label for feature in FEATURES})
        for feature in FEATURES:
            with self.subTest(feature=feature.label):
                self.assertTrue(modules[feature.label].enabled)
                self.assertTrue((root / feature.script).is_file())

    def test_terminal_module_has_hardware_diagnostics(self):
        deauth = next(module for module in available_modules() if module.key == "Deauth")
        self.assertEqual(module_status(deauth, hardware(tools=set()))[0], "missing_dependency")
        self.assertIn("Monitor-mode adapter not confirmed", compatibility_issues(deauth, hardware(wifi=False)))

    def test_management_connection_requires_confirmation(self):
        engine = SwissKnifeEngine(demo=True)
        with self.assertRaises(PermissionError):
            engine.start("Recon", {"interface": "wlan0"}, hardware=hardware())

    def test_disconnected_adapter_is_rejected(self):
        engine = SwissKnifeEngine(demo=True)
        with self.assertRaises(ValueError):
            engine.start("Recon", {"interface": "wlan9"}, hardware=hardware())

    def test_demo_events_and_cancel(self):
        engine = SwissKnifeEngine(demo=True)
        operation = engine.start("Recon", {"interface": "wlan1"}, hardware=hardware())
        operation.cancel()
        operation.thread.join(timeout=2)
        self.assertEqual(operation.state, "cancelled")
        self.assertTrue(any(event.kind == "finished" for event in operation.poll()))

    def test_every_terminal_module_starts_in_simulation(self):
        engine = SwissKnifeEngine(demo=True)
        for module in engine.modules():
            with self.subTest(module=module.key):
                operation = engine.start_terminal(module.key)
                operation.thread.join(timeout=2)
                self.assertFalse(operation.thread.is_alive())
                self.assertEqual(operation.state, "completed")
                events = operation.poll()
                self.assertTrue(any(event.kind == "finished" for event in events))
                self.assertTrue(any("SIMULATED" in event.message for event in events))

    def test_backend_exception_becomes_error_event(self):
        engine = SwissKnifeEngine(demo=False)
        with patch.object(engine, "_recon", side_effect=RuntimeError("scan failed")), \
             patch("core.engine.LOG_DIR") as log_dir:
            log_dir.__truediv__.return_value = None
            operation = engine.start("Recon", {"interface": "wlan1"}, hardware=hardware())
            operation.thread.join(timeout=2)
        self.assertEqual(operation.state, "error")
        self.assertTrue(any("scan failed" in event.message for event in operation.poll()))


if __name__ == "__main__":
    unittest.main()
