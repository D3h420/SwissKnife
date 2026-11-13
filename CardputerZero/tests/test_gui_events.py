import json
import os
import unittest
from unittest.mock import patch

from core.gui_events import emit


class GuiEventTests(unittest.TestCase):
    def test_structured_payload_is_separate_from_module_output(self):
        with patch.dict(os.environ, {"SWISSKNIFE_GUI": "1", "SWISSKNIFE_CONTROL_FD": "2", "SWISSKNIFE_CONTROL_PREFIX": "SKINPUT:"}), patch("core.gui_events.os.write") as write:
            emit("recon_networks", networks=[{"ssid": "LAB5", "rssi": -51}])
        fd, payload = write.call_args.args
        self.assertEqual(fd, 2)
        self.assertTrue(payload.startswith(b"SKINPUT:"))
        message = json.loads(payload.removeprefix(b"SKINPUT:"))
        self.assertEqual(message["data"]["networks"][0]["ssid"], "LAB5")

    def test_terminal_run_does_not_emit_gui_payload(self):
        with patch.dict(os.environ, {}, clear=True), patch("core.gui_events.os.write") as write:
            emit("recon_networks", networks=[])
        write.assert_not_called()
