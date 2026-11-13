"""Exercise the Cardputer CLI bridge without sudo or radio hardware."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from core.cli_bridge import CliOperation


def _collect_until(operation: CliOperation, predicate, timeout: float = 3.0):
    events = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events.extend(operation.poll())
        if predicate(events):
            return events
        time.sleep(0.01)
    raise AssertionError(f"Timed out waiting for CLI event; state={operation.state}, events={events}")


class CliBridgeTests(unittest.TestCase):
    @staticmethod
    def _replace_sudo(script: Path):
        original = subprocess.Popen

        def launch(command, **kwargs):
            assert command[:3] == ["sudo", "-n", "/tmp/test-swissknife-helper"]
            return original([sys.executable, "-u", str(script)], **kwargs)

        return launch

    def test_prompts_secret_answer_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "module.py"
            script.write_text(
                "import json, sys\n"
                "print('Name: ', end='', flush=True)\n"
                "print('SKINPUT:' + json.dumps({'type': 'input', 'secret': False}), file=sys.stderr, flush=True)\n"
                "name = sys.stdin.readline().strip()\n"
                "print('Secret: ', end='', flush=True)\n"
                "print('SKINPUT:' + json.dumps({'type': 'input', 'secret': True}), file=sys.stderr, flush=True)\n"
                "secret = sys.stdin.readline().strip()\n"
                "print(f'RESULT={name}/{len(secret)}', flush=True)\n",
                encoding="utf-8",
            )
            with patch("core.cli_bridge.subprocess.Popen", side_effect=self._replace_sudo(script)):
                operation = CliOperation("Recon", helper=Path("/tmp/test-swissknife-helper"))
                events = _collect_until(operation, lambda items: any(item.kind == "input" for item in items))
                self.assertTrue(operation.awaiting_input)
                self.assertFalse(operation.secret)
                self.assertEqual(next(item for item in events if item.kind == "input").data["secret"], False)
                with self.assertRaises(ValueError):
                    operation.send("bad\ninput")
                operation.send("Lab5")
                events.extend(_collect_until(operation, lambda items: any(item.kind == "input" for item in items)))
                self.assertTrue(operation.awaiting_input)
                self.assertTrue(operation.secret)
                operation.send("hidden")
                events.extend(_collect_until(operation, lambda items: any(item.kind == "finished" for item in items)))
                operation.thread.join(timeout=1)
                self.assertEqual(operation.state, "completed")
                self.assertIn("RESULT=Lab5/6", "".join(item.message for item in events if item.kind == "output"))
                self.assertNotIn("hidden", "".join(item.message for item in events))

    def test_cancel_stops_a_running_module(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "module.py"
            script.write_text("import time\nprint('READY', flush=True)\nwhile True: time.sleep(0.1)\n", encoding="utf-8")
            with patch("core.cli_bridge.subprocess.Popen", side_effect=self._replace_sudo(script)):
                operation = CliOperation("Recon", helper=Path("/tmp/test-swissknife-helper"))
                _collect_until(operation, lambda items: any("READY" in item.message for item in items))
                operation.cancel()
                operation.thread.join(timeout=2)
                self.assertFalse(operation.thread.is_alive())
                self.assertEqual(operation.state, "cancelled")
                self.assertTrue(any(item.kind == "finished" for item in operation.poll()))


if __name__ == "__main__":
    unittest.main()
