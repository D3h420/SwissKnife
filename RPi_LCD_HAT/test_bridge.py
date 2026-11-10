"""Protocol tests for the CLI-to-LCD process bridge (no GPIO required)."""

from pathlib import Path
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from RPi_LCD_HAT.bridge import ModuleProcess


def collect_until(process: ModuleProcess, predicate, timeout: float = 5.0):
    events = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events.extend(process.poll())
        if predicate(events, process.returncode):
            return events
        time.sleep(0.01)
    raise AssertionError(f"timed out; events={events!r}; returncode={process.returncode!r}")


class BridgeTests(unittest.TestCase):
    def test_pi_command_runs_os_binary_and_returns_its_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "lsusb"
            binary.write_text("#!/bin/sh\necho 'Bus 001 Device 002: USB WiFi'\n", encoding="utf-8")
            binary.chmod(0o755)
            script = Path(__file__).with_name("pi_commands.py")
            with patch.dict(os.environ, {"PATH": directory + os.pathsep + os.environ.get("PATH", "")}):
                process = ModuleProcess(script, ["usb"])
                process.start()
            try:
                events = collect_until(process, lambda events, rc: rc is not None and "USB WiFi" in "".join(value for kind, value in events if kind == "text"))
                output = "".join(value for kind, value in events if kind == "text")
                self.assertIn("$ lsusb", output)
                self.assertIn("Bus 001 Device 002: USB WiFi", output)
                self.assertEqual(process.returncode, 0)
            finally:
                process.terminate()

    def script(self, directory: str, source: str) -> Path:
        path = Path(directory) / "fixture.py"
        path.write_text(source, encoding="utf-8")
        return path

    def test_input_readline_and_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            script = self.script(
                directory,
                "import getpass, sys\n"
                "name = input('Name: ')\n"
                "sys.stdout.write('Code: '); sys.stdout.flush()\n"
                "code = sys.stdin.readline().strip()\n"
                "secret = getpass.getpass('Secret: ')\n"
                "print(f'RESULT={name}/{code}/{len(secret)}')\n",
            )
            process = ModuleProcess(script)
            process.start()
            try:
                first = collect_until(process, lambda events, _: ("input", False) in events)
                self.assertIn("Name: ", "".join(value for kind, value in first if kind == "text"))
                process.send("Ada")

                second = collect_until(process, lambda events, _: ("input", False) in events)
                self.assertIn("Code: ", "".join(value for kind, value in second if kind == "text"))
                process.send("42")

                third = collect_until(process, lambda events, _: ("input", True) in events)
                self.assertIn("Secret: ", "".join(value for kind, value in third if kind == "text"))
                process.send("private")

                final = collect_until(process, lambda events, rc: rc is not None and
                                      "RESULT=" in "".join(value for kind, value in events if kind == "text"))
                output = "".join(value for kind, value in final if kind == "text")
                self.assertIn("RESULT=Ada/42/7", output)
                self.assertNotIn("private", output)
                self.assertEqual(process.returncode, 0)
            finally:
                process.terminate()

    def test_interrupt_reaches_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            script = self.script(
                directory,
                "import time\n"
                "print('READY', flush=True)\n"
                "try:\n"
                "    while True: time.sleep(1)\n"
                "except KeyboardInterrupt:\n"
                "    print('INTERRUPTED', flush=True)\n",
            )
            process = ModuleProcess(script)
            process.start()
            try:
                collect_until(process, lambda events, _: "READY" in
                              "".join(value for kind, value in events if kind == "text"))
                process.interrupt()
                final = collect_until(process, lambda events, rc: rc is not None and
                                      "INTERRUPTED" in "".join(value for kind, value in events if kind == "text"))
                self.assertIn("INTERRUPTED", "".join(value for kind, value in final if kind == "text"))
                self.assertEqual(process.returncode, 0)
            finally:
                process.terminate()


if __name__ == "__main__":
    unittest.main()
