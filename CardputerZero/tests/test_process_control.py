import sys
import threading
import time
import unittest

from core.process_control import run_cancellable


class ProcessControlTests(unittest.TestCase):
    def test_cancel_stops_child_process(self):
        cancel = threading.Event()
        result = {}

        def runner():
            result["value"] = run_cancellable(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                timeout=11,
                cancel_event=cancel,
            )

        worker = threading.Thread(target=runner)
        start = time.monotonic()
        worker.start()
        time.sleep(0.15)
        cancel.set()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(result["value"].stderr, "cancelled")


if __name__ == "__main__":
    unittest.main()
