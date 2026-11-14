import tempfile
import unittest
from pathlib import Path

from CardputerZero.app.settings import IdleScreen, load_screen_timeout, save_screen_timeout


class SettingsTests(unittest.TestCase):
    def test_valid_timeout_persists_and_invalid_file_falls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            self.assertEqual(load_screen_timeout(path), 0)
            save_screen_timeout(path, 120)
            self.assertEqual(load_screen_timeout(path), 120)
            with self.assertRaises(ValueError):
                save_screen_timeout(path, -1)
            path.write_text('{"screen_timeout_seconds": true}', encoding="utf-8")
            self.assertEqual(load_screen_timeout(path), 0)

    def test_idle_first_key_only_wakes_screen(self):
        idle = IdleScreen()
        idle.last_activity = 10.0
        self.assertFalse(idle.should_blank(0, now=100.0))
        self.assertFalse(idle.should_blank(30, now=39.9))
        self.assertTrue(idle.should_blank(30, now=40.0))
        self.assertTrue(idle.key_pressed(now=41.0))
        self.assertFalse(idle.key_pressed(now=42.0))
        self.assertFalse(idle.should_blank(30, now=60.0))


if __name__ == "__main__":
    unittest.main()
