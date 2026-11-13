import unittest
from types import SimpleNamespace

from CardputerZero.app.keyboard import Keyboard


class KeyboardMappingTests(unittest.TestCase):
    def test_bare_navigation_keys_and_text_mode(self):
        try:
            from evdev import ecodes
        except ImportError:
            self.skipTest("python-evdev is not installed")
        keyboard = Keyboard.__new__(Keyboard)
        keyboard.ecodes = ecodes
        keyboard.shift = False
        for code, direction, letter in (
            (ecodes.KEY_F, "UP", "f"),
            (ecodes.KEY_X, "DOWN", "x"),
            (ecodes.KEY_Z, "LEFT", "z"),
            (ecodes.KEY_C, "RIGHT", "c"),
        ):
            self.assertEqual(keyboard._map(code, False), (direction, ""))
            self.assertEqual(keyboard._map(code, True), ("TEXT", letter))
        self.assertEqual(keyboard._map(ecodes.KEY_UP, False), ("UP", ""))
        self.assertIsNone(keyboard._map(ecodes.KEY_UP, True))


if __name__ == "__main__":
    unittest.main()
