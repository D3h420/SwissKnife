"""Tests for prompt recognition and button-driven text entry."""

import unittest

from SwissKnifOS_RPi.logic import Keyboard, TerminalBuffer, input_mode


class LogicTests(unittest.TestCase):
    def test_ansi_and_carriage_return_output(self) -> None:
        buffer = TerminalBuffer()
        buffer.feed("\x1b[31mScanning 1\rScanning 2\r\nReady\n")
        self.assertEqual(buffer.visible_lines(), ["Scanning 2", "Ready"])

    def test_numbered_menu_and_network_table(self) -> None:
        buffer = TerminalBuffer()
        buffer.feed("Recon menu:\n  [1] Scan\n  [2] Sniffer\n  [0] Back\nYour choice (0-2): ")
        mode, options = input_mode(buffer)
        self.assertEqual(mode, "choices")
        self.assertEqual([(option.key, option.label) for option in options],
                         [("1", "Scan"), ("2", "Sniffer"), ("0", "Back")])

        buffer = TerminalBuffer()
        buffer.feed("# | SSID | BSSID\n1 | Lab AP | 12:34\n2 | Test AP | 56:78\nChoose network number [1]: ")
        mode, options = input_mode(buffer)
        self.assertEqual(mode, "choices")
        self.assertEqual([option.key for option in options], ["1", "2"])

        buffer = TerminalBuffer()
        buffer.feed("#  SSID  BSSID\n1  Lab AP  12:34\n2  Test AP  56:78\nChoose network number [1]: ")
        mode, options = input_mode(buffer)
        self.assertEqual(mode, "choices")
        self.assertEqual([option.key for option in options], ["1", "2"])

    def test_text_input_does_not_reuse_old_menu(self) -> None:
        buffer = TerminalBuffer()
        buffer.feed("[1] Scan\n[0] Back\nYour choice: \nEnter SSID: ")
        self.assertEqual(input_mode(buffer), ("keyboard", []))

    def test_enter_and_keyboard(self) -> None:
        buffer = TerminalBuffer()
        buffer.feed("Press Enter to start scan...")
        self.assertEqual(input_mode(buffer), ("enter", []))
        buffer = TerminalBuffer()
        buffer.feed("Scan duration (Enter for 12): ")
        self.assertEqual(input_mode(buffer), ("keyboard", []))

        keyboard = Keyboard(secret=True)
        self.assertEqual(keyboard.keys[0], "a")
        keyboard.activate()
        self.assertEqual(keyboard.value, "a")
        keyboard.cursor = 43  # DEL
        keyboard.activate()
        self.assertEqual(keyboard.value, "")
        keyboard.cursor = 44  # OK
        self.assertEqual(keyboard.activate(), "submit")


if __name__ == "__main__":
    unittest.main()
