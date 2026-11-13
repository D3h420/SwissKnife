import unittest

from core.gui_choices import current_choices


class ChoiceTests(unittest.TestCase):
    def test_numbered_choices_near_prompt(self):
        lines = ["Recon menu:", "  [1] Scaner", "  [2] Sniffer", "  [0] Back", "Your choice (0-2):"]
        self.assertEqual(current_choices(lines), [("1", "Scaner"), ("2", "Sniffer"), ("0", "Back")])

    def test_unrelated_old_choices_are_ignored(self):
        lines = ["1) Old option", "many lines"] + ["other output"] * 5 + ["Enter SSID:"]
        self.assertEqual(current_choices(lines), [])
