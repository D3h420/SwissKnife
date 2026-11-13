"""Layout checks for long wireless results on the tiny LCD."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


class RenderTests(unittest.TestCase):
    def test_qr_screen_survives_missing_or_broken_image(self):
        try:
            from RPi_LCD_HAT.render import Renderer
        except ImportError:
            self.skipTest("Pillow is not installed")
        with TemporaryDirectory() as directory:
            with patch("RPi_LCD_HAT.render.ASSETS", Path(directory)):
                self.assertEqual(Renderer().about_qr().size, (128, 128))
                (Path(directory) / "github-qr.png").write_bytes(b"not a PNG")
                self.assertEqual(Renderer().about_qr().size, (128, 128))

    def test_network_result_is_grouped_into_readable_rows(self):
        try:
            from RPi_LCD_HAT.logic import TerminalBuffer
            from RPi_LCD_HAT.render import Renderer
        except ImportError:
            self.skipTest("Pillow is not installed")
        buffer = TerminalBuffer()
        buffer.feed(
            "Observed networks:\n"
            "  1) Lab AP (AA:BB:CC:DD:EE:FF) - ch 6 | WPA2 | -54 dBm | clients 3 (11:22) | Vendor\n"
        )
        renderer = Renderer()
        _, draw = renderer._canvas()
        rows = renderer._output_rows(draw, buffer)
        self.assertEqual(rows[1], ("1. Lab AP", "title"))
        self.assertIn(("MAC AA:BB:CC:DD:EE:FF", "detail"), rows)
        self.assertIn(("clients 3", "detail"), rows)
        self.assertLessEqual(len(rows), 6)
        self.assertEqual(renderer.output("Recon", buffer, 0, "scroll").size, (128, 128))

        wifi = TerminalBuffer()
        wifi.feed("1) Lab AP - 83% WPA2\n2) Guest - 60% open\n")
        _, draw = renderer._canvas()
        self.assertEqual(
            renderer._output_rows(draw, wifi),
            [("1. Lab AP", "title"), ("83% WPA2", "detail"), ("2. Guest", "title"), ("60% open", "detail")],
        )


if __name__ == "__main__":
    unittest.main()
