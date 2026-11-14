import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from CardputerZero.app.controller import ViewState


@unittest.skipUnless(importlib.util.find_spec("PIL"), "Pillow not installed")
class RenderTests(unittest.TestCase):
    def test_native_resolution_and_all_screen_types(self):
        from CardputerZero.app.render import Renderer

        renderer = Renderer()
        for screen in ("splash", "list", "detail", "log", "about", "screen_settings", "recon_modes", "recon_scan_setup", "sniffer_live", "sniffer_stopped", "sniffer_probes", "sniffer_aps", "workflow_wait", "workflow_choice", "workflow_text", "workflow_scan", "workflow_start", "workflow_live", "workflow_result"):
            with self.subTest(screen=screen):
                frame = renderer.draw(
                    ViewState(screen=screen, title="SwissKnife", rows=["A long result " * 8] * 12, simulated=True),
                )
                self.assertEqual(frame.size, (320, 170))

    def test_workflow_choice_supports_network_records_and_long_lists(self):
        from CardputerZero.app.render import Renderer

        renderer = Renderer()
        records = [{"ssid": f"Network {i}", "channel": i, "signal": -50 - i} for i in range(8)]
        frame = renderer.draw(ViewState(screen="workflow_choice", title="TARGET", description="Choose network", records=records, selected=7))
        self.assertEqual(frame.size, (320, 170))
        rows = [f"Interface {i}" for i in range(8)]
        frame = renderer.draw(ViewState(screen="workflow_choice", title="INTERFACE", rows=rows, selected=7))
        self.assertEqual(frame.size, (320, 170))

    @unittest.skipUnless(importlib.util.find_spec("qrcode"), "python-qrcode not installed")
    def test_repository_qr_screen(self):
        from CardputerZero.app.render import Renderer

        frame = Renderer().draw(ViewState(screen="about_qr", title="GITHUB"))
        self.assertEqual(frame.size, (320, 170))

    def test_intro_and_delayed_prompt(self):
        from CardputerZero.app.render import Renderer

        renderer = Renderer()
        self.assertIsNotNone(renderer.intro)
        before = renderer.draw(ViewState(screen="splash"))
        after = renderer.draw(ViewState(screen="splash", show_prompt=True))
        self.assertEqual(before.size, (320, 170))
        self.assertNotEqual(before.getpixel((160, 157)), after.getpixel((160, 157)))

    def test_sleep_restores_backlight_when_writable(self):
        from CardputerZero.app.framebuffer import Framebuffer

        with tempfile.TemporaryDirectory() as directory:
            brightness = Path(directory) / "brightness"
            brightness.write_text("72\n", encoding="ascii")
            frame = Framebuffer.__new__(Framebuffer)
            frame.width, frame.height = 320, 170
            frame._saved_brightness = None
            frame.show = Mock()
            with patch("CardputerZero.app.framebuffer.Path.glob", return_value=[brightness]):
                frame.sleep()
            self.assertEqual(brightness.read_text(encoding="ascii"), "0\n")
            frame.wake()
            self.assertEqual(brightness.read_text(encoding="ascii"), "72\n")
            frame.show.assert_not_called()

    def test_sleep_draws_black_when_backlight_is_unavailable(self):
        from CardputerZero.app.framebuffer import Framebuffer

        frame = Framebuffer.__new__(Framebuffer)
        frame.width, frame.height = 320, 170
        frame._saved_brightness = None
        frame.show = Mock()
        with patch("CardputerZero.app.framebuffer.Path.glob", return_value=[]):
            frame.sleep()
        image = frame.show.call_args.args[0]
        self.assertEqual(image.getpixel((160, 85)), (0, 0, 0))

    def test_usb_wifi_icon_appears_only_when_adapter_is_detected(self):
        from PIL import ImageChops
        from CardputerZero.app.render import Renderer

        renderer = Renderer()
        state = ViewState(screen="list", title="MAIN MENU", rows=["Recon"])
        without = renderer.draw(state, usb_wifi_connected=False)
        with_adapter = renderer.draw(state, usb_wifi_connected=True)
        indicator = ImageChops.difference(without.crop((271, 7, 286, 26)), with_adapter.crop((271, 7, 286, 26)))
        self.assertIsNotNone(indicator.getbbox())
        self.assertEqual(without.crop((240, 8, 271, 27)).tobytes(), with_adapter.crop((240, 8, 271, 27)).tobytes())



if __name__ == "__main__":
    unittest.main()
