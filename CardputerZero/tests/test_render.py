import importlib.util
import unittest

from CardputerZero.app.controller import ViewState


@unittest.skipUnless(importlib.util.find_spec("PIL"), "Pillow not installed")
class RenderTests(unittest.TestCase):
    def test_native_resolution_and_all_screen_types(self):
        from CardputerZero.app.render import Renderer

        renderer = Renderer()
        for screen in ("splash", "list", "detail", "log", "about", "recon_modes", "recon_scan_setup", "sniffer_live", "sniffer_stopped", "sniffer_probes", "sniffer_aps", "workflow_wait", "workflow_choice", "workflow_text", "workflow_scan", "workflow_start", "workflow_live", "workflow_result"):
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



if __name__ == "__main__":
    unittest.main()
