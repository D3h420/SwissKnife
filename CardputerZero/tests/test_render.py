import importlib.util
import unittest

from CardputerZero.app.controller import ViewState


@unittest.skipUnless(importlib.util.find_spec("PIL"), "Pillow not installed")
class RenderTests(unittest.TestCase):
    def test_native_resolution_and_all_screen_types(self):
        from CardputerZero.app.render import Renderer

        renderer = Renderer()
        for screen in ("splash", "list", "detail", "log"):
            with self.subTest(screen=screen):
                frame = renderer.draw(
                    ViewState(screen=screen, title="SwissKnife", rows=["A long result " * 8] * 12, simulated=True),
                )
                self.assertEqual(frame.size, (320, 170))

    def test_sdr_waterfall_frame(self):
        from CardputerZero.app.render import Renderer
        from modules.sdr import SDRSession

        sdr = SDRSession(demo=True)
        sdr.start_spectrum()
        frame = Renderer().draw(ViewState(screen="sdr", title="SDR", sdr=sdr.snapshot(), simulated=True))
        self.assertEqual(frame.size, (320, 170))
        sdr.close()


if __name__ == "__main__":
    unittest.main()
