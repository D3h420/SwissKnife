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
