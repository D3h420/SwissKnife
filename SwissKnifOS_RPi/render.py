"""128 x 128 pixel screens for the Seengreat LCD."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

if __package__:
    from .logic import Choice, Keyboard, TerminalBuffer
else:
    from logic import Choice, Keyboard, TerminalBuffer

SIZE = 128
BG = "#030604"
PANEL = "#142014"
ACCENT = "#a6ff3d"
HIGHLIGHT = "#ff7b19"
TEXT = "#fff6d8"
MUTED = "#bdcda8"
ASSETS = Path(__file__).resolve().parent / "assets"


def _font(size: int):
    try:
        return ImageFont.truetype("DejaVuSansMono.ttf", size)
    except OSError:
        return ImageFont.load_default()


class Renderer:
    def __init__(self) -> None:
        self.small = _font(9)
        self.body = _font(11)
        self.large = _font(16)
        self._char_widths: dict[str, int] = {}
        self._scroll_cache: tuple[TerminalBuffer, int, int] | None = None
        source = ASSETS / "logo-source.png"
        prepared = ASSETS / "logo-128.png"
        logo = source if source.exists() else prepared
        self.logo = None
        if logo.exists():
            with Image.open(logo) as original:
                resized = original.convert("RGB")
                resized.thumbnail((SIZE, SIZE), Image.Resampling.LANCZOS)
                self.logo = Image.new("RGB", (SIZE, SIZE), "black")
                self.logo.paste(resized, ((SIZE - resized.width) // 2, (SIZE - resized.height) // 2))

    def _canvas(self):
        image = Image.new("RGB", (SIZE, SIZE), BG)
        draw = ImageDraw.Draw(image)
        draw.fontmode = "1"  # No grey antialias pixels at the LCD's native resolution.
        return image, draw

    @staticmethod
    def _width(draw: ImageDraw.ImageDraw, value: str, font) -> int:
        box = draw.textbbox((0, 0), value, font=font)
        return box[2] - box[0]

    def _fit(self, draw: ImageDraw.ImageDraw, value: str, width: int, font) -> str:
        value = value.replace("\n", " ")
        if self._width(draw, value, font) <= width:
            return value
        low, high = 0, len(value)
        while low < high:
            middle = (low + high + 1) // 2
            if self._width(draw, value[:middle] + "…", font) <= width:
                low = middle
            else:
                high = middle - 1
        return value[:low] + "…"

    def _header(self, draw: ImageDraw.ImageDraw, title: str, state: str = "") -> None:
        draw.rectangle((0, 0, 127, 17), fill=PANEL)
        draw.rectangle((0, 16, 127, 17), fill=ACCENT)
        draw.rectangle((3, 4, 10, 11), fill=ACCENT)
        draw.text((15, 3), self._fit(draw, title, 82, self.body), font=self.body, fill=TEXT)
        if state:
            state = self._fit(draw, state, 29, self.small)
            draw.text((126 - self._width(draw, state, self.small), 4), state, font=self.small, fill=ACCENT)

    def _footer(self, draw: ImageDraw.ImageDraw, hint: str) -> None:
        draw.rectangle((0, 114, 127, 127), fill=PANEL)
        draw.rectangle((0, 113, 127, 113), fill="#45692b")
        draw.text((3, 115), self._fit(draw, hint, 123, self.small), font=self.small, fill=MUTED)

    def boot(self) -> Image.Image:
        image, draw = self._canvas()
        if self.logo is not None:
            image.paste(self.logo, (0, 0))
            draw = ImageDraw.Draw(image)
            draw.fontmode = "1"
        else:
            draw.text((15, 48), "SWISSKNIFE", font=self.large, fill=TEXT)
        draw.rectangle((0, 114, 127, 127), fill=BG)
        hint = "PRESS ANY KEY"
        draw.text(((SIZE - self._width(draw, hint, self.small)) // 2, 116), hint, font=self.small, fill=ACCENT)
        return image

    def menu(self, title: str, items: list[str], selected: int) -> Image.Image:
        image, draw = self._canvas()
        self._header(draw, title, f"{selected + 1}/{len(items)}")
        count = 5
        first = max(0, min(selected - 3, len(items) - count))
        first = max(0, first)
        for offset, index in enumerate(range(first, min(first + count, len(items)))):
            y = 22 + 18 * offset
            active = index == selected
            if active:
                draw.rectangle((2, y, 125, y + 16), fill=HIGHLIGHT)
                draw.rectangle((2, y, 5, y + 16), fill=ACCENT)
            else:
                draw.rectangle((2, y, 125, y + 16), fill=PANEL)
                draw.rectangle((2, y, 3, y + 16), fill="#426028")
            number = f"{index + 1:02d}"
            draw.text((9, y + 2), number, font=self.small, fill=BG if active else ACCENT)
            draw.text((30, y + 1), self._fit(draw, items[index], 87, self.body), font=self.body, fill=BG if active else TEXT)
            draw.text((117, y + 2), ">", font=self.small, fill=BG if active else ACCENT)
        self._footer(draw, "UP/DN select  OK open")
        return image

    def choices(self, title: str, prompt: str, options: list[Choice], selected: int) -> Image.Image:
        image, draw = self._canvas()
        self._header(draw, title, "IN")
        prompt = self._fit(draw, prompt, 124, self.small)
        draw.text((3, 19), prompt, font=self.small, fill=MUTED)
        count = 6
        first = max(0, min(selected - 4, len(options) - count))
        first = max(0, first)
        for offset, index in enumerate(range(first, min(first + count, len(options)))):
            y = 32 + 13 * offset
            active = index == selected
            if active:
                draw.rounded_rectangle((2, y - 1, 125, y + 11), radius=2, fill=ACCENT)
            label = f"{options[index].key} {options[index].label}"
            draw.text((5, y), self._fit(draw, label, 119, self.small), font=self.small, fill=BG if active else TEXT)
        self._footer(draw, "OK pick  K2 type  K1 log")
        return image

    def _wrap(self, draw: ImageDraw.ImageDraw, line: str, width: int) -> list[str]:
        if not line:
            return [""]
        parts: list[str] = []
        current = ""
        used = 0
        for char in line:
            char_width = self._char_widths.get(char)
            if char_width is None:
                char_width = self._width(draw, char, self.small)
                self._char_widths[char] = char_width
            if current and used + char_width > width:
                parts.append(current)
                current = ""
                used = 0
            current += char
            used += char_width
        if current:
            parts.append(current)
        return parts

    def output(self, title: str, buffer: TerminalBuffer, scroll: int, hint: str, state: str = "") -> Image.Image:
        image, draw = self._canvas()
        self._header(draw, title, state)
        visual_reverse: list[str] = []
        for line in reversed(buffer.visible_lines()):
            visual_reverse.extend(reversed(self._wrap(draw, line, 122)))
            if len(visual_reverse) >= scroll + 8:
                break
        visual = list(reversed(visual_reverse))
        scroll = min(scroll, max(0, len(visual) - 8))
        end = max(0, len(visual) - scroll)
        visible = visual[max(0, end - 8):end]
        for index, line in enumerate(visible):
            draw.text((3, 19 + 11 * index), line, font=self.small, fill=TEXT)
        self._footer(draw, hint)
        return image

    def max_scroll(self, buffer: TerminalBuffer) -> int:
        cache = self._scroll_cache
        if cache is not None and cache[0] is buffer and cache[1] == buffer.version:
            return cache[2]
        _, draw = self._canvas()
        count = sum(len(self._wrap(draw, line, 122)) for line in buffer.visible_lines())
        result = max(0, count - 8)
        self._scroll_cache = (buffer, buffer.version, result)
        return result

    def keyboard(self, prompt: str, keyboard: Keyboard) -> Image.Image:
        image, draw = self._canvas()
        prompt = self._fit(draw, prompt or "Enter text", 124, self.small)
        draw.text((3, 1), prompt, font=self.small, fill=MUTED)
        draw.rounded_rectangle((2, 15, 125, 30), radius=2, fill=PANEL)
        display = "•" * len(keyboard.value) if keyboard.secret else keyboard.value
        if not display:
            display = "_"
        while self._width(draw, display, self.body) > 116:
            display = display[1:]
        draw.text((5, 17), display, font=self.body, fill=TEXT)
        keys = keyboard.keys
        for index, key in enumerate(keys):
            row, col = divmod(index, 8)
            x, y = col * 16, 34 + row * 13
            selected = keyboard.cursor == index
            if selected:
                draw.rounded_rectangle((x, y, x + 15, y + 12), radius=2, fill=ACCENT)
            elif index >= 42:
                draw.rectangle((x, y, x + 15, y + 12), outline="#29415a")
            label = {"SHIFT": "^", "LOG": "L", "DEL": "<", "SP": "SP", "SYM": "#"}.get(key, key)
            label = self._fit(draw, label, 15, self.small)
            tx = x + (16 - self._width(draw, label, self.small)) // 2
            draw.text((tx, y + 2), label, font=self.small, fill=BG if selected else TEXT)
        self._footer(draw, "K3 del  K4 space  R send")
        return image

    def message(self, title: str, lines: list[str], hint: str) -> Image.Image:
        image, draw = self._canvas()
        self._header(draw, title)
        y = 22
        for line in lines:
            for part in self._wrap(draw, line, 120):
                draw.text((4, y), part, font=self.body, fill=TEXT)
                y += 14
                if y > 104:
                    break
            if y > 104:
                break
        self._footer(draw, hint)
        return image
