"""128 x 128 pixel screens for the Seengreat LCD."""

from __future__ import annotations

from PIL import Image, ImageDraw, ImageFont

if __package__:
    from .logic import Choice, Keyboard, TerminalBuffer
else:
    from logic import Choice, Keyboard, TerminalBuffer

SIZE = 128
BG = "#091425"
PANEL = "#142741"
ACCENT = "#49d6e8"
TEXT = "#edf6ff"
MUTED = "#9bb3c9"


def _font(size: int):
    try:
        return ImageFont.truetype("DejaVuSans.ttf", size)
    except OSError:
        return ImageFont.load_default()


class Renderer:
    def __init__(self) -> None:
        self.small = _font(8)
        self.body = _font(10)
        self.large = _font(17)
        self._char_widths: dict[str, int] = {}
        self._scroll_cache: tuple[TerminalBuffer, int, int] | None = None

    def _canvas(self):
        image = Image.new("RGB", (SIZE, SIZE), BG)
        return image, ImageDraw.Draw(image)

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
        draw.rectangle((0, 0, 127, 16), fill=PANEL)
        draw.rectangle((0, 0, 3, 16), fill=ACCENT)
        draw.text((8, 3), self._fit(draw, title, 94, self.body), font=self.body, fill=TEXT)
        if state:
            state = self._fit(draw, state, 28, self.small)
            draw.text((126 - self._width(draw, state, self.small), 4), state, font=self.small, fill=ACCENT)

    def _footer(self, draw: ImageDraw.ImageDraw, hint: str) -> None:
        draw.rectangle((0, 114, 127, 127), fill=PANEL)
        draw.text((3, 116), self._fit(draw, hint, 123, self.small), font=self.small, fill=MUTED)

    def boot(self) -> Image.Image:
        image, draw = self._canvas()
        draw.rounded_rectangle((37, 10, 91, 64), radius=12, fill=PANEL, outline=ACCENT, width=2)
        draw.polygon([(49, 48), (75, 22), (82, 29), (56, 55)], fill=ACCENT)
        draw.polygon([(75, 22), (87, 17), (82, 29)], fill=TEXT)
        draw.ellipse((45, 48, 55, 58), fill=BG, outline=TEXT)
        for word, y, font, color in (
            ("SWISS", 72, self.large, TEXT),
            ("KNIFOS", 91, self.large, ACCENT),
            ("Raspberry Pi", 116, self.small, MUTED),
        ):
            x = (SIZE - self._width(draw, word, font)) // 2
            draw.text((x, y), word, font=font, fill=color)
        return image

    def menu(self, title: str, items: list[str], selected: int) -> Image.Image:
        image, draw = self._canvas()
        self._header(draw, title)
        count = 6
        first = max(0, min(selected - 4, len(items) - count))
        first = max(0, first)
        for offset, index in enumerate(range(first, min(first + count, len(items)))):
            y = 20 + 15 * offset
            active = index == selected
            if active:
                draw.rounded_rectangle((3, y - 1, 124, y + 13), radius=3, fill=ACCENT)
            draw.text((6, y), ">" if active else " ", font=self.body, fill=BG if active else MUTED)
            draw.text((17, y), self._fit(draw, items[index], 105, self.body), font=self.body, fill=BG if active else TEXT)
        self._footer(draw, "U/D move  OK go  K1 back")
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
