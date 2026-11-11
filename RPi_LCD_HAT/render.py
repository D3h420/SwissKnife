"""128 x 128 pixel screens for the Seengreat LCD."""

from __future__ import annotations

import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from modules.sdr import SDRSnapshot

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
OUTPUT_ROWS = 6
_NETWORK_ROW = re.compile(r"^\s*(\d{1,2})[).]\s+(.+?)\s+\(([0-9A-Fa-f:]{17})\)\s*-\s*(.*)$")
_NUMBERED_ROW = re.compile(r"^\s*(\d{1,2})[).]\s+(.+?)\s+-\s+(.+)$")


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
        self._visual_cache: tuple[TerminalBuffer, int, list[tuple[str, str]]] | None = None
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
        self.qr = None
        qr_path = ASSETS / "github-qr.png"
        try:
            with Image.open(qr_path) as original:
                original.load()
                self.qr = original.convert("RGB")
        except (OSError, ValueError):
            pass

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

    def about_info(self) -> Image.Image:
        image, draw = self._canvas()
        self._header(draw, "About", "1/2")
        draw.text((7, 23), "SWISSKNIFE", font=self.large, fill=ACCENT)
        draw.rectangle((7, 45, 120, 45), fill=HIGHLIGHT)
        draw.text((7, 51), "D3h420 from LAB5", font=self.small, fill=TEXT)
        draw.text((7, 68), "github.com/", font=self.body, fill=MUTED)
        draw.text((7, 82), "D3h420/SwissKnife", font=self.small, fill=TEXT)
        self._footer(draw, "K1: show QR  LEFT: back")
        return image

    def about_qr(self) -> Image.Image:
        image, draw = self._canvas()
        draw.rectangle((0, 0, 127, 13), fill=PANEL)
        draw.text((4, 1), "GITHUB QR", font=self.small, fill=ACCENT)
        draw.text((77, 1), "K1 close", font=self.small, fill=TEXT)
        if self.qr is not None:
            image.paste(self.qr, (8, 16))
        else:
            draw.text((8, 48), "QR unavailable", font=self.body, fill=TEXT)
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

    def sdr(self, state: SDRSnapshot | None, error: str, step_hz: int) -> Image.Image:
        image, draw = self._canvas()
        self._header(draw, "SDR", state.mode.upper() if state else "WAIT")
        if state is None:
            draw.text((4, 27), "Starting receiver...", font=self.small, fill=TEXT)
            self._footer(draw, "K3 back")
            return image
        config = state.config
        draw.text((3, 19), f"{config.center_hz / 1e6:.3f} MHz", font=self.body, fill=ACCENT)
        draw.text((3, 101), self._fit(draw, error or state.message, 122, self.small), font=self.small, fill=HIGHLIGHT if error or state.mode == "error" else MUTED)
        if state.mode == "spectrum":
            rows = state.waterfall[-68:]
            for row_index, row in enumerate(rows):
                y = 99 - len(rows) + row_index
                if y < 31:
                    continue
                for x in range(128):
                    level = row[min(len(row) - 1, int(x * len(row) / 128))]
                    strength = max(0, min(255, int((level + 105) * 4)))
                    draw.point((x, y), fill=(strength // 2, min(255, strength), strength // 5))
            if not rows:
                draw.text((4, 55), "Waiting for sweep...", font=self.small, fill=MUTED)
        if state.mode == "adsb":
            draw.text((3, 34), f"Aircraft: {len(state.aircraft)}", font=self.small, fill=ACCENT)
            for index, aircraft in enumerate(state.aircraft[:4]):
                draw.text((3, 48 + index * 12), self._fit(draw, aircraft, 120, self.small), font=self.small, fill=TEXT)
        elif state.mode in {"audio", "record"}:
            draw.text((3, 41), "AUDIO" if state.mode == "audio" else "IQ RECORDING", font=self.body, fill=HIGHLIGHT)
            draw.text((3, 60), f"Mode {config.modulation}  Dev {config.device}", font=self.small, fill=TEXT)
            if state.recording and state.mode == "record":
                draw.text((3, 75), self._fit(draw, Path(state.recording).name, 120, self.small), font=self.small, fill=MUTED)
        self._footer(draw, f"K3< K4 on/off {step_hz // 1000}k")
        return image

    def choices(self, title: str, prompt: str, options: list[Choice], selected: int) -> Image.Image:
        image, draw = self._canvas()
        self._header(draw, title, "IN")
        prompt = self._fit(draw, prompt, 124, self.small)
        draw.text((3, 19), prompt, font=self.small, fill=MUTED)
        compact = len(options) <= 4 and all(
            " - " not in option.label and not _NETWORK_ROW.match(f"1) {option.label}")
            for option in options
        )
        count = 4 if compact else 3
        first = max(0, min(selected - 1, len(options) - count))
        first = max(0, first)
        for offset, index in enumerate(range(first, min(first + count, len(options)))):
            y = 31 + 20 * offset if compact else 29 + 27 * offset
            height = 18 if compact else 24
            active = index == selected
            if active:
                draw.rectangle((2, y, 125, y + height), fill=HIGHLIGHT)
            else:
                draw.rectangle((2, y, 125, y + height), fill=PANEL)
            key = options[index].key
            label = options[index].label
            network = _NETWORK_ROW.match(f"1) {label}")
            if network:
                label = network.group(2)
                detail = f"{network.group(3)} {network.group(4)}"
            elif " - " in label:
                label, detail = label.split(" - ", 1)
            else:
                detail = ""
            draw.text((5, y + (4 if compact else 3)), self._fit(draw, key, 18, self.small), font=self.small, fill=BG if active else ACCENT)
            draw.text((25, y + (3 if compact else 1)), self._fit(draw, label, 98, self.body), font=self.body, fill=BG if active else TEXT)
            if detail and not compact:
                draw.text((25, y + 13), self._fit(draw, detail, 98, self.small), font=self.small, fill=BG if active else MUTED)
        self._footer(draw, "UP/DN choose  OK select")
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

    def _output_rows(self, draw: ImageDraw.ImageDraw, buffer: TerminalBuffer) -> list[tuple[str, str]]:
        cache = self._visual_cache
        if cache is not None and cache[0] is buffer and cache[1] == buffer.version:
            return cache[2]
        rows: list[tuple[str, str]] = []

        def add(value: str, role: str = "plain") -> None:
            for part in self._wrap(draw, value.strip(), 121):
                if part:
                    rows.append((part, role))

        for raw in buffer.visible_lines():
            line = raw.strip()
            if not line or re.fullmatch(r"[=+\-|\s]{4,}", line):
                continue
            if line.startswith("|") and line.endswith("|"):
                line = line[1:-1].strip()
            network = _NETWORK_ROW.match(line)
            if network:
                number, ssid, bssid, details = network.groups()
                rows.append((self._fit(draw, f"{number}. {ssid}", 121, self.small), "title"))
                add(f"MAC {bssid}", "detail")
                parts = [part.strip() for part in details.split("|")]
                add("  ".join(parts[:3]), "detail")
                if len(parts) > 3:
                    add(parts[3].split("(", 1)[0].strip(), "detail")
                continue
            numbered = _NUMBERED_ROW.match(line)
            if numbered:
                number, name, details = numbered.groups()
                add(f"{number}. {name}", "title")
                add(details, "detail")
                continue
            role = "section" if line.endswith(":") and len(line) < 36 else "plain"
            add(line, role)
        self._visual_cache = (buffer, buffer.version, rows)
        return rows

    def output(self, title: str, buffer: TerminalBuffer, scroll: int, hint: str, state: str = "") -> Image.Image:
        image, draw = self._canvas()
        self._header(draw, title, state)
        rows = self._output_rows(draw, buffer)
        scroll = min(scroll, max(0, len(rows) - OUTPUT_ROWS))
        end = max(0, len(rows) - scroll)
        visible = rows[max(0, end - OUTPUT_ROWS):end]
        for index, (line, role) in enumerate(visible):
            y = 19 + 15 * index
            color = ACCENT if role == "section" else HIGHLIGHT if role == "title" else MUTED if role == "detail" else TEXT
            if role == "title":
                draw.rectangle((0, y + 1, 2, y + 11), fill=HIGHLIGHT)
            draw.text((5, y), line, font=self.small, fill=color)
        self._footer(draw, hint)
        return image

    def max_scroll(self, buffer: TerminalBuffer) -> int:
        _, draw = self._canvas()
        return max(0, len(self._output_rows(draw, buffer)) - OUTPUT_ROWS)

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
