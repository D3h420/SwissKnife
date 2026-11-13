"""Native 320x170 SwissKnife UI, drawn with Pillow."""

from __future__ import annotations

from pathlib import Path

from .controller import ViewState


WIDTH, HEIGHT = 320, 170
BG = (8, 13, 24)
PANEL = (22, 31, 47)
GREEN = (151, 231, 91)
AMBER = (255, 182, 82)
TEXT = (244, 247, 252)
DIM = (157, 171, 193)
BLUE = (91, 146, 245)


class Renderer:
    def __init__(self) -> None:
        from PIL import Image, ImageFont
        candidates = (
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/System/Library/Fonts/Supplemental/Arial.ttf",
        )
        font_path = next((path for path in candidates if Path(path).exists()), None)
        bold_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf").exists() else font_path
        self.small = ImageFont.truetype(font_path, 10) if font_path else ImageFont.load_default()
        self.medium = ImageFont.truetype(bold_path, 14) if bold_path else ImageFont.load_default()
        self.body = ImageFont.truetype(font_path, 14) if font_path else ImageFont.load_default()
        self.menu = ImageFont.truetype(bold_path, 16) if bold_path else ImageFont.load_default()
        self.large = ImageFont.truetype(bold_path, 25) if bold_path else ImageFont.load_default()
        intro_path = Path(__file__).resolve().parents[1] / "swiss_intro.png"
        self.intro = None
        if intro_path.is_file():
            with Image.open(intro_path) as source:
                self.intro = source.convert("RGB")
                resampling = getattr(Image, "Resampling", Image)
                self.intro.thumbnail((WIDTH, 150), resampling.LANCZOS)

    def _clip(self, draw, text: str, font, width: int) -> str:
        if draw.textbbox((0, 0), text, font=font)[2] <= width:
            return text
        while text and draw.textbbox((0, 0), text + "…", font=font)[2] > width:
            text = text[:-1]
        return text + "…"

    def draw(self, state: ViewState, *, bright: bool = False):
        from PIL import Image, ImageDraw
        image = Image.new("RGB", (WIDTH, HEIGHT), BG)
        draw = ImageDraw.Draw(image)
        if state.screen == "splash":
            if self.intro is not None:
                image.paste(self.intro, ((WIDTH - self.intro.width) // 2, (150 - self.intro.height) // 2))
            else:
                draw.text((20, 63), "SWISSKNIFE", font=self.large, fill=GREEN)
            draw.rectangle((0, 150, WIDTH, HEIGHT), fill=BG)
            if state.show_prompt:
                prompt = "PRESS ANY KEY"
                width = draw.textbbox((0, 0), prompt, font=self.medium)[2]
                draw.text(((WIDTH - width) // 2, 152), prompt, font=self.medium, fill=AMBER)
            if state.simulated:
                draw.text((4, 153), "DEMO", font=self.small, fill=AMBER)
            return image
        accent = AMBER if state.accent == "amber" else GREEN
        if bright:
            accent = (170, 255, 193)
        draw.rounded_rectangle((5, 4, 314, 29), radius=8, fill=PANEL)
        draw.text((13, 8), self._clip(draw, state.title, self.medium, 245), font=self.medium, fill=TEXT)
        draw.text((281, 10), "LAB5", font=self.small, fill=BLUE)

        if state.screen == "networks":
            draw.text((10, 35), self._clip(draw, state.summary or "Networks", self.body, 300), font=self.body, fill=DIM)
            first = max(0, state.selected - 1)
            for i, record in enumerate(state.records[first:first + 2]):
                index = first + i
                y = 54 + i * 44
                active = index == state.selected
                draw.rounded_rectangle((5, y, 314, y + 40), radius=9, fill=(34, 49, 72) if active else PANEL, outline=BLUE if active else PANEL, width=2 if active else 1)
                name = str(record.get("ssid") or record.get("ip") or record.get("vendor") or "<hidden>")
                draw.text((12, y + 4), self._clip(draw, name, self.menu, 190), font=self.menu, fill=TEXT)
                channel = record.get("channel") or "?"
                strength = record.get("rssi")
                signal = f"{strength} dBm" if strength is not None else (str(record.get("state") or record.get("source") or ""))
                draw.text((224, y + 7), self._clip(draw, signal, self.body, 83), font=self.body, fill=GREEN)
                detail = f"CH {channel}  {record.get('encryption') or '?'}  {record.get('clients') or 0} clients" if "channel" in record else f"{record.get('vendor') or ''}  {record.get('mac') or ''}"
                draw.text((12, y + 23), self._clip(draw, detail, self.body, 286), font=self.body, fill=DIM)
        elif state.screen == "list":
            first = max(0, state.selected - 3)
            visible = state.rows[first:first + 4]
            for i, row in enumerate(visible):
                idx = first + i
                y = 34 + i * 28
                active = idx == state.selected
                if active:
                    draw.rounded_rectangle((5, y - 2, 314, y + 24), radius=8, fill=(35, 53, 77), outline=BLUE, width=2)
                    draw.rounded_rectangle((9, y + 4, 13, y + 18), radius=2, fill=GREEN)
                else:
                    draw.rounded_rectangle((5, y - 2, 314, y + 24), radius=5, fill=PANEL)
                draw.text((22, y + 1), self._clip(draw, row, self.menu, 270), font=self.menu, fill=TEXT if active else DIM)
            if len(state.rows) > 4:
                draw.text((273, 132), f"{state.selected + 1}/{len(state.rows)}", font=self.small, fill=DIM)
        elif state.screen == "module_detail":
            draw.rounded_rectangle((7, 36, 312, 96), radius=11, fill=PANEL)
            description = state.description
            words = description.split()
            lines = []
            line = ""
            for word in words:
                candidate = f"{line} {word}".strip()
                if draw.textbbox((0, 0), candidate, font=self.body)[2] > 275 and line:
                    lines.append(line)
                    line = word
                else:
                    line = candidate
            if line:
                lines.append(line)
            for i, line in enumerate(lines[:2]):
                draw.text((17, 46 + i * 20), line, font=self.body, fill=TEXT)
            status = state.status_label or "Ready"
            draw.text((13, 101), self._clip(draw, status, self.small, 285), font=self.small, fill=GREEN if state.status == "needs_device_test" else AMBER)
            draw.rounded_rectangle((7, 118, 312, 142), radius=10, fill=GREEN)
            draw.text((20, 122), "Start", font=self.medium, fill=BG)
            draw.text((283, 122), "→", font=self.medium, fill=BG)
        elif state.screen in {"log", "detail"}:
            lines: list[str] = []
            max_chars = 31
            for item in state.rows:
                words = str(item).split()
                line = ""
                for word in words:
                    if len(line) + len(word) + 1 > max_chars and line:
                        lines.append(line)
                        line = word
                    else:
                        line = (line + " " + word).strip()
                lines.append(line)
            draw.rounded_rectangle((5, 34, 314, 144), radius=9, fill=PANEL)
            for i, line in enumerate(lines[state.scroll:state.scroll + 5]):
                y = 37 + i * 21
                color = AMBER if line.startswith("Error") else TEXT
                draw.text((13, y), self._clip(draw, line, self.body, 294), font=self.body, fill=color)
            if state.screen == "log" and state.status:
                draw.rounded_rectangle((237, 128, 312, 144), radius=4, fill=(38, 50, 63))
                draw.text((242, 130), self._clip(draw, state.status.upper(), self.small, 66), font=self.small, fill=AMBER)
        else:
            for i, row in enumerate(state.rows[:5]):
                draw.text((8, 34 + i * 19), self._clip(draw, row, self.medium, 300), font=self.medium, fill=TEXT)

        draw.rounded_rectangle((5, 147, 314, 168), radius=7, fill=PANEL)
        if state.awaiting_input:
            value = "*" * len(state.input_value) if state.secret_input else state.input_value
            if "press enter" in state.prompt_text.lower() and not value:
                prompt = "ENTER  continue / stop"
            else:
                prompt = ("PASS> " if state.secret_input else "INPUT> ") + value + "_"
            draw.text((13, 152), self._clip(draw, prompt, self.small, 290), font=self.small, fill=TEXT)
        else:
            hint = self._clip(draw, state.hint, self.small, 290)
            draw.text((13, 152), hint, font=self.small, fill=DIM)
        if state.simulated:
            draw.rectangle((251, 148, 315, 167), fill=(75, 49, 17), outline=AMBER)
            draw.text((257, 152), "DEMO", font=self.small, fill=AMBER)
        return image
