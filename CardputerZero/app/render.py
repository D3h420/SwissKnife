"""Native 320x170 SwissKnife UI, drawn with Pillow."""

from __future__ import annotations

from pathlib import Path

from .controller import ViewState


WIDTH, HEIGHT = 320, 170
BG = (7, 15, 13)
PANEL = (14, 29, 23)
GREEN = (112, 238, 166)
AMBER = (246, 185, 85)
TEXT = (226, 239, 229)
DIM = (129, 154, 138)


class Renderer:
    def __init__(self) -> None:
        from PIL import ImageFont
        candidates = (
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
            "/System/Library/Fonts/Menlo.ttc",
        )
        font_path = next((path for path in candidates if Path(path).exists()), None)
        self.small = ImageFont.truetype(font_path, 10) if font_path else ImageFont.load_default()
        self.medium = ImageFont.truetype(font_path, 12) if font_path else ImageFont.load_default()
        self.large = ImageFont.truetype(font_path, 25) if font_path else ImageFont.load_default()

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
        accent = AMBER if state.accent == "amber" else GREEN
        if bright:
            accent = (170, 255, 193)
        for y in range(0, HEIGHT, 5):
            draw.line((0, y, WIDTH, y), fill=(10, 21, 17))
        draw.rectangle((0, 0, WIDTH - 1, 25), fill=PANEL)
        draw.rectangle((0, 25, WIDTH - 1, 26), fill=accent)
        draw.text((8, 5), self._clip(draw, state.title.upper(), self.medium, 255), font=self.medium, fill=accent)
        draw.text((278, 5), "LAB5", font=self.small, fill=DIM)

        if state.screen == "splash":
            draw.text((15, 42), "SWISS", font=self.large, fill=GREEN)
            draw.text((15, 71), "KNIFE", font=self.large, fill=AMBER)
            draw.line((15, 104, 210, 104), fill=GREEN, width=2)
            draw.text((16, 112), "LAB5 / D3h420", font=self.medium, fill=TEXT)
            draw.text((16, 130), "ONE ENGINE / THREE INTERFACES", font=self.small, fill=DIM)
        elif state.screen == "list":
            first = max(0, state.selected - 4)
            visible = state.rows[first:first + 5]
            for i, row in enumerate(visible):
                idx = first + i
                y = 34 + i * 22
                active = idx == state.selected
                if active:
                    draw.rounded_rectangle((5, y - 2, 314, y + 19), radius=3, fill=(31, 64, 46), outline=GREEN)
                    draw.text((10, y + 1), ">", font=self.medium, fill=AMBER)
                draw.text((25, y + 1), self._clip(draw, row, self.medium, 282), font=self.medium, fill=TEXT if active else DIM)
            if len(state.rows) > 5:
                draw.text((286, 130), f"{state.selected + 1}/{len(state.rows)}", font=self.small, fill=DIM)
        elif state.screen in {"log", "detail"}:
            lines: list[str] = []
            max_chars = 46 if state.screen == "log" else 42
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
            for i, line in enumerate(lines[state.scroll:state.scroll + 7]):
                y = 34 + i * 15
                color = AMBER if line.startswith("Error") or line.startswith("Status:") else TEXT
                draw.text((8, y), self._clip(draw, line, self.small, 302), font=self.small, fill=color)
            if state.screen == "log" and state.status:
                draw.rectangle((237, 126, 312, 143), fill=(37, 45, 30))
                draw.text((242, 130), self._clip(draw, state.status.upper(), self.small, 66), font=self.small, fill=AMBER)
        else:
            for i, row in enumerate(state.rows[:5]):
                draw.text((8, 34 + i * 19), self._clip(draw, row, self.medium, 300), font=self.medium, fill=TEXT)

        draw.rectangle((0, 146, WIDTH - 1, HEIGHT - 1), fill=PANEL)
        draw.line((0, 146, WIDTH - 1, 146), fill=(45, 84, 59))
        hint = self._clip(draw, state.hint, self.small, 290)
        draw.text((8, 152), hint, font=self.small, fill=DIM)
        if state.simulated:
            draw.rectangle((251, 148, 315, 167), fill=(75, 49, 17), outline=AMBER)
            draw.text((257, 152), "DEMO", font=self.small, fill=AMBER)
        return image
