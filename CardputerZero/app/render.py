"""Native 320x170 SwissKnife UI, drawn with Pillow."""

from __future__ import annotations

from pathlib import Path

from .controller import ViewState


WIDTH, HEIGHT = 320, 170
BG = (5, 12, 27)
PANEL = (12, 28, 51)
GREEN = (182, 247, 75)
AMBER = (255, 166, 48)
TEXT = (245, 250, 255)
DIM = (159, 181, 205)


class Renderer:
    def __init__(self) -> None:
        from PIL import Image, ImageFont
        candidates = (
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
            "/System/Library/Fonts/Menlo.ttc",
        )
        font_path = next((path for path in candidates if Path(path).exists()), None)
        self.small = ImageFont.truetype(font_path, 10) if font_path else ImageFont.load_default()
        self.medium = ImageFont.truetype(font_path, 14) if font_path else ImageFont.load_default()
        self.body = ImageFont.truetype(font_path, 14) if font_path else ImageFont.load_default()
        self.menu = ImageFont.truetype(font_path, 16) if font_path else ImageFont.load_default()
        self.large = ImageFont.truetype(font_path, 25) if font_path else ImageFont.load_default()
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
        draw.rectangle((0, 0, WIDTH - 1, 28), fill=PANEL)
        draw.rectangle((0, 28, WIDTH - 1, 29), fill=accent)
        draw.text((9, 5), self._clip(draw, state.title.upper(), self.medium, 250), font=self.medium, fill=TEXT)
        draw.text((278, 7), "LAB5", font=self.small, fill=GREEN)

        if state.screen == "list":
            first = max(0, state.selected - 3)
            visible = state.rows[first:first + 4]
            for i, row in enumerate(visible):
                idx = first + i
                y = 34 + i * 28
                active = idx == state.selected
                if active:
                    draw.rounded_rectangle((5, y - 2, 314, y + 24), radius=6, fill=(26, 48, 73), outline=GREEN, width=2)
                    draw.rounded_rectangle((8, y + 1, 13, y + 20), radius=2, fill=GREEN)
                else:
                    draw.rounded_rectangle((5, y - 2, 314, y + 24), radius=5, fill=PANEL)
                draw.text((22, y + 1), self._clip(draw, row, self.menu, 270), font=self.menu, fill=TEXT if active else DIM)
            if len(state.rows) > 4:
                draw.text((273, 132), f"{state.selected + 1}/{len(state.rows)}", font=self.small, fill=AMBER)
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
            for i, line in enumerate(lines[state.scroll:state.scroll + 5]):
                y = 37 + i * 21
                color = AMBER if line.startswith("Error") else (GREEN if line.lstrip().startswith(("[1]", "[2]", "[0]", "Status:")) else TEXT)
                draw.text((9, y), self._clip(draw, line, self.body, 302), font=self.body, fill=color)
            if state.screen == "log" and state.status:
                draw.rounded_rectangle((237, 128, 312, 144), radius=4, fill=(38, 50, 63))
                draw.text((242, 130), self._clip(draw, state.status.upper(), self.small, 66), font=self.small, fill=AMBER)
        else:
            for i, row in enumerate(state.rows[:5]):
                draw.text((8, 34 + i * 19), self._clip(draw, row, self.medium, 300), font=self.medium, fill=TEXT)

        draw.rectangle((0, 146, WIDTH - 1, HEIGHT - 1), fill=PANEL)
        draw.line((0, 146, WIDTH - 1, 146), fill=(56, 83, 105))
        if state.awaiting_input:
            value = "*" * len(state.input_value) if state.secret_input else state.input_value
            prompt = ("PASS> " if state.secret_input else "INPUT> ") + value + "_"
            draw.text((8, 152), self._clip(draw, prompt, self.small, 300), font=self.small, fill=AMBER)
        else:
            hint = self._clip(draw, state.hint, self.small, 290)
            draw.text((8, 152), hint, font=self.small, fill=DIM)
        if state.simulated:
            draw.rectangle((251, 148, 315, 167), fill=(75, 49, 17), outline=AMBER)
            draw.text((257, 152), "DEMO", font=self.small, fill=AMBER)
        return image
