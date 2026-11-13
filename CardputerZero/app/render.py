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
MAGENTA = (232, 91, 194)
REPOSITORY_URL = "https://github.com/D3h420/SwissKnife"


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
        self.qr = None
        if intro_path.is_file():
            with Image.open(intro_path) as source:
                self.intro = source.convert("RGB")
                resampling = getattr(Image, "Resampling", Image)
                self.intro.thumbnail((WIDTH, 150), resampling.LANCZOS)

    @staticmethod
    def _battery_percent() -> int | None:
        for path in Path("/sys/class/power_supply").glob("*/capacity"):
            try:
                value = int(path.read_text().strip())
                if 0 <= value <= 100:
                    return value
            except (OSError, ValueError):
                continue
        return None

    def _button(self, draw, box, label: str, active: bool, color=GREEN) -> None:
        draw.rounded_rectangle(box, radius=8, fill=color if active else PANEL, outline=color)
        draw.text((box[0] + 9, box[1] + 4), self._clip(draw, label, self.medium, box[2] - box[0] - 15), font=self.medium, fill=BG if active else TEXT)

    def _draw_status(self, draw) -> None:
        battery = self._battery_percent()
        x = 240
        draw.rounded_rectangle((x, 10, x + 27, 23), radius=2, outline=DIM, width=1)
        draw.rectangle((x + 28, 14, x + 30, 19), fill=DIM)
        if battery is not None:
            draw.rectangle((x + 3, 13, x + 3 + round(21 * battery / 100), 20), fill=GREEN if battery > 20 else AMBER)
        else:
            draw.text((x + 10, 10), "?", font=self.small, fill=DIM)
        # Draw the skull as shapes so it does not depend on emoji fonts.
        draw.ellipse((287, 8, 307, 25), fill=MAGENTA)
        draw.rectangle((292, 19, 302, 27), fill=MAGENTA)
        draw.ellipse((291, 15, 296, 20), fill=BG)
        draw.ellipse((299, 15, 304, 20), fill=BG)
        draw.polygon([(297, 20), (300, 20), (298, 23)], fill=BG)
        for x in (294, 298, 302):
            draw.line((x, 24, x, 27), fill=BG, width=1)

    def _qr_image(self):
        if self.qr is None:
            import qrcode
            code = qrcode.QRCode(border=4, box_size=3)
            code.add_data(REPOSITORY_URL)
            code.make(fit=True)
            self.qr = code.make_image(fill_color="white", back_color="black").convert("RGB")
        return self.qr

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
        draw.text((13, 8), self._clip(draw, state.title, self.medium, 210), font=self.medium, fill=TEXT)
        self._draw_status(draw)

        if state.screen == "about":
            draw.rounded_rectangle((7, 36, 312, 143), radius=10, fill=PANEL)
            draw.text((17, 43), "SWISSKNIFE", font=self.menu, fill=GREEN)
            draw.text((17, 67), "LAB5 / D3h420", font=self.body, fill=TEXT)
            draw.text((17, 91), f"Version {state.version}", font=self.body, fill=DIM)
            self._button(draw, (157, 111, 305, 139), "GitHub QR", True, BLUE)
        elif state.screen == "about_qr":
            try:
                qr = self._qr_image()
                qr.thumbnail((112, 112))
                image.paste(qr, (13, 34))
            except ImportError:
                draw.text((13, 50), "QR unavailable", font=self.body, fill=AMBER)
            draw.text((135, 47), "SwissKnife", font=self.menu, fill=TEXT)
            draw.text((135, 79), "GitHub repo", font=self.body, fill=DIM)
            draw.text((135, 107), "Scan to open", font=self.body, fill=GREEN)
        elif state.screen == "recon_modes":
            draw.rounded_rectangle((7, 36, 312, 86), radius=10, fill=PANEL)
            draw.text((17, 44), "Wi-Fi discovery", font=self.menu, fill=TEXT)
            draw.text((17, 67), "Choose an operation", font=self.body, fill=DIM)
            self._button(draw, (7, 104, 153, 140), "Scaner", state.selected == 0)
            self._button(draw, (161, 104, 312, 140), "Sniffer", state.selected == 1, BLUE)
        elif state.screen == "recon_scan_setup":
            draw.rounded_rectangle((7, 36, 312, 104), radius=10, fill=PANEL)
            draw.text((17, 43), "Scan duration", font=self.body, fill=DIM)
            draw.text((17, 63), state.status_label, font=self.large, fill=TEXT)
            draw.text((172, 72), "Z -1  C +1", font=self.small, fill=DIM)
            self._button(draw, (7, 111, 312, 143), "Start scan", True)
        elif state.screen in {"sniffer_live", "sniffer_stopped"}:
            live = state.screen == "sniffer_live"
            draw.text((10, 35), state.status_label if state.status_label != "READY" else "STOPPED", font=self.small, fill=GREEN if live and state.status_label == "LIVE" else AMBER)
            metrics = [("AP", len(state.records)), ("PROBES", state.probes), ("PACKETS", state.packets)]
            for i, (label, value) in enumerate(metrics):
                x = 7 + i * 103
                draw.rounded_rectangle((x, 50, x + 98, 104), radius=9, fill=PANEL)
                draw.text((x + 8, 56), label, font=self.small, fill=DIM)
                draw.text((x + 8, 73), str(value), font=self.menu, fill=TEXT)
            actions = ("Stop", "Probes", "Main") if live else ("Probes", "Resume", "Main")
            for i, label in enumerate(actions):
                x = 7 + i * 103
                self._button(draw, (x, 115, x + 98, 142), label, state.selected == i, GREEN if i == 0 else BLUE)
        elif state.screen == "sniffer_probes":
            draw.text((10, 36), f"{state.probes} probes / {len(state.probe_records)} SSIDs", font=self.body, fill=DIM)
            if not state.probe_records:
                draw.text((14, 78), "No probes yet", font=self.body, fill=TEXT)
            first = max(0, state.selected - 2)
            for i, record in enumerate(state.probe_records[first:first + 3]):
                y = 57 + i * 28
                active = first + i == state.selected
                draw.rounded_rectangle((7, y, 312, y + 25), radius=6, fill=(35, 53, 77) if active else PANEL)
                draw.text((15, y + 3), self._clip(draw, str(record.get("ssid") or "<hidden>"), self.body, 244), font=self.body, fill=TEXT)
                draw.text((270, y + 3), str(record.get("count") or 0), font=self.body, fill=GREEN)
        elif state.screen == "networks":
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
            if state.secondary_label:
                draw.rounded_rectangle((7, 118, 201, 142), radius=10, fill=GREEN if state.selected == 0 else PANEL, outline=GREEN)
                draw.text((20, 122), "Start", font=self.medium, fill=BG if state.selected == 0 else TEXT)
                draw.rounded_rectangle((207, 118, 312, 142), radius=10, fill=BLUE if state.selected == 1 else PANEL, outline=BLUE)
                draw.text((216, 123), self._clip(draw, state.secondary_label, self.small, 90), font=self.small, fill=BG if state.selected == 1 else TEXT)
            else:
                draw.rounded_rectangle((7, 118, 312, 142), radius=10, fill=GREEN)
                draw.text((20, 122), "Start", font=self.medium, fill=BG)
                draw.text((283, 122), "→", font=self.medium, fill=BG)
        elif state.screen == "duration_input":
            draw.rounded_rectangle((7, 40, 312, 112), radius=11, fill=PANEL)
            draw.text((17, 48), "Scan duration", font=self.body, fill=DIM)
            draw.text((17, 72), (state.input_value or "_") + " s", font=self.large, fill=TEXT)
            draw.text((17, 119), "1–300 seconds", font=self.body, fill=DIM)
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
