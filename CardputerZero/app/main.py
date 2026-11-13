"""APPLaunch entry point and desktop simulator."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path


def _prepare_source_path() -> None:
    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    if "SWISSKNIFE_DATA_DIR" not in os.environ:
        state = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "swissknife"
        os.environ["SWISSKNIFE_DATA_DIR"] = str(state)


def run_device(controller) -> int:
    from .framebuffer import Framebuffer
    from .keyboard import Keyboard
    from .render import Renderer
    display = Framebuffer(os.environ.get("APPLAUNCH_LINUX_FBDEV_DEVICE") or os.environ.get("LV_LINUX_FBDEV_DEVICE") or Framebuffer.detect_path())
    try:
        keyboard = Keyboard()
    except Exception:
        display.close()
        raise
    running = True

    def stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        renderer = Renderer()
        last_draw = 0.0
        while running and not controller.quit_requested:
            editing = controller.screen == "duration_input" or (controller.screen == "running" and controller.awaiting_input and not controller.choices)
            for key, char in keyboard.events(editing=editing):
                controller.handle(key, char)
            changed = controller.tick()
            now = time.monotonic()
            if changed or now - last_draw > 1.0:
                display.show(renderer.draw(controller.view(), bright=controller.theme_bright))
                last_draw = now
            time.sleep(0.04)
    finally:
        if controller.operation and controller.operation.state == "running":
            controller.operation.cancel()
            if controller.operation.thread:
                controller.operation.thread.join(timeout=8)
        keyboard.close()
        display.close()
    return 0


def run_desktop(controller, *, snapshot: Path | None = None) -> int:
    import tkinter as tk
    from PIL import ImageTk
    from .render import Renderer
    renderer = Renderer()
    root = tk.Tk()
    root.title("SwissKnife / Cardputer Zero [SIMULATED]")
    root.resizable(False, False)
    label = tk.Label(root, bg="black")
    label.pack()
    scale = 3
    image_ref = None

    def key_event(event) -> None:
        mapping = {"Up": "UP", "Down": "DOWN", "Left": "LEFT", "Right": "RIGHT", "Return": "ENTER", "Escape": "ESC", "Home": "HOME", "Prior": "PAGEUP", "Next": "PAGEDOWN", "BackSpace": "BACKSPACE"}
        key = mapping.get(event.keysym)
        editing = controller.screen == "duration_input" or (controller.screen == "running" and controller.awaiting_input and not controller.choices)
        if not key and not editing:
            key = {"f": "UP", "x": "DOWN", "z": "LEFT", "c": "RIGHT"}.get(event.char.lower())
        if key:
            controller.handle(key)
        elif event.char and event.char.isprintable():
            controller.handle("TEXT", event.char)

    def draw_loop() -> None:
        nonlocal image_ref
        changed = controller.tick()
        if changed:
            image = renderer.draw(controller.view(), bright=controller.theme_bright)
            if snapshot:
                snapshot.parent.mkdir(parents=True, exist_ok=True)
                image.save(snapshot)
            image_ref = ImageTk.PhotoImage(image.resize((960, 510)))
            label.configure(image=image_ref)
        if controller.quit_requested:
            root.destroy()
        else:
            root.after(50, draw_loop)

    root.bind("<KeyPress>", key_event)
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.after(20, draw_loop)
    root.mainloop()
    if controller.operation and controller.operation.state == "running":
        controller.operation.cancel()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SwissKnife for Cardputer Zero")
    parser.add_argument("--dev", action="store_true", help="desktop simulator with labelled sample data")
    parser.add_argument("--snapshot", type=Path, help="save simulator frame after each update")
    args = parser.parse_args(argv)
    _prepare_source_path()
    from core.engine import SwissKnifeEngine
    from .controller import Controller
    controller = Controller(SwissKnifeEngine(demo=args.dev))
    try:
        return run_desktop(controller, snapshot=args.snapshot) if args.dev else run_device(controller)
    except Exception as exc:
        print(f"SwissKnife Cardputer Zero startup error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
