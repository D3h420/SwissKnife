"""Linux framebuffer output for the Cardputer Zero ST7789V display."""

from __future__ import annotations

import fcntl
import mmap
import os
import struct


FBIOGET_VSCREENINFO = 0x4600
FBIOGET_FSCREENINFO = 0x4602


class Framebuffer:
    @staticmethod
    def detect_path() -> str:
        try:
            with open("/proc/fb", encoding="ascii") as handle:
                for line in handle:
                    index, _, name = line.strip().partition(" ")
                    if "fb_st7789v" in name and index.isdigit():
                        return f"/dev/fb{index}"
        except OSError:
            pass
        return "/dev/fb0"

    def __init__(self, path: str = "/dev/fb0") -> None:
        self.fd = os.open(path, os.O_RDWR)
        try:
            variable = bytearray(160)
            fixed = bytearray(80)
            fcntl.ioctl(self.fd, FBIOGET_VSCREENINFO, variable)
            fcntl.ioctl(self.fd, FBIOGET_FSCREENINFO, fixed)
            self.width, self.height = struct.unpack_from("II", variable, 0)
            bpp = struct.unpack_from("I", variable, 24)[0]
            memory_length = struct.unpack_from("I", fixed, 24)[0]
            self.stride = struct.unpack_from("I", fixed, 48)[0]
            if (self.width, self.height, bpp) != (320, 170, 16):
                raise RuntimeError(f"Expected 320x170 RGB565 framebuffer, got {self.width}x{self.height}x{bpp}")
            if memory_length < self.stride * self.height:
                raise RuntimeError("Framebuffer memory is smaller than visible screen")
            self.memory = mmap.mmap(self.fd, memory_length, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ)
        except Exception:
            os.close(self.fd)
            raise

    def show(self, image) -> None:
        if image.size != (self.width, self.height):
            raise ValueError("Wrong frame size")
        pixels = image.convert("RGB").tobytes()
        row_bytes = self.width * 2
        frame = bytearray(row_bytes * self.height)
        for pos in range(self.width * self.height):
            offset = pos * 3
            red, green, blue = pixels[offset:offset + 3]
            color = ((red >> 3) << 11) | ((green >> 2) << 5) | (blue >> 3)
            frame[pos * 2] = color & 0xff
            frame[pos * 2 + 1] = color >> 8
        if self.stride == row_bytes:
            self.memory.seek(0)
            self.memory.write(frame)
        else:
            for y in range(self.height):
                self.memory.seek(y * self.stride)
                self.memory.write(frame[y * row_bytes:(y + 1) * row_bytes])

    def close(self) -> None:
        self.memory.close()
        os.close(self.fd)
