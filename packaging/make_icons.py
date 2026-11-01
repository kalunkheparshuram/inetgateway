#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate the InetGateway icon (PNG, ICO, and a 64px base64 PNG for the window icon). Pure standard library."""
import base64
import math
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "icons")


def rrect_sdf(x, y, cx, cy, hw, hh, r):
    qx, qy = abs(x - cx) - (hw - r), abs(y - cy) - (hh - r)
    return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - r


def render(size):
    s = size / 256.0
    top, bot = (11, 92, 173), (77, 163, 255)   # accent blue gradient (matches the app theme)
    px = bytearray()
    bars = [(128, 82, 78, 11), (128, 128, 98, 11), (128, 174, 58, 11)]  # cx, cy, half-width, half-height (traffic rows)
    for j in range(size):
        for i in range(size):
            x, y = (i + 0.5) / s, (j + 0.5) / s
            a = max(0.0, min(1.0, 0.5 - rrect_sdf(x, y, 128, 128, 120, 120, 54) * s))
            t = (x + y) / 512.0
            r, g, b = (top[k] + (bot[k] - top[k]) * t for k in range(3))
            for cx, cy, hw, hh in bars:
                c = max(0.0, min(1.0, 0.5 - rrect_sdf(x, y, cx, cy, hw, hh, hh) * s))
                r, g, b = (r + (255 - r) * c, g + (255 - g) * c, b + (255 - b) * c)
            # small "gateway" dot at the left of the top row
            c = max(0.0, min(1.0, 0.5 - (math.hypot(x - 62, y - 82) - 11) * s))
            r, g, b = (r + (255 - r) * c, g + (255 - g) * c, b + (255 - b) * c)
            px += bytes((int(r), int(g), int(b), int(a * 255)))
    return bytes(px)


def png(size):
    raw = render(size)
    rows = b"".join(b"\x00" + raw[y * size * 4:(y + 1) * size * 4] for y in range(size))

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def ico(sizes):
    imgs = [(n, png(n)) for n in sizes]
    head = struct.pack("<HHH", 0, 1, len(imgs))
    off = 6 + 16 * len(imgs)
    entries, blobs = b"", b""
    for n, data in imgs:
        entries += struct.pack("<BBBBHHII", 0 if n >= 256 else n, 0 if n >= 256 else n, 0, 0, 1, 32, len(data), off)
        blobs += data
        off += len(data)
    return head + entries + blobs


SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0b5cad"/><stop offset="1" stop-color="#4da3ff"/></linearGradient></defs>
  <rect x="8" y="8" width="240" height="240" rx="54" fill="url(#g)"/>
  <rect x="50" y="71" width="156" height="22" rx="11" fill="#fff"/>
  <rect x="30" y="117" width="196" height="22" rx="11" fill="#fff"/>
  <rect x="70" y="163" width="116" height="22" rx="11" fill="#fff"/>
  <circle cx="62" cy="82" r="11" fill="#fff"/>
</svg>
"""

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "inetgateway.png"), "wb") as f:
        f.write(png(256))
    with open(os.path.join(OUT, "inetgateway.ico"), "wb") as f:
        f.write(ico([256, 128, 64, 48, 32, 16]))
    with open(os.path.join(OUT, "inetgateway.svg"), "w", encoding="utf-8") as f:
        f.write(SVG)
    b64 = base64.b64encode(png(64)).decode("ascii")
    with open(os.path.join(OUT, "window_icon_64.b64"), "w", encoding="ascii") as f:
        f.write(b64)
    print("wrote icons; 64px base64 length:", len(b64))
