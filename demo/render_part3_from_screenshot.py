#!/usr/bin/env python3
"""
Part 3: Composite the shield screenshot with overlaid text.
- Scales shield to ~50% of canvas (540px max dimension)
- Adds a bold border frame around the shield
- Overlays GitHub URL inside the shield
- Overlays credit line at the very bottom
- Fades in (2s) -> hold (8s) -> fade out (2s) = 12s total
"""

import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from PIL import Image, ImageDraw
import numpy as np
from font_helper import get_mono_font

WIDTH, HEIGHT = 1080, 1080
FPS = 24
BG_COLOR    = (30, 30, 30)
LIGHT_BLUE  = (140, 200, 255)
OUTPUT_DIR  = Path(__file__).parent / "output" / "frames_outro"

GITHUB_LINE1 = "github.com/"
GITHUB_LINE2 = "Tranquil-Flow/hermes-aegis"
CREDIT_TEXT = "ASCII animations by Joacim Wejdin (asciiart.eu) and Hermes-Agent"

SOURCE_IMG  = Path(__file__).parent / "shield_source.png"

# Target: shield occupies at most 75% of canvas in each dimension
SHIELD_MAX_PX = int(WIDTH * 0.75)   # 810


def build_base_frame():
    """Load source, flatten BG, scale to 50%, center on 1080x1080 canvas.

    Returns (canvas_rgb, shield_rect) where shield_rect = (x0, y0, x1, y1)
    on the canvas.
    """
    src = Image.open(SOURCE_IMG).convert("RGBA")
    arr = np.array(src)

    # Normalise near-background pixels to exact BG_COLOR
    bg   = np.array([30, 30, 30], dtype=np.float32)
    rgb  = arr[:, :, :3].astype(np.float32)
    dist = np.abs(rgb - bg).max(axis=2)
    mask = dist < 12
    arr[mask, :3] = BG_COLOR
    arr[mask, 3]  = 255

    src_flat = Image.fromarray(arr, "RGBA")

    # Trim a few artifact pixels from the top edge
    src_flat = src_flat.crop((0, 8, src_flat.width, src_flat.height))

    # Scale so the largest dimension == SHIELD_MAX_PX
    w, h   = src_flat.size
    scale  = SHIELD_MAX_PX / max(w, h)
    new_w  = int(w * scale)
    new_h  = int(h * scale)
    src_scaled = src_flat.resize((new_w, new_h), Image.LANCZOS)

    # Center on canvas
    canvas  = Image.new("RGBA", (WIDTH, HEIGHT), (*BG_COLOR, 255))
    paste_x = (WIDTH  - new_w) // 2
    paste_y = (HEIGHT - new_h) // 2
    canvas.paste(src_scaled, (paste_x, paste_y), src_scaled)

    shield_rect = (paste_x, paste_y, paste_x + new_w, paste_y + new_h)
    return canvas.convert("RGB"), shield_rect


def render_frame(base: Image.Image, shield_rect, alpha: float) -> Image.Image:
    """Composite base + border + text overlays at given alpha (0-1)."""
    font_url    = get_mono_font(24)
    font_credit = get_mono_font(17)

    # Blend base toward BG at current alpha
    bg_img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
    frame  = Image.blend(bg_img, base, alpha)
    draw   = ImageDraw.Draw(frame)

    def fade(color):
        r, g, b = color
        return (
            int(BG_COLOR[0] + (r - BG_COLOR[0]) * alpha),
            int(BG_COLOR[1] + (g - BG_COLOR[1]) * alpha),
            int(BG_COLOR[2] + (b - BG_COLOR[2]) * alpha),
        )

    # GitHub URL (two lines) — centered, inside the shield (~60% down)
    x0, y0, x1, y1 = shield_rect
    shield_center_x = (x0 + x1) // 2
    shield_h        = y1 - y0
    line_h          = font_url.size + 6  # leading between the two lines
    url_y           = y0 + int(shield_h * 0.60) - line_h // 2

    for line in (GITHUB_LINE1, GITHUB_LINE2):
        try:
            lw = font_url.getlength(line)
        except AttributeError:
            lw = len(line) * 14
        draw.text((int(shield_center_x - lw // 2), url_y), line,
                  fill=fade(LIGHT_BLUE), font=font_url)
        url_y += line_h

    # Credit line — centered, very bottom of canvas
    try:
        credit_w = font_credit.getlength(CREDIT_TEXT)
    except AttributeError:
        credit_w = len(CREDIT_TEXT) * 7
    credit_x = int((WIDTH - credit_w) // 2)
    credit_y = HEIGHT - 28
    draw.text((credit_x, credit_y), CREDIT_TEXT, fill=fade(LIGHT_BLUE), font=font_credit)

    return frame


def main():
    print("=" * 52)
    print("PART 3  --  Shield screenshot compositor")
    print("=" * 52)

    print("Loading and processing source image...")
    base, shield_rect = build_base_frame()
    x0, y0, x1, y1 = shield_rect
    print(f"  Shield rect on canvas: ({x0},{y0}) -> ({x1},{y1})  "
          f"size={x1-x0}x{y1-y0}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    frames = []

    print("Rendering fade in  (4s)...")
    for i in range(96):
        frames.append(render_frame(base, shield_rect, i / 96.0))

    print("Rendering hold     (8s)...")
    hold_frame = render_frame(base, shield_rect, 1.0)
    for _ in range(192):
        frames.append(hold_frame)

    print("Rendering fade out (2s)...")
    for i in range(48):
        frames.append(render_frame(base, shield_rect, 1.0 - i / 48.0))

    total = len(frames)
    print(f"\nSaving {total} frames -> {OUTPUT_DIR}")
    t0 = time.time()
    for i, img in enumerate(frames):
        if i % 60 == 0:
            print(f"  [{i/total*100:5.1f}%] frame {i}/{total}")
        img.save(OUTPUT_DIR / f"frame_{i:04d}.png")

    elapsed = time.time() - t0
    print(f"\n  Done: {total} frames ({total/FPS:.0f}s)  in {elapsed:.0f}s")
    out = Path(__file__).parent / "output" / "part3_V5.mp4"
    print(f"\nEncode:")
    print(f"  ffmpeg -framerate {FPS} -i {OUTPUT_DIR}/frame_%04d.png "
          f"-c:v libx264 -crf 18 -pix_fmt yuv420p {out}")


if __name__ == "__main__":
    main()
