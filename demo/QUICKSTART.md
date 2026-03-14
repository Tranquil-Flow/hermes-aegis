# Quick Start - Render Demo Video

## Prerequisites

- Python 3.10+
- ffmpeg (for video encoding)

## Installation

```bash
cd hermes-aegis

# Install with demo dependencies
uv pip install -e ".[demo]"

# Or manually install deps
uv pip install numpy pillow
```

## Render Options

### Option 1: Test Single Frame (Fastest - 1 second)

**Use this first to verify everything works!**

```bash
uv run python demo/test_single_frame.py
# Output: output/test_frame.png
open output/test_frame.png  # macOS
```

### Option 2: Fast Demo (~5-10 minutes)

Optimized version with reduced effects for quick iteration.

```bash
uv run python demo/render_demo_fast.py
# Output: output/frames_v2/*.png
# ~800-1000 frames
```

### Option 3: Full Demo V2 (~15-20 minutes)

Complete version with all effects at full quality.

```bash
uv run python demo/render_demo_v2.py
# Output: output/frames_v2/*.png
# ~1200 frames
```

### Option 4: Basic Demo V1 (~3-5 minutes)

Text-only version, no effects (fastest full render).

```bash
uv run python demo/render_demo.py
# Output: output/frames/*.png
# ~960 frames
```

## Encode Video

After rendering frames, encode to MP4:

```bash
# Full HD (1920x1080)
ffmpeg -framerate 24 -i output/frames_v2/frame_%04d.png \
  -c:v libx264 -preset medium -crf 18 -pix_fmt yuv420p \
  output/aegis_demo.mp4

# Twitter version (1280x720, 30s max)
ffmpeg -framerate 24 -i output/frames_v2/frame_%04d.png \
  -vf "scale=1280:720" -t 30 \
  -c:v libx264 -preset medium -crf 23 -pix_fmt yuv420p \
  output/aegis_demo_twitter.mp4

# GIF version (smaller, for quick previews)
ffmpeg -framerate 12 -i output/frames_v2/frame_%04d.png \
  -vf "scale=640:360:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" \
  -loop 0 output/aegis_demo.gif
```

## Troubleshooting

### ModuleNotFoundError: numpy/pillow

```bash
# Make sure demo dependencies are installed
cd hermes-aegis
uv pip install -e ".[demo]"
```

### Out of Memory (OOM) / Process Killed

The renderer is memory-intensive. Try:

1. **Reduce resolution** - Edit RESOLUTION in the script
2. **Use V1 renderer** - No effects, much faster
3. **Close other apps** - Free up RAM
4. **Use fast mode** - `render_demo_fast.py`

Example - reduce resolution:
```python
# In render_demo_v2.py, line ~12
RESOLUTION = (1280, 720)  # Instead of (1920, 1080)
```

### Font not found

The renderer tries these fonts in order:
1. `/System/Library/Fonts/Menlo.ttc` (macOS)
2. `/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf` (Linux)
3. Default PIL font (fallback)

No action needed - it will use whatever is available.

### ffmpeg not found

Install ffmpeg:

```bash
# macOS
brew install ffmpeg

# Ubuntu/Debian
sudo apt-get install ffmpeg

# Or skip video encoding and just use PNG frames
```

## Expected Output

### Test Frame
- **File:** output/test_frame.png
- **Size:** ~29KB
- **Resolution:** 1920x1080
- **Shows:** All 4 protection levels with attack scenario

### Full Render
- **Files:** output/frames_v2/frame_0000.png to frame_1199.png
- **Total Frames:** ~1200
- **Duration:** ~50 seconds @ 24fps
- **Total Size:** ~40-60MB (PNG frames)
- **Final Video:** ~5-10MB (MP4)

## Performance Tips

### Faster Rendering
1. Use `render_demo_fast.py` (already optimized)
2. Reduce FPS: `FPS = 12` instead of 24
3. Reduce resolution: `RESOLUTION = (1280, 720)`
4. Disable effects:
   - Comment out matrix rain initialization
   - Reduce particle count: `count=5` instead of 20

### Better Quality
1. Use `render_demo_v2.py` (full effects)
2. Increase resolution: `RESOLUTION = (2560, 1440)`
3. Lower CRF: `-crf 15` (larger file, better quality)
4. Use slower preset: `-preset slow`

## Next Steps

1. ✅ **Test first:** `uv run python demo/test_single_frame.py`
2. ✅ **Verify output:** Check `output/test_frame.png` looks good
3. 🎬 **Render demo:** Choose V1 (fast) or V2 (effects)
4. 🎥 **Encode video:** Use ffmpeg commands above
5. 📤 **Share:** Post to Twitter/Discord/GitHub!

## Questions?

See `demo/README.md` for full documentation and effect details.
