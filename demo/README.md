# Hermes-Aegis Demo Video

This directory contains the demo video renderer for showcasing hermes-aegis protection levels.

## What We Built

**Four Levels of Protection** - A split-screen demo showing 4 different protection configurations responding to the same security threats in real-time.

### Visual Features

#### 1. Split-Screen Layout (2x2 Grid)
- **Level 0 (Top-Left):** Unprotected Hermes - RED border
- **Level 1 (Top-Right):** Docker Backend Only - AMBER border  
- **Level 2 (Bottom-Left):** Aegis + Local - GREEN border
- **Level 3 (Bottom-Right):** Aegis + Docker - GREEN border

#### 2. ASCII Art Icons
- **Skull** - Attack succeeded (❌)
- **Warning** - Partial protection (⚠️)
- **Shield** - Attack blocked (✓)
- **Lock** - Security features enabled

#### 3. Animated Effects
- **Matrix Rain** - Falling characters on protected terminals (Levels 2 & 3)
- **Particle Bursts** - Explosion effect on attack/block events
  - Red particles: Attack succeeded
  - Amber particles: Partial protection
  - Green particles: Attack blocked
- **Pulse Effect** - Border pulse when blocking attacks
- **Color-coded feedback** - Red/Amber/Green for instant visual status

#### 4. Attack Scenarios (5 total)
1. **Secret Exfiltration** - AWS credentials via HTTP
2. **Destructive Commands** - `rm -rf /`
3. **SSH Key Theft** - Reading `~/.ssh/id_rsa`
4. **Privilege Escalation** - `sudo` attempts
5. **Data Tunneling** - Burst upload detection

## Files

- `attack_prompts.py` - Attack scenario definitions
- `render_demo.py` - V1 renderer (basic, text-only)
- `render_demo_v2.py` - V2 renderer (enhanced with effects)
- `test_single_frame.py` - Test script for single frame preview
- `attack-scenarios.md` - Detailed attack documentation

## Usage

### Render Test Frame
```bash
cd hermes-aegis
uv run python demo/test_single_frame.py
# Output: output/test_frame.png
```

### Render Full Demo (V1 - Fast)
```bash
uv run python demo/render_demo.py
# Output: output/frames/ (960 frames @ 24fps = 40 seconds)
```

### Render Full Demo (V2 - Enhanced)
```bash
uv run python demo/render_demo_v2.py
# Output: output/frames_v2/ (~1200 frames @ 24fps = 50 seconds)
# Note: Takes longer due to particle effects and matrix rain
```

### Encode Video (requires ffmpeg)
```bash
# From V1 frames
ffmpeg -framerate 24 -i output/frames/frame_%04d.png \
  -c:v libx264 -preset medium -crf 18 -pix_fmt yuv420p \
  output/aegis_demo_v1.mp4

# From V2 frames
ffmpeg -framerate 24 -i output/frames_v2/frame_%04d.png \
  -c:v libx264 -preset medium -crf 18 -pix_fmt yuv420p \
  output/aegis_demo_v2.mp4
```

## Configuration

Edit these constants in the renderer files:

- `RESOLUTION` - Default: (1920, 1080)
- `FPS` - Default: 24
- `FONT_SIZE` - Default: 14
- `COLORS` - RGB color palette

## Dependencies

- Python 3.11+
- numpy
- Pillow (PIL)
- ffmpeg (for video encoding)

Install with:
```bash
uv pip install numpy pillow
```

## Next Steps / Ideas

### Visual Enhancements
- [ ] Add HTTP packet flow visualization (ASCII packets moving)
- [ ] More dramatic ASCII art (larger, animated)
- [ ] Glitch effects on breaches
- [ ] Progress bars for data tunneling
- [ ] Audit trail hash-chain visualization
- [ ] Real terminal font with better Unicode support

### Technical Improvements
- [ ] Optimize rendering loop (currently slow with effects)
- [ ] Add frame caching for repeated elements
- [ ] GPU acceleration for effects
- [ ] Real-time preview mode
- [ ] Interactive demo (clickable scenarios)

### Content
- [ ] Add narration/voice-over
- [ ] Sound effects (alert tones, blocks, beeps)
- [ ] More attack scenarios
- [ ] Statistics overlay (blocked/allowed counters)
- [ ] Timing comparison (Aegis overhead)

### Distribution
- [ ] Optimized version for Twitter (1280x720, 30s max)
- [ ] GIF version for quick previews
- [ ] YouTube version with chapters
- [ ] Still frames for documentation

## Demo Video Structure

**Total Duration:** ~50 seconds

1. **Intro (5s)** - Show all 4 levels initializing
2. **Attack 1 (8s)** - Secret exfiltration
3. **Attack 2 (8s)** - Destructive command
4. **Attack 3 (8s)** - SSH key theft
5. **Attack 4 (8s)** - Privilege escalation
6. **Attack 5 (8s)** - Data tunneling
7. **Outro (7s)** - Summary scores + call-to-action

## Color Palette

```python
RED     = (255, 0, 0)    # Unprotected / Attack succeeded
AMBER   = (255, 165, 0)  # Partial protection
GREEN   = (0, 255, 0)    # Protected / Attack blocked
CYAN    = (0, 255, 255)  # System messages / Titles
WHITE   = (255, 255, 255) # Normal text
BLACK   = (0, 0, 0)      # Background
```

## ASCII Art Examples

### Skull (Attack Succeeded)
```
   ___   
 ,'   `. 
/  o o  \
|   ^   |
 \  v  / 
  `---'  
```

### Shield (Attack Blocked)
```
   ___   
  /   \  
 | ✓✓✓ | 
 |  ✓  | 
  \ ^ /  
   `-'   
```

### Lock (Security Enabled)
```
  .---.  
 /     \ 
|   O   |
|-------|
| ===== |
`-------'
```

## License

Part of hermes-aegis project - MIT License
