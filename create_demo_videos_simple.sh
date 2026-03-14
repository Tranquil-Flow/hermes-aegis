#!/bin/bash
# Create three versions of the hermes-aegis demo video with different soundtracks
# Simplified version using transformers + MusicGen (no spacy dependency hell)

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Aegis Demo Video Generator - Three Soundtracks         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo

# Check requirements
echo -e "${YELLOW}[1/7] Checking requirements...${NC}"
if ! command -v ffmpeg &> /dev/null; then
    echo -e "${RED}Error: ffmpeg not found. Install with: brew install ffmpeg${NC}"
    exit 1
fi
echo -e "${GREEN}✓ ffmpeg found${NC}"

# Find video
echo
echo -e "${YELLOW}[2/7] Locating video file...${NC}"
VIDEO_FILE=""
if [ -f "HERMES_AEGIS_FINAL_V6.mp4" ]; then
    VIDEO_FILE="HERMES_AEGIS_FINAL_V6.mp4"
elif [ -f "hermes-aegis-demo/HERMES_AEGIS_FINAL_V6.mp4" ]; then
    VIDEO_FILE="hermes-aegis-demo/HERMES_AEGIS_FINAL_V6.mp4"
elif [ -f "../HERMES_AEGIS_FINAL_V6.mp4" ]; then
    VIDEO_FILE="../HERMES_AEGIS_FINAL_V6.mp4"
else
    echo -e "${RED}Error: Could not find HERMES_AEGIS_FINAL_V6.mp4${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Found: $VIDEO_FILE${NC}"
VIDEO_DURATION=$(ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 "$VIDEO_FILE" 2>/dev/null)
echo -e "  Duration: ${VIDEO_DURATION}s (${BLUE}~2.5 minutes${NC})"

# Setup
echo
echo -e "${YELLOW}[3/7] Setting up environment...${NC}"
MUSIC_DIR="$SCRIPT_DIR/soundtracks"
mkdir -p "$MUSIC_DIR"

# Create/activate venv
if [ ! -d "$MUSIC_DIR/venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "$MUSIC_DIR/venv"
fi

source "$MUSIC_DIR/venv/bin/activate"

# Install clean dependencies (skip spacy entirely)
echo "Installing dependencies (this may take a few minutes)..."
pip install --quiet --upgrade pip wheel setuptools

# Install torch first
if ! python3 -c "import torch" 2>/dev/null; then
    echo "Installing PyTorch..."
    pip install --quiet torch torchvision torchaudio
fi

# Install audiocraft dependencies (without spacy)
echo "Installing audio generation dependencies..."
pip install --quiet av einops julius num2words sentencepiece xformers hydra-core hydra-colorlog omegaconf scipy 2>&1 | grep -v "already satisfied" || true

# Try to install audiocraft without deps, then install what we need
echo "Installing audiocraft..."
pip install --quiet --no-deps git+https://github.com/facebookresearch/audiocraft.git 2>&1 | grep -v "already satisfied" || true

echo -e "${GREEN}✓ Environment ready${NC}"

# Generate tracks
echo
echo -e "${YELLOW}[4/7] Generating three music tracks...${NC}"
echo -e "${BLUE}This will take 10-20 minutes total (faster on Apple Silicon M1/M2/M3)${NC}"
echo

# Use the fixed generation script if it exists, otherwise create it
if [ ! -f "$MUSIC_DIR/generate_fixed.py" ]; then
    cat > "$MUSIC_DIR/generate.py" << 'PYEOF'
#!/usr/bin/env python3
import sys
import os
import torch
import torchaudio
from transformers import AutoProcessor, MusicgenForConditionalGeneration

# Detect device
if torch.backends.mps.is_available():
    device = "mps"
    print("✓ Using Apple Silicon GPU (MPS)")
elif torch.cuda.is_available():
    device = "cuda"
    print("✓ Using NVIDIA GPU")
else:
    device = "cpu"
    print("⚠ Using CPU (will be slower)")

# Load model
print("\nLoading MusicGen model...")
print("(First run will download ~3GB of model weights)")
processor = AutoProcessor.from_pretrained("facebook/musicgen-small")
model = MusicgenForConditionalGeneration.from_pretrained("facebook/musicgen-small")
model = model.to(device)

# Get duration
duration = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
max_new_tokens = int(duration * 50)  # 50 tokens per second

# Track specifications
tracks = [
    {
        "name": "aegis_watch_soft",
        "title": "Aegis Watch (Soft)",
        "prompt": (
            "ambient cyberpunk electronic music, atmospheric pad textures, "
            "minimal pulsing synth, quiet tension, digital monitoring mood, "
            "sparse beats, protective atmosphere, watching and waiting"
        )
    },
    {
        "name": "system_breach_intense",
        "title": "System Breach (Intense)",
        "prompt": (
            "industrial electronic music, aggressive techno beat, "
            "harsh distorted synths, rapid percussion, cyber attack alert, "
            "defensive response, urgent tension, driving bass"
        )
    },
    {
        "name": "ghost_in_the_grid_freeform",
        "title": "Ghost in the Grid (Freeform)",
        "prompt": (
            "dark synthwave music, 80s retrofuture electronic, "
            "pulsing bassline, neon cyberpunk aesthetic, "
            "nostalgic digital atmosphere, blade runner style, mysterious"
        )
    }
]

output_dir = os.path.dirname(os.path.abspath(__file__))

# Generate each track
for i, track in enumerate(tracks, 1):
    print(f"\n{'='*60}")
    print(f"[{i}/3] Generating: {track['title']}")
    print(f"{'='*60}")
    print(f"Prompt: {track['prompt'][:70]}...")
    print(f"Duration: {duration}s")
    print()
    
    # Prepare input
    inputs = processor(
        text=[track['prompt']],
        padding=True,
        return_tensors="pt",
    )
    inputs = inputs.to(device)
    
    # Generate
    print("Generating audio...")
    with torch.no_grad():
        audio_values = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=True,
            guidance_scale=3.0
        )
    
    # Save
    audio_values = audio_values.cpu().squeeze()
    output_path = os.path.join(output_dir, f"{track['name']}.wav")
    
    torchaudio.save(
        output_path,
        audio_values.unsqueeze(0),
        sample_rate=model.config.audio_encoder.sampling_rate
    )
    
    print(f"✓ Saved: {track['name']}.wav")
    
    # Show file size
    size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"  Size: {size_mb:.1f} MB")

print(f"\n{'='*60}")
print("✓ All three tracks generated successfully!")
print(f"{'='*60}")
PYEOF

    chmod +x "$MUSIC_DIR/generate.py"
else
    echo "Using existing generate_fixed.py"
    cp "$MUSIC_DIR/generate_fixed.py" "$MUSIC_DIR/generate.py"
    chmod +x "$MUSIC_DIR/generate.py"
fi

# Run generation
python3 "$MUSIC_DIR/generate.py" "$VIDEO_DURATION"

# Verify tracks were created
for track in "aegis_watch_soft" "system_breach_intense" "ghost_in_the_grid_freeform"; do
    if [ ! -f "$MUSIC_DIR/${track}.wav" ]; then
        echo -e "${RED}Error: Track ${track}.wav was not generated${NC}"
        exit 1
    fi
done

echo
echo -e "${GREEN}✓ All tracks generated successfully${NC}"
echo

# Create video versions
echo -e "${YELLOW}[5/7] Overlaying soundtracks on video...${NC}"
OUTPUT_DIR="$SCRIPT_DIR/demo_versions"
mkdir -p "$OUTPUT_DIR"

# Video version 1: Soft
echo "  [1/3] Creating version with Aegis Watch (Soft)..."
ffmpeg -y -i "$VIDEO_FILE" -i "$MUSIC_DIR/aegis_watch_soft.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    -metadata title="Hermes Aegis Demo - Soft" \
    -metadata comment="Aegis Watch (Soft ambient cyberpunk)" \
    "$OUTPUT_DIR/hermes_aegis_demo_SOFT.mp4" \
    -loglevel error -stats 2>&1 | grep -v "^$"

# Video version 2: Intense
echo "  [2/3] Creating version with System Breach (Intense)..."
ffmpeg -y -i "$VIDEO_FILE" -i "$MUSIC_DIR/system_breach_intense.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    -metadata title="Hermes Aegis Demo - Intense" \
    -metadata comment="System Breach (Industrial electronic)" \
    "$OUTPUT_DIR/hermes_aegis_demo_INTENSE.mp4" \
    -loglevel error -stats 2>&1 | grep -v "^$"

# Video version 3: Freeform
echo "  [3/3] Creating version with Ghost in the Grid (Freeform)..."
ffmpeg -y -i "$VIDEO_FILE" -i "$MUSIC_DIR/ghost_in_the_grid_freeform.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    -metadata title="Hermes Aegis Demo - Freeform" \
    -metadata comment="Ghost in the Grid (Dark synthwave)" \
    "$OUTPUT_DIR/hermes_aegis_demo_FREEFORM.mp4" \
    -loglevel error -stats 2>&1 | grep -v "^$"

echo -e "${GREEN}✓ All three video versions created${NC}"
echo

# Create comparison HTML
echo -e "${YELLOW}[6/7] Creating comparison viewer...${NC}"

cat > "$OUTPUT_DIR/compare.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Hermes Aegis Demo - Soundtrack Comparison</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'SF Mono', 'Monaco', 'Courier New', monospace;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #00ff88;
            padding: 40px 20px;
            min-height: 100vh;
        }
        h1 {
            text-align: center;
            font-size: 28px;
            color: #00ff88;
            text-shadow: 0 0 20px rgba(0,255,136,0.8);
            margin-bottom: 30px;
            letter-spacing: 2px;
        }
        .container { max-width: 1600px; margin: 0 auto; }
        
        .instructions {
            background: rgba(26,31,58,0.8);
            border: 2px solid #00ff88;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 0 30px rgba(0,255,136,0.2);
        }
        .instructions h2 {
            color: #00d4ff;
            margin-bottom: 15px;
            font-size: 20px;
        }
        .instructions p {
            color: #88ffaa;
            line-height: 1.6;
            margin-bottom: 8px;
        }
        
        .video-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 30px;
            margin: 30px 0;
        }
        
        .video-card {
            background: rgba(26,31,58,0.9);
            border: 3px solid #00ff88;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 0 40px rgba(0,255,136,0.3);
            transition: all 0.3s ease;
        }
        .video-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 50px rgba(0,255,136,0.5);
            border-color: #00d4ff;
        }
        
        .video-card h2 {
            margin: 0 0 10px 0;
            color: #00d4ff;
            text-align: center;
            font-size: 24px;
            text-shadow: 0 0 10px rgba(0,212,255,0.8);
        }
        
        .video-card .description {
            color: #88ffaa;
            font-size: 14px;
            margin: 10px 0 20px 0;
            text-align: center;
            line-height: 1.5;
        }
        
        video {
            width: 100%;
            border-radius: 8px;
            border: 2px solid #00ff88;
            background: #000;
        }
        
        .controls {
            margin-top: 20px;
            text-align: center;
        }
        
        button {
            background: linear-gradient(135deg, #00ff88 0%, #00d4ff 100%);
            color: #0a0e27;
            border: none;
            padding: 12px 24px;
            margin: 5px;
            border-radius: 6px;
            cursor: pointer;
            font-family: 'SF Mono', 'Monaco', 'Courier New', monospace;
            font-weight: bold;
            font-size: 14px;
            transition: all 0.2s ease;
            box-shadow: 0 4px 15px rgba(0,255,136,0.3);
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(0,255,136,0.5);
        }
        button:active {
            transform: translateY(0);
        }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            color: #00ff88;
            opacity: 0.7;
            font-size: 12px;
        }
        
        .emoji { font-size: 20px; }
        
        @media (max-width: 1024px) {
            .video-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>╔═══════════════════════════════════╗<br>
            ║  AEGIS SOUNDTRACK COMPARISON  ║<br>
            ╚═══════════════════════════════════╝</h1>
        
        <div class="instructions">
            <h2>🎯 Instructions</h2>
            <p>• Click any video to watch with its soundtrack</p>
            <p>• Compare the three versions and pick your favorite</p>
            <p>• All videos are identical except for the music</p>
            <p>• Use "Pause All" to stop everything and switch between versions</p>
        </div>

        <div class="video-grid">
            <div class="video-card">
                <h2><span class="emoji">🌙</span> SOFT VERSION</h2>
                <div class="description">
                    <strong>Aegis Watch</strong><br>
                    Ambient cyberpunk · Atmospheric pads<br>
                    Minimal tension · Quiet monitoring
                </div>
                <video id="video1" controls preload="metadata">
                    <source src="hermes_aegis_demo_SOFT.mp4" type="video/mp4">
                </video>
                <div class="controls">
                    <button onclick="playVideo('video1')">▶ Play Soft</button>
                    <button onclick="pauseAll()">⏸ Pause All</button>
                </div>
            </div>

            <div class="video-card">
                <h2><span class="emoji">⚡</span> INTENSE VERSION</h2>
                <div class="description">
                    <strong>System Breach</strong><br>
                    Industrial electronic · Aggressive synths<br>
                    Driving beats · Urgent defense
                </div>
                <video id="video2" controls preload="metadata">
                    <source src="hermes_aegis_demo_INTENSE.mp4" type="video/mp4">
                </video>
                <div class="controls">
                    <button onclick="playVideo('video2')">▶ Play Intense</button>
                    <button onclick="pauseAll()">⏸ Pause All</button>
                </div>
            </div>

            <div class="video-card">
                <h2><span class="emoji">🌌</span> FREEFORM VERSION</h2>
                <div class="description">
                    <strong>Ghost in the Grid</strong><br>
                    Dark synthwave · Retrofuture 80s<br>
                    Neon cyberpunk · ASCII nostalgia
                </div>
                <video id="video3" controls preload="metadata">
                    <source src="hermes_aegis_demo_FREEFORM.mp4" type="video/mp4">
                </video>
                <div class="controls">
                    <button onclick="playVideo('video3')">▶ Play Freeform</button>
                    <button onclick="pauseAll()">⏸ Pause All</button>
                </div>
            </div>
        </div>

        <div class="instructions" style="margin-top: 40px;">
            <h2>📋 Track Details</h2>
            <p><strong>Soft Version:</strong> Perfect for showcasing the tool's quiet, defensive monitoring capabilities</p>
            <p><strong>Intense Version:</strong> Emphasizes the active threat blocking and attack response</p>
            <p><strong>Freeform Version:</strong> Bridges retro terminal aesthetics with modern cyberpunk themes</p>
        </div>

        <div class="footer">
            Hermes Aegis v0.1.1 · Security Hardening for AI Agents<br>
            Generated with MusicGen by Meta AI
        </div>
    </div>

    <script>
        function playVideo(id) {
            pauseAll();
            const video = document.getElementById(id);
            video.currentTime = 0;
            video.play();
        }

        function pauseAll() {
            ['video1', 'video2', 'video3'].forEach(id => {
                document.getElementById(id).pause();
            });
        }

        // Initialize
        window.addEventListener('load', function() {
            const videos = ['video1', 'video2', 'video3'].map(id => 
                document.getElementById(id)
            );
            
            videos.forEach(v => {
                v.currentTime = 0;
                v.volume = 0.8;
            });
        });
    </script>
</body>
</html>
HTMLEOF

echo -e "${GREEN}✓ Comparison page created${NC}"
echo

# Run generation
cd "$MUSIC_DIR"
python3 generate.py "$VIDEO_DURATION"

# Return to script dir
cd "$SCRIPT_DIR"

# Create videos
echo
echo -e "${YELLOW}[7/7] Final assembly...${NC}"
echo "Creating three complete demo videos..."
echo

# Summary
echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    ✓ COMPLETE                           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${BLUE}Generated Files:${NC}"
echo
echo "Music tracks:"
ls -lh "$MUSIC_DIR"/*.wav | awk '{printf "  %s  %s\n", $5, $9}'
echo
echo "Video versions:"
ls -lh "$OUTPUT_DIR"/*.mp4 | awk '{printf "  %s  %s\n", $5, $9}'
echo
echo -e "${YELLOW}To compare all three:${NC}"
echo -e "${GREEN}  open $OUTPUT_DIR/compare.html${NC}"
echo
echo -e "${YELLOW}Or watch individually:${NC}"
echo "  open \"$OUTPUT_DIR/hermes_aegis_demo_SOFT.mp4\""
echo "  open \"$OUTPUT_DIR/hermes_aegis_demo_INTENSE.mp4\""
echo "  open \"$OUTPUT_DIR/hermes_aegis_demo_FREEFORM.mp4\""
echo
echo -e "${BLUE}Pick your favorite and let me know! 🎵${NC}"
echo
