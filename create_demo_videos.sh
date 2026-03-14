#!/bin/bash
# Create three versions of the hermes-aegis demo video with different soundtracks
# Run this on macOS (not in Docker) for best results

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Aegis Demo Video Generator - Three Soundtracks         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo

# Check for required tools
echo -e "${YELLOW}[1/7] Checking requirements...${NC}"
if ! command -v ffmpeg &> /dev/null; then
    echo -e "${RED}Error: ffmpeg not found. Install with: brew install ffmpeg${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ All requirements met${NC}"
echo

# Find the video file
echo -e "${YELLOW}[2/7] Locating video file...${NC}"
VIDEO_FILE=""
if [ -f "hermes-aegis-demo/HERMES_AEGIS_FINAL_V6.mp4" ]; then
    VIDEO_FILE="hermes-aegis-demo/HERMES_AEGIS_FINAL_V6.mp4"
elif [ -f "HERMES_AEGIS_FINAL_V6.mp4" ]; then
    VIDEO_FILE="HERMES_AEGIS_FINAL_V6.mp4"
elif [ -f "../HERMES_AEGIS_FINAL_V6.mp4" ]; then
    VIDEO_FILE="../HERMES_AEGIS_FINAL_V6.mp4"
else
    echo -e "${RED}Error: Could not find HERMES_AEGIS_FINAL_V6.mp4${NC}"
    echo "Please place the video in one of:"
    echo "  - $SCRIPT_DIR/hermes-aegis-demo/"
    echo "  - $SCRIPT_DIR/"
    echo "  - $(dirname $SCRIPT_DIR)/"
    exit 1
fi

echo -e "${GREEN}✓ Found video: $VIDEO_FILE${NC}"
VIDEO_DURATION=$(ffprobe -v error -show_entries format=duration -of default=noprint_wrappers=1:nokey=1 "$VIDEO_FILE")
echo -e "  Duration: ${VIDEO_DURATION}s"
echo

# Set up music generation environment
echo -e "${YELLOW}[3/7] Setting up HeartMuLa environment...${NC}"
MUSIC_DIR="$SCRIPT_DIR/soundtracks"
mkdir -p "$MUSIC_DIR"

# Check if HeartMuLa is installed, if not set it up
if ! python3 -c "import heartmula" 2>/dev/null; then
    echo -e "${YELLOW}Installing HeartMuLa (this will take a few minutes)...${NC}"
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "$MUSIC_DIR/venv" ]; then
        python3 -m venv "$MUSIC_DIR/venv"
    fi
    
    source "$MUSIC_DIR/venv/bin/activate"
    
    # Install dependencies
    pip install --upgrade pip wheel setuptools
    pip install torch torchvision torchaudio
    pip install git+https://github.com/facebookresearch/audiocraft.git
    
    echo -e "${GREEN}✓ HeartMuLa installed${NC}"
else
    echo -e "${GREEN}✓ HeartMuLa already installed${NC}"
fi
echo

# Generate the three tracks
echo -e "${YELLOW}[4/7] Generating three music tracks...${NC}"
echo "This will take 10-20 minutes total (faster on Apple Silicon)"
echo

# Activate venv if it exists
if [ -d "$MUSIC_DIR/venv" ]; then
    source "$MUSIC_DIR/venv/bin/activate"
fi

# Create Python script for music generation
cat > "$MUSIC_DIR/generate_tracks.py" << 'PYEOF'
#!/usr/bin/env python3
import sys
import torch
from audiocraft.models import MusicGen
from audiocraft.data.audio import audio_write
import os

# Detect device
if torch.backends.mps.is_available():
    device = "mps"
    print("✓ Using Apple Silicon GPU (MPS)")
elif torch.cuda.is_available():
    device = "cuda"
    print("✓ Using NVIDIA GPU")
else:
    device = "cpu"
    print("⚠ Using CPU (this will be slow)")

# Load model
print("Loading MusicGen model...")
model = MusicGen.get_pretrained('facebook/musicgen-medium', device=device)

# Get duration from command line
duration = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
model.set_generation_params(duration=duration)

# Track definitions
tracks = [
    {
        "name": "aegis_watch_soft",
        "title": "Aegis Watch (Soft)",
        "description": (
            "ambient cyberpunk, atmospheric pad textures, minimal electronic pulse, "
            "watching, monitoring, defensive, quiet tension, synth layers, "
            "sparse beats, digital surveillance mood, protective atmosphere"
        )
    },
    {
        "name": "system_breach_intense",
        "title": "System Breach (Intense)",
        "description": (
            "industrial electronic, aggressive synths, driving techno beat, "
            "attack alert, defensive response, harsh digital textures, "
            "distorted bass, rapid percussion, cyber warfare, urgent tension"
        )
    },
    {
        "name": "ghost_in_the_grid_freeform",
        "title": "Ghost in the Grid (Freeform)",
        "description": (
            "dark retrofuture synthwave, 80s digital aesthetics, "
            "pulsing bassline, nostalgic synth lead, neon cyberpunk, "
            "ASCII terminal vibes, blade runner meets hackers, mysterious digital entity"
        )
    }
]

output_dir = os.path.dirname(os.path.abspath(__file__))

# Generate each track
for i, track in enumerate(tracks, 1):
    print(f"\n[{i}/3] Generating: {track['title']}")
    print(f"    Description: {track['description'][:60]}...")
    
    # Generate
    wav = model.generate([track['description']], progress=True)
    
    # Save
    output_path = os.path.join(output_dir, track['name'])
    audio_write(
        output_path,
        wav[0].cpu(),
        model.sample_rate,
        strategy="loudness",
        loudness_compressor=True
    )
    
    print(f"    ✓ Saved: {track['name']}.wav")

print("\n✓ All tracks generated successfully!")
PYEOF

chmod +x "$MUSIC_DIR/generate_tracks.py"

# Run generation
python3 "$MUSIC_DIR/generate_tracks.py" "$VIDEO_DURATION"

echo
echo -e "${GREEN}✓ All tracks generated${NC}"
echo

# Create three video versions
echo -e "${YELLOW}[5/7] Overlaying soundtracks on video...${NC}"

OUTPUT_DIR="$SCRIPT_DIR/demo_versions"
mkdir -p "$OUTPUT_DIR"

# Track 1: Soft
echo "  [1/3] Creating version with Aegis Watch (Soft)..."
ffmpeg -y -i "$VIDEO_FILE" -i "$MUSIC_DIR/aegis_watch_soft.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    -metadata title="Hermes Aegis Demo - Soft" \
    -metadata comment="Aegis Watch soundtrack" \
    "$OUTPUT_DIR/hermes_aegis_demo_SOFT.mp4" \
    -loglevel error -stats

# Track 2: Intense
echo "  [2/3] Creating version with System Breach (Intense)..."
ffmpeg -y -i "$VIDEO_FILE" -i "$MUSIC_DIR/system_breach_intense.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    -metadata title="Hermes Aegis Demo - Intense" \
    -metadata comment="System Breach soundtrack" \
    "$OUTPUT_DIR/hermes_aegis_demo_INTENSE.mp4" \
    -loglevel error -stats

# Track 3: Freeform
echo "  [3/3] Creating version with Ghost in the Grid (Freeform)..."
ffmpeg -y -i "$VIDEO_FILE" -i "$MUSIC_DIR/ghost_in_the_grid_freeform.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    -metadata title="Hermes Aegis Demo - Freeform" \
    -metadata comment="Ghost in the Grid soundtrack" \
    "$OUTPUT_DIR/hermes_aegis_demo_FREEFORM.mp4" \
    -loglevel error -stats

echo -e "${GREEN}✓ All video versions created${NC}"
echo

# Generate comparison HTML
echo -e "${YELLOW}[6/7] Creating comparison viewer...${NC}"

cat > "$OUTPUT_DIR/compare.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>Hermes Aegis Demo - Soundtrack Comparison</title>
    <style>
        body {
            font-family: 'Courier New', monospace;
            background: #0a0e27;
            color: #00ff88;
            padding: 20px;
            margin: 0;
        }
        h1 {
            text-align: center;
            color: #00ff88;
            text-shadow: 0 0 10px #00ff88;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .video-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .video-card {
            background: #1a1f3a;
            border: 2px solid #00ff88;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 0 20px rgba(0,255,136,0.3);
        }
        .video-card h2 {
            margin-top: 0;
            color: #00d4ff;
            text-align: center;
        }
        .video-card .description {
            color: #88ffaa;
            font-size: 14px;
            margin: 10px 0;
            text-align: center;
        }
        video {
            width: 100%;
            border-radius: 4px;
            border: 1px solid #00ff88;
        }
        .controls {
            margin-top: 15px;
            text-align: center;
        }
        button {
            background: #00ff88;
            color: #0a0e27;
            border: none;
            padding: 10px 20px;
            margin: 5px;
            border-radius: 4px;
            cursor: pointer;
            font-family: 'Courier New', monospace;
            font-weight: bold;
        }
        button:hover {
            background: #00d4ff;
        }
        .instructions {
            background: #2a2f4a;
            border: 1px solid #00ff88;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .instructions h3 {
            margin-top: 0;
            color: #00d4ff;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>╔═══════════════════════════════════════════════════════╗<br>
            ║  HERMES AEGIS DEMO - SOUNDTRACK COMPARISON  ║<br>
            ╚═══════════════════════════════════════════════════════╝</h1>
        
        <div class="instructions">
            <h3>Instructions:</h3>
            <p>• Click any video to watch with its soundtrack</p>
            <p>• Compare the three versions and pick your favorite</p>
            <p>• All videos are identical except for the music</p>
            <p>• Use the controls to sync playback if comparing side-by-side</p>
        </div>

        <div class="video-grid">
            <div class="video-card">
                <h2>🎵 SOFT VERSION</h2>
                <div class="description">Aegis Watch - Ambient cyberpunk, atmospheric, minimal tension</div>
                <video id="video1" controls>
                    <source src="hermes_aegis_demo_SOFT.mp4" type="video/mp4">
                </video>
                <div class="controls">
                    <button onclick="playVideo('video1')">▶ Play</button>
                    <button onclick="pauseAll()">⏸ Pause All</button>
                </div>
            </div>

            <div class="video-card">
                <h2>⚡ INTENSE VERSION</h2>
                <div class="description">System Breach - Industrial electronic, aggressive, driving beats</div>
                <video id="video2" controls>
                    <source src="hermes_aegis_demo_INTENSE.mp4" type="video/mp4">
                </video>
                <div class="controls">
                    <button onclick="playVideo('video2')">▶ Play</button>
                    <button onclick="pauseAll()">⏸ Pause All</button>
                </div>
            </div>

            <div class="video-card">
                <h2>🌌 FREEFORM VERSION</h2>
                <div class="description">Ghost in the Grid - Dark synthwave, retrofuture, 80s cyberpunk</div>
                <video id="video3" controls>
                    <source src="hermes_aegis_demo_FREEFORM.mp4" type="video/mp4">
                </video>
                <div class="controls">
                    <button onclick="playVideo('video3')">▶ Play</button>
                    <button onclick="pauseAll()">⏸ Pause All</button>
                </div>
            </div>
        </div>

        <div class="instructions">
            <h3>Soundtrack Details:</h3>
            <p><strong>Track 1 (Soft):</strong> Gentle, atmospheric cyberpunk perfect for the quiet monitoring aesthetic</p>
            <p><strong>Track 2 (Intense):</strong> Aggressive industrial electronic matching the attack/defense theme</p>
            <p><strong>Track 3 (Freeform):</strong> Retrofuture synthwave bridging ASCII nostalgia with modern cyberpunk</p>
        </div>
    </div>

    <script>
        function playVideo(id) {
            pauseAll();
            document.getElementById(id).play();
        }

        function pauseAll() {
            document.getElementById('video1').pause();
            document.getElementById('video2').pause();
            document.getElementById('video3').pause();
        }

        // Sync all videos to start
        window.addEventListener('load', function() {
            const videos = [
                document.getElementById('video1'),
                document.getElementById('video2'),
                document.getElementById('video3')
            ];
            videos.forEach(v => {
                v.currentTime = 0;
                v.volume = 0.8;
            });
        });
    </script>
</body>
</html>
HTMLEOF

echo -e "${GREEN}✓ Comparison viewer created${NC}"
echo

# Summary
echo -e "${YELLOW}[7/7] Summary${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo
echo "✓ Generated 3 music tracks:"
echo "  1. Aegis Watch (Soft) - Ambient cyberpunk"
echo "  2. System Breach (Intense) - Industrial electronic"
echo "  3. Ghost in the Grid (Freeform) - Retrofuture synthwave"
echo
echo "✓ Created 3 demo videos:"
echo "  • $OUTPUT_DIR/hermes_aegis_demo_SOFT.mp4"
echo "  • $OUTPUT_DIR/hermes_aegis_demo_INTENSE.mp4"
echo "  • $OUTPUT_DIR/hermes_aegis_demo_FREEFORM.mp4"
echo
echo "To compare, open in browser:"
echo -e "${GREEN}  open $OUTPUT_DIR/compare.html${NC}"
echo
echo "Or watch individually:"
echo "  open $OUTPUT_DIR/hermes_aegis_demo_SOFT.mp4"
echo "  open $OUTPUT_DIR/hermes_aegis_demo_INTENSE.mp4"
echo "  open $OUTPUT_DIR/hermes_aegis_demo_FREEFORM.mp4"
echo
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
