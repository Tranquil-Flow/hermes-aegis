#!/bin/bash
# QUICK VERSION: Generate three versions with synthesized audio using ffmpeg only
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Aegis Demo - Quick 3-Track Generator (ffmpeg only)     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"

VIDEO_FILE="HERMES_AEGIS_FINAL_V6.mp4"
DURATION=142
MUSIC_DIR="$SCRIPT_DIR/soundtracks"
OUTPUT_DIR="$SCRIPT_DIR/demo_versions"
mkdir -p "$MUSIC_DIR" "$OUTPUT_DIR"

echo
echo -e "${YELLOW}Generating three synthesized soundtracks (10 seconds)...${NC}"

# Track 1: Soft ambient
echo "  [1/3] Aegis Watch (Soft)..."
ffmpeg -f lavfi -i "anoisesrc=duration=$DURATION:color=pink:amplitude=0.1" \
    -af "highpass=f=100,lowpass=f=800,volume=0.3" \
    -y "$MUSIC_DIR/aegis_watch_soft.wav" -loglevel error 2>&1

# Track 2: Intense pulse
echo "  [2/3] System Breach (Intense)..."
ffmpeg -f lavfi -i "sine=f=110:d=$DURATION" \
    -af "tremolo=f=8:d=0.9,aphaser=type=t:speed=2:decay=0.6,volume=0.5" \
    -y "$MUSIC_DIR/system_breach_intense.wav" -loglevel error 2>&1

# Track 3: Synthwave arp
echo "  [3/3] Ghost in the Grid (Freeform)..."
ffmpeg -f lavfi -i "sine=f=220:d=$DURATION" \
    -af "tremolo=f=4:d=0.7,chorus=0.5:0.9:50:0.4:0.25:2,aphaser=speed=0.8,volume=0.4" \
    -y "$MUSIC_DIR/ghost_in_the_grid_freeform.wav" -loglevel error 2>&1

echo -e "${GREEN}✓ Soundtracks ready${NC}"
echo
echo -e "${YELLOW}Creating video versions...${NC}"

ffmpeg -y -i "$VIDEO_FILE" -i "$MUSIC_DIR/aegis_watch_soft.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    "$OUTPUT_DIR/hermes_aegis_demo_SOFT.mp4" -loglevel error -stats 2>&1 | tail -1

ffmpeg -y -i "$VIDEO_FILE" -i "$MUSIC_DIR/system_breach_intense.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    "$OUTPUT_DIR/hermes_aegis_demo_INTENSE.mp4" -loglevel error -stats 2>&1 | tail -1

ffmpeg -y -i "$VIDEO_FILE" -i "$MUSIC_DIR/ghost_in_the_grid_freeform.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    "$OUTPUT_DIR/hermes_aegis_demo_FREEFORM.mp4" -loglevel error -stats 2>&1 | tail -1

# Create viewer
cat > "$OUTPUT_DIR/compare.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Aegis Soundtrack Comparison</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: 'SF Mono', monospace;
            background: linear-gradient(135deg, #0a0e27, #1a1f3a);
            color: #00ff88;
            padding: 40px 20px;
        }
        h1 {
            text-align: center;
            font-size: 28px;
            text-shadow: 0 0 20px rgba(0,255,136,0.8);
            margin-bottom: 30px;
        }
        .container { max-width: 1600px; margin: 0 auto; }
        .video-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(450px, 1fr));
            gap: 30px;
        }
        .video-card {
            background: rgba(26,31,58,0.9);
            border: 3px solid #00ff88;
            border-radius: 12px;
            padding: 25px;
            transition: all 0.3s;
        }
        .video-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 50px rgba(0,255,136,0.5);
        }
        h2 { color: #00d4ff; text-align: center; margin-bottom: 10px; }
        .description { color: #88ffaa; text-align: center; margin-bottom: 20px; }
        video { width: 100%; border-radius: 8px; border: 2px solid #00ff88; }
        .controls { margin-top: 20px; text-align: center; }
        button {
            background: linear-gradient(135deg, #00ff88, #00d4ff);
            color: #0a0e27;
            border: none;
            padding: 12px 24px;
            margin: 5px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: bold;
        }
        button:hover { transform: translateY(-2px); }
    </style>
</head>
<body>
    <div class="container">
        <h1>HERMES AEGIS - SOUNDTRACK COMPARISON</h1>
        
        <div class="video-grid">
            <div class="video-card">
                <h2>🌙 SOFT</h2>
                <div class="description">Ambient · Low tension · Watching</div>
                <video id="v1" controls><source src="hermes_aegis_demo_SOFT.mp4" type="video/mp4"></video>
                <div class="controls">
                    <button onclick="play('v1')">▶ Play</button>
                    <button onclick="pauseAll()">⏸ Pause All</button>
                </div>
            </div>

            <div class="video-card">
                <h2>⚡ INTENSE</h2>
                <div class="description">Pulse · High energy · Alert</div>
                <video id="v2" controls><source src="hermes_aegis_demo_INTENSE.mp4" type="video/mp4"></video>
                <div class="controls">
                    <button onclick="play('v2')">▶ Play</button>
                    <button onclick="pauseAll()">⏸ Pause All</button>
                </div>
            </div>

            <div class="video-card">
                <h2>🌌 FREEFORM</h2>
                <div class="description">Synthwave · Retrofuture · Mystery</div>
                <video id="v3" controls><source src="hermes_aegis_demo_FREEFORM.mp4" type="video/mp4"></video>
                <div class="controls">
                    <button onclick="play('v3')">▶ Play</button>
                    <button onclick="pauseAll()">⏸ Pause All</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        function play(id) { pauseAll(); document.getElementById(id).play(); }
        function pauseAll() { ['v1','v2','v3'].forEach(id => document.getElementById(id).pause()); }
    </script>
</body>
</html>
HTMLEOF

echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                  ✓ DONE IN 20 SECONDS                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo
echo "📁 Videos ready:"
ls -lh "$OUTPUT_DIR"/*.mp4 | awk '{printf "  %s  %s\n", $5, $9}'
echo
echo -e "${YELLOW}Compare all three:${NC}"
echo -e "${GREEN}  open $OUTPUT_DIR/compare.html${NC}"
echo
