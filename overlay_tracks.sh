#!/bin/bash
# Overlay the generated music tracks onto video
set -e

VIDEO="HERMES_AEGIS_FINAL_V6.mp4"
MUSIC_DIR="soundtracks"
OUTPUT_DIR="demo_versions"

mkdir -p "$OUTPUT_DIR"

echo "Creating three video versions..."

echo "  [1/3] Soft..."
ffmpeg -y -i "$VIDEO" -i "$MUSIC_DIR/aegis_watch_soft.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    "$OUTPUT_DIR/hermes_aegis_demo_SOFT.mp4" -loglevel error -stats

echo "  [2/3] Intense..."
ffmpeg -y -i "$VIDEO" -i "$MUSIC_DIR/system_breach_intense.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    "$OUTPUT_DIR/hermes_aegis_demo_INTENSE.mp4" -loglevel error -stats

echo "  [3/3] Freeform..."
ffmpeg -y -i "$VIDEO" -i "$MUSIC_DIR/ghost_in_the_grid_freeform.wav" \
    -c:v copy -c:a aac -b:a 192k -shortest \
    "$OUTPUT_DIR/hermes_aegis_demo_FREEFORM.mp4" -loglevel error -stats

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
        h1 { text-align: center; font-size: 28px; text-shadow: 0 0 20px rgba(0,255,136,0.8); margin-bottom: 30px; }
        .container { max-width: 1600px; margin: 0 auto; }
        .video-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 30px; }
        .video-card {
            background: rgba(26,31,58,0.9);
            border: 3px solid #00ff88;
            border-radius: 12px;
            padding: 25px;
            transition: all 0.3s;
        }
        .video-card:hover { transform: translateY(-5px); box-shadow: 0 5px 50px rgba(0,255,136,0.5); }
        h2 { color: #00d4ff; text-align: center; margin-bottom: 10px; }
        .description { color: #88ffaa; text-align: center; margin-bottom: 20px; font-size: 14px; }
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
                <h2>🌙 SOFT VERSION</h2>
                <div class="description">Aegis Watch<br>Ambient cyberpunk · Atmospheric · Monitoring</div>
                <video id="v1" controls><source src="hermes_aegis_demo_SOFT.mp4"></video>
                <div class="controls">
                    <button onclick="play('v1')">▶ Play</button>
                    <button onclick="pauseAll()">⏸ Pause All</button>
                </div>
            </div>

            <div class="video-card">
                <h2>⚡ INTENSE VERSION</h2>
                <div class="description">System Breach<br>Industrial electronic · Aggressive · Attack</div>
                <video id="v2" controls><source src="hermes_aegis_demo_INTENSE.mp4"></video>
                <div class="controls">
                    <button onclick="play('v2')">▶ Play</button>
                    <button onclick="pauseAll()">⏸ Pause All</button>
                </div>
            </div>

            <div class="video-card">
                <h2>🌌 FREEFORM VERSION</h2>
                <div class="description">Ghost in the Grid<br>Dark synthwave · Retrofuture · Mysterious</div>
                <video id="v3" controls><source src="hermes_aegis_demo_FREEFORM.mp4"></video>
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
        window.onload = () => ['v1','v2','v3'].forEach(id => {
            const v = document.getElementById(id);
            v.volume = 0.8;
            v.currentTime = 0;
        });
    </script>
</body>
</html>
HTMLEOF

echo "✓ Complete!"
echo
echo "Videos created:"
ls -lh "$OUTPUT_DIR"/*.mp4
echo
echo "To compare: open $OUTPUT_DIR/compare.html"
echo
