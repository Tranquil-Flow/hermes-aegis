#!/bin/bash
# Generate AI music with MusicGen on macOS
# Uses Python 3.11, mocks xformers+spacy (unavailable/unneeded on Mac)

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  MusicGen AI Music Generator - macOS                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo

PYTHON=""
for candidate in /Users/evinova/.local/bin/python3.11 python3.11 python3.12; do
    if command -v "$candidate" &>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done
[ -z "$PYTHON" ] && { echo "❌ Need Python 3.11 or 3.12"; exit 1; }
echo "Using: $($PYTHON --version)"

WORK_DIR="$HOME/aegis_music_temp"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

echo "[1/4] Setting up Python environment..."
if [ ! -d "venv" ]; then
    $PYTHON -m venv venv
fi
source venv/bin/activate

# Only install if audiocraft not already present
if ! python3 -c "import audiocraft" 2>/dev/null; then
    echo "[2/4] Installing dependencies..."
    pip install -q --upgrade pip
    pip install -q torch torchaudio
    pip install -q --no-deps audiocraft==1.3.0
    pip install -q \
        "numpy<2" av einops julius num2words sentencepiece hydra-core omegaconf \
        soundfile librosa encodec flashy transformers huggingface_hub protobuf \
        demucs hydra_colorlog torchmetrics torchdiffeq
    echo "✓ Dependencies installed"
else
    echo "[2/4] Dependencies already installed ✓"
fi
echo

echo "[3/4] Generating three AI music tracks..."
echo "Duration: 142 seconds each"
echo

cat > generate.py << 'PYEOF'
#!/usr/bin/env python3
"""Generate 3 AI music tracks. Mocks xformers+spacy (Mac-incompatible, training-only)."""
import sys, types, torch

# === Mock xformers with real torch equivalents ===
xf = types.ModuleType("xformers")
xf_ops = types.ModuleType("xformers.ops")

# xformers.ops.unbind is just torch.unbind
xf_ops.unbind = torch.unbind
xf_ops.memory_efficient_attention = lambda *a, **kw: None
xf_ops.LowerTriangularMask = type("LowerTriangularMask", (), {})
xf_ops.AttentionBias = type("AttentionBias", (), {})

xf_fmha = types.ModuleType("xformers.ops.fmha")
xf_attn = types.ModuleType("xformers.ops.fmha.attn_bias")
xf_attn.LowerTriangularMask = xf_ops.LowerTriangularMask
xf_fmha.attn_bias = xf_attn
xf_ops.fmha = xf_fmha
xf.ops = xf_ops

for name, mod in [("xformers", xf), ("xformers.ops", xf_ops),
                   ("xformers.ops.fmha", xf_fmha),
                   ("xformers.ops.fmha.attn_bias", xf_attn)]:
    sys.modules[name] = mod

# === Mock spacy ===
spacy = types.ModuleType("spacy")
class _FakeNLP:
    def __call__(self, text):
        return type('Doc', (list,), {'text': text})()
spacy.load = lambda *a, **kw: _FakeNLP()
spacy.tokens = types.ModuleType("spacy.tokens")
spacy.tokens.Doc = type("Doc", (), {})
spacy.tokens.Span = type("Span", (), {})
for name, mod in [("spacy", spacy), ("spacy.tokens", spacy.tokens)]:
    sys.modules[name] = mod

# === Mock xformers.profiler (checked in _is_profiled) ===
xf_profiler_mod = types.ModuleType("xformers.profiler")
class _FakeProfiler:
    _CURRENT_PROFILER = None
class _FakeProfilerModule:
    _Profiler = _FakeProfiler
xf_profiler_mod.profiler = _FakeProfilerModule()
sys.modules["xformers.profiler"] = xf_profiler_mod

from audiocraft.models import MusicGen
from audiocraft.data.audio import audio_write

device = "mps" if torch.backends.mps.is_available() else "cpu"
print(f"✓ Device: {device.upper()}")

print("Loading MusicGen-small (downloads ~1.5GB first time)...")
model = MusicGen.get_pretrained('facebook/musicgen-small', device=device)
model.set_generation_params(duration=142.0)
print("✓ Model loaded\n")

tracks = [
    ("aegis_watch_soft",
     "ambient cyberpunk electronic, atmospheric pads, minimal pulse, quiet tension, digital surveillance, protective watching"),
    ("system_breach_intense",
     "industrial electronic, aggressive techno beat, harsh distorted synths, rapid percussion, cyber attack alert, urgent driving bass"),
    ("ghost_in_the_grid_freeform",
     "dark synthwave, 80s retrofuture electronic, pulsing bassline, neon cyberpunk, blade runner atmosphere, mysterious digital")
]

for i, (name, prompt) in enumerate(tracks, 1):
    print(f"[{i}/3] {name}...")
    print(f"     {prompt[:60]}...")
    wav = model.generate([prompt], progress=True)
    audio_write(name, wav[0].cpu(), model.sample_rate, strategy="loudness")
    print(f"     ✓ {name}.wav\n")

print("✓ All tracks generated!")
PYEOF

python3 generate.py

echo
echo "[4/4] Copying tracks to hermes-aegis..."

TARGET="$HOME/Projects/hermes-aegis/soundtracks"
mkdir -p "$TARGET"
cp *.wav "$TARGET/"

echo
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                     ✓ COMPLETE                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo
echo "✓ Tracks saved to: $TARGET/"
echo
echo "Now overlay onto video:"
echo "  cd ~/Projects/hermes-aegis && bash overlay_tracks.sh"
echo
