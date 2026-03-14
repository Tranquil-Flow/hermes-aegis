#!/usr/bin/env python3
"""
Minimal MusicGen generator that installs only what's needed
Skips xformers (optional) and handles missing deps gracefully
"""
import sys
import os
import subprocess

def install_if_needed(package, import_name=None):
    """Install package if the import fails"""
    import_name = import_name or package.split('[')[0].split('==')[0].split('>=')[0]
    try:
        __import__(import_name)
        return True
    except ImportError:
        print(f"Installing {package}...")
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", package], 
                      check=False, capture_output=True)
        return False

# Core dependencies (install in order)
deps = [
    ("soundfile", "soundfile"),
    ("av", "av"),
    ("einops", "einops"),
    ("julius", "julius"),
    ("num2words", "num2words"),
    ("sentencepiece", "sentencepiece"),
    ("hydra-core", "hydra"),
    ("hydra-colorlog", "hydra_colorlog"),
    ("omegaconf", "omegaconf"),
    ("librosa", "librosa"),
]

print("Checking dependencies...")
for pkg, imp in deps:
    install_if_needed(pkg, imp)

# Try audiocraft import
try:
    from audiocraft.models import MusicGen
    from audiocraft.data.audio import audio_write
    print("✓ Audiocraft loaded")
except ImportError:
    print("Installing audiocraft (without xformers)...")
    subprocess.run([
        sys.executable, "-m", "pip", "install", "-q",
        "git+https://github.com/facebookresearch/audiocraft.git"
    ], check=False, capture_output=True)
    from audiocraft.models import MusicGen
    from audiocraft.data.audio import audio_write

import torch

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
print("(First run downloads ~1.5GB of weights)")
try:
    model = MusicGen.get_pretrained('facebook/musicgen-small', device=device)
except Exception as e:
    print(f"Error loading model: {e}")
    print("Trying CPU fallback...")
    device = "cpu"
    model = MusicGen.get_pretrained('facebook/musicgen-small', device=device)

# Get duration from command line
duration = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
model.set_generation_params(duration=duration)
print(f"✓ Model loaded, set to generate {duration:.1f}s tracks\n")

# Track definitions
tracks = [
    {
        "name": "aegis_watch_soft",
        "title": "Aegis Watch (Soft)",
        "prompt": (
            "ambient cyberpunk electronic music, atmospheric synthesizer pads, "
            "minimal pulsing rhythm, quiet tension, digital monitoring soundscape, "
            "sparse electronic beats, protective atmosphere, watching vigilant"
        )
    },
    {
        "name": "system_breach_intense",
        "title": "System Breach (Intense)",
        "prompt": (
            "industrial electronic music, aggressive techno beat, "
            "harsh distorted synthesizers, rapid percussion, cyber attack alert, "
            "defensive response energy, urgent tension, heavy driving bass"
        )
    },
    {
        "name": "ghost_in_the_grid_freeform",
        "title": "Ghost in the Grid (Freeform)",
        "prompt": (
            "dark synthwave retro music, 80s electronic synthesizers, "
            "pulsing analog bassline, neon lit cyberpunk aesthetic, "
            "nostalgic digital atmosphere, blade runner cinematic, mysterious entity"
        )
    }
]

output_dir = os.path.dirname(os.path.abspath(__file__))

# Generate each track
for i, track in enumerate(tracks, 1):
    print(f"{'='*70}")
    print(f"[{i}/3] Generating: {track['title']}")
    print(f"{'='*70}")
    print(f"Prompt: {track['prompt'][:65]}...")
    print(f"Duration: {duration:.1f}s")
    print()
    
    try:
        # Generate
        print("Generating audio (3-8 minutes depending on hardware)...")
        wav = model.generate(
            descriptions=[track['prompt']], 
            progress=True
        )
        
        # Save
        output_path = os.path.join(output_dir, track['name'])
        audio_write(
            output_path,
            wav[0].cpu(),
            model.sample_rate,
            strategy="loudness",
            loudness_compressor=True
        )
        
        # Verify
        file_path = f"{output_path}.wav"
        if os.path.exists(file_path):
            size_mb = os.path.getsize(file_path) / (1024 * 1024)
            print(f"\n✓ SUCCESS: {track['name']}.wav ({size_mb:.1f} MB)")
        else:
            print(f"\n⚠ Warning: Expected file not found at {file_path}")
    except Exception as e:
        print(f"\n✗ ERROR generating {track['name']}: {e}")
        import traceback
        traceback.print_exc()
    
    print()

print(f"{'='*70}")
print("✓ Track generation complete!")
print(f"{'='*70}")
