#!/usr/bin/env python3
import sys
import os
import torch
import torchaudio
import scipy

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

print("\nLoading MusicGen model...")
print("(Using audiocraft API directly)")

# Import audiocraft (should be available even if spacy failed)
try:
    from audiocraft.models import MusicGen
    from audiocraft.data.audio import audio_write
except ImportError:
    print("\nAttempting to install audiocraft core without spacy...")
    import subprocess
    
    # Install core dependencies manually
    subprocess.run([sys.executable, "-m", "pip", "install", 
                   "av", "einops", "julius", "num2words", 
                   "sentencepiece", "xformers", "hydra-core",
                   "omegaconf"], check=False)
    
    # Now try git install but skip spacy
    subprocess.run([sys.executable, "-m", "pip", "install",
                   "--no-deps",
                   "git+https://github.com/facebookresearch/audiocraft.git"],
                   check=False)
    
    # Install remaining deps
    subprocess.run([sys.executable, "-m", "pip", "install",
                   "torch", "torchaudio", "einops", "julius", 
                   "flashy", "hydra-core", "hydra_colorlog",
                   "num2words", "sentencepiece", "xformers"],
                   check=False)
    
    from audiocraft.models import MusicGen
    from audiocraft.data.audio import audio_write

# Load model
print("Loading facebook/musicgen-small...")
model = MusicGen.get_pretrained('facebook/musicgen-small', device=device)

# Get duration
duration = float(sys.argv[1]) if len(sys.argv) > 1 else 30.0
model.set_generation_params(duration=duration)
print(f"✓ Model loaded, generating {duration:.1f}s tracks\n")

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
    print(f"{'='*60}")
    print(f"[{i}/3] Generating: {track['title']}")
    print(f"{'='*60}")
    print(f"Prompt: {track['prompt'][:70]}...")
    print(f"Duration: {duration:.1f}s")
    print()
    
    # Generate
    print("Generating audio (this will take a few minutes)...")
    wav = model.generate([track['prompt']], progress=True)
    
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
        print(f"\n✓ Saved: {track['name']}.wav ({size_mb:.1f} MB)")
    else:
        print(f"\n⚠ Warning: {file_path} not found")
    print()

print(f"{'='*60}")
print("✓ All three tracks generated successfully!")
print(f"{'='*60}")
