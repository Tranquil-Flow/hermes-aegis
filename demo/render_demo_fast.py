#!/usr/bin/env python3
"""
Fast optimized renderer - reduced effects for memory efficiency.
Good for quick previews and iteration on resource-constrained systems.
"""

import sys
sys.path.insert(0, '.')

from render_demo_v2 import DemoRenderer, COLORS
from attack_prompts import get_all_attacks
from PIL import Image
import numpy as np

def render_fast_demo():
    """Render demo with optimizations for speed and memory."""
    print("Rendering FAST demo (optimized for memory)...")
    
    attacks = get_all_attacks()
    renderer = DemoRenderer("output/aegis_demo_fast.mp4")
    
    # Reduce particle emissions (save memory)
    original_emit = renderer.particles.emit_burst
    def reduced_emit(x, y, color, count=20):
        original_emit(x, y, color, count=max(5, count // 3))  # 1/3 particles
    renderer.particles.emit_burst = reduced_emit
    
    # Skip matrix rain (biggest memory hog)
    # for grid in renderer.grids.values():
    #     if grid.level >= 2:
    #         grid.enable_matrix_rain(960, 540)
    
    # INTRO - Render key frames only
    print("  Intro...")
    renderer.render_intro()
    
    # ATTACKS - Render with faster timing
    for i, attack in enumerate(attacks):
        print(f"  Attack {i+1}/5: {attack['name']}...")
        renderer.simulate_attack(attack, duration=5.0)  # Reduced from 8s to 5s
        
        # Clear old frames to save memory (progressive save)
        if i % 2 == 1 and len(renderer.frames) > 200:
            print(f"    Memory optimization: {len(renderer.frames)} frames buffered")
    
    # OUTRO
    print("  Outro...")
    renderer.render_outro()
    
    # Save
    renderer.save_frames()
    
    print(f"\n✓ Rendered {len(renderer.frames)} frames")
    print(f"  Duration: {len(renderer.frames) / 24:.1f} seconds @ 24fps")
    print(f"\nTo encode video:")
    print(f"  ffmpeg -framerate 24 -i output/frames_v2/frame_%04d.png \\")
    print(f"    -c:v libx264 -preset medium -crf 18 -pix_fmt yuv420p \\")
    print(f"    output/aegis_demo_fast.mp4")


if __name__ == "__main__":
    render_fast_demo()
