#!/usr/bin/env python3
"""Test single frame render to verify effects."""

from render_demo_v2 import DemoRenderer, COLORS
from attack_prompts import get_all_attacks

# Create renderer
renderer = DemoRenderer("output/test.mp4")

# Initialize
for grid in renderer.grids.values():
    grid.clear()
    if grid.level >= 2:
        grid.enable_matrix_rain(960, 540)
    
    grid.add_line("═" * 60, COLORS["cyan"])
    grid.add_line(f"  {grid.name}", COLORS["cyan"])
    grid.add_line("═" * 60, COLORS["cyan"])
    grid.add_line("", COLORS["text"])

# Add some content
attacks = get_all_attacks()
attack = attacks[0]  # Secret exfiltration

for grid_key in ["level0", "level1", "level2", "level3"]:
    grid = renderer.grids[grid_key]
    grid.add_line(f">>> ATTACK: {attack['name']}", COLORS["cyan"])
    grid.add_line("", COLORS["text"])
    grid.add_line(f"$ {attack['expected_command']}", COLORS["amber"])
    grid.add_line("", COLORS["text"])
    
    result = attack[grid_key]
    if "❌" in result:
        grid.add_line("  ATTACK SUCCEEDED", COLORS["red"])
        renderer.draw_ascii_icon(grid_key, "skull")
    elif "⚠️" in result:
        grid.add_line("  PARTIAL PROTECTION", COLORS["amber"])
        renderer.draw_ascii_icon(grid_key, "warning")
    else:
        grid.add_line("  ATTACK BLOCKED", COLORS["green"])
        renderer.draw_ascii_icon(grid_key, "shield")
        grid.pulse_alpha = 0.8
    
    grid.add_line("", COLORS["text"])
    grid.add_line(f"  {result}", 
                 COLORS["red"] if "❌" in result else 
                 COLORS["amber"] if "⚠️" in result else 
                 COLORS["green"])

# Emit some particles
renderer.particles.emit_burst(480, 270, COLORS["red"], count=15)
renderer.particles.emit_burst(1440, 270, COLORS["amber"], count=10)
renderer.particles.emit_burst(480, 810, COLORS["green"], count=20)
renderer.particles.emit_burst(1440, 810, COLORS["green"], count=20)

# Update a few times to see effects
for _ in range(10):
    renderer.particles.update()
    for grid in renderer.grids.values():
        if grid.matrix_rain:
            grid.matrix_rain.update()
        grid.update_pulse()

# Render and save
print("Rendering test frame...")
frame = renderer.render_frame()

from PIL import Image
img = Image.fromarray(frame)
img.save("output/test_frame.png")
print("✓ Test frame saved to output/test_frame.png")
