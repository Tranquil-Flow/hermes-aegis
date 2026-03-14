#!/usr/bin/env python3
"""
Render hermes-aegis demo video.
Shows 4 protection levels responding to security threats in real-time.
"""

import numpy as np
from PIL import Image, ImageDraw, ImageFont
import subprocess
from pathlib import Path
import json

# Demo configuration
RESOLUTION = (1920, 1080)
FPS = 24
FONT_SIZE = 14
CELL_SIZE = 8

# Color scheme
COLORS = {
    "bg": (0, 0, 0),           # Black background
    "text": (255, 255, 255),   # White text
    "red": (255, 0, 0),        # Unprotected
    "amber": (255, 165, 0),    # Partial protection
    "green": (0, 255, 0),      # Protected
    "cyan": (0, 255, 255),     # System info
    "blocked": (255, 50, 50),  # Blocked action
}

# ASCII art
SKULL = """
       ___
    .-'   '-.
   /         \\
  |           |
   \\  ^   ^  /
    '-.___..-'
     | | | |
"""

SHIELD = """
       ___
      /   \\
     /     \\
    |   ✓   |
     \\     /
      \\___/
"""

LOCK = """
     .---.
    /     \\
   |   ⌯   |
   |_______|
   | [===] |
   |_______|
"""


class TerminalGrid:
    """Represents one of the 4 terminal quadrants."""
    
    def __init__(self, name: str, level: int, color: tuple):
        self.name = name
        self.level = level
        self.color = color
        self.lines = []
        self.max_lines = 25
        
    def add_line(self, text: str, color: tuple = None):
        """Add a line to the terminal."""
        if color is None:
            color = self.color
        self.lines.append((text, color))
        if len(self.lines) > self.max_lines:
            self.lines.pop(0)
    
    def clear(self):
        """Clear terminal."""
        self.lines = []
        
    def get_status_emoji(self, attack: str, result: str) -> str:
        """Get emoji for attack result."""
        if "BLOCKED" in result or "✓" in result:
            return "✓"
        elif "⚠️" in result:
            return "⚠️"
        else:
            return "❌"


class DemoRenderer:
    """Renders the 4-quadrant demo video."""
    
    def __init__(self, output_path: str):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create font
        try:
            self.font = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", FONT_SIZE)
        except:
            try:
                self.font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", FONT_SIZE)
            except:
                self.font = ImageFont.load_default()
        
        # Create 4 terminal grids
        self.grids = {
            "level0": TerminalGrid("Unprotected Hermes", 0, COLORS["red"]),
            "level1": TerminalGrid("Docker Backend Only", 1, COLORS["amber"]),
            "level2": TerminalGrid("Aegis + Local", 2, COLORS["green"]),
            "level3": TerminalGrid("Aegis + Docker", 3, COLORS["green"]),
        }
        
        # Frame buffer
        self.frames = []
        
    def render_frame(self) -> np.ndarray:
        """Render current state to a frame."""
        width, height = RESOLUTION
        canvas = np.zeros((height, width, 3), dtype=np.uint8)
        img = Image.fromarray(canvas)
        draw = ImageDraw.Draw(img)
        
        # Split into 4 quadrants
        quad_width = width // 2
        quad_height = height // 2
        
        positions = [
            ("level0", COLORS["red"], 0, 0),
            ("level1", COLORS["amber"], quad_width, 0),
            ("level2", COLORS["green"], 0, quad_height),
            ("level3", COLORS["green"], quad_width, quad_height),
        ]
        
        for grid_key, color, x_offset, y_offset in positions:
            grid = self.grids[grid_key]
            
            # Draw border
            draw.rectangle(
                [x_offset, y_offset, x_offset + quad_width - 2, y_offset + quad_height - 2],
                outline=color,
                width=2
            )
            
            # Draw title
            title_y = y_offset + 10
            draw.text((x_offset + 10, title_y), grid.name, fill=COLORS["cyan"], font=self.font)
            
            # Draw terminal lines
            line_y = title_y + 30
            for i, (text, line_color) in enumerate(grid.lines):
                if line_y + 20 > y_offset + quad_height:
                    break
                draw.text((x_offset + 10, line_y), text, fill=line_color, font=self.font)
                line_y += 20
        
        return np.array(img)
    
    def add_frame(self, duration_frames: int = 1):
        """Add current state as frame(s)."""
        frame = self.render_frame()
        for _ in range(duration_frames):
            self.frames.append(frame)
    
    def simulate_attack(self, attack: dict, duration: float = 6.0):
        """Simulate an attack across all 4 levels."""
        frames_for_attack = int(duration * FPS)
        
        # Show attack prompt
        prompt_short = attack["prompt"][:60] + "..."
        
        for grid in self.grids.values():
            grid.add_line(f"", COLORS["text"])
            grid.add_line(f"[USER]: {prompt_short}", COLORS["text"])
            grid.add_line(f"[AGENT]: Processing...", COLORS["cyan"])
        
        self.add_frame(int(FPS * 2))  # 2 seconds
        
        # Show command being generated
        cmd = attack.get("expected_command", "command")
        for grid in self.grids.values():
            grid.add_line(f"$ {cmd}", COLORS["text"])
        
        self.add_frame(int(FPS * 1))  # 1 second
        
        # Show results per level
        for grid_key in ["level0", "level1", "level2", "level3"]:
            grid = self.grids[grid_key]
            result = attack[grid_key]
            
            if "❌" in result:
                grid.add_line(f"  {result}", COLORS["red"])
            elif "⚠️" in result:
                grid.add_line(f"  {result}", COLORS["amber"])
            else:
                grid.add_line(f"  {result}", COLORS["green"])
        
        self.add_frame(int(FPS * 3))  # 3 seconds
    
    def render_intro(self):
        """Render intro sequence."""
        # Clear all grids
        for grid in self.grids.values():
            grid.clear()
            grid.add_line("═" * 70, COLORS["cyan"])
            grid.add_line(f"  {grid.name}", COLORS["cyan"])
            grid.add_line("═" * 70, COLORS["cyan"])
            grid.add_line("", COLORS["text"])
            grid.add_line("Initializing agent...", COLORS["text"])
        
        self.add_frame(int(FPS * 3))  # 3 seconds
        
        # Show startup complete
        for grid in self.grids.values():
            grid.add_line("✓ Ready", COLORS["green"])
            grid.add_line("", COLORS["text"])
        
        self.add_frame(int(FPS * 2))  # 2 seconds
    
    def render_outro(self):
        """Render outro with summary."""
        for grid in self.grids.values():
            grid.clear()
        
        # Summary
        self.grids["level0"].add_line("═" * 70, COLORS["red"])
        self.grids["level0"].add_line("  5/5 ATTACKS SUCCEEDED", COLORS["red"])
        self.grids["level0"].add_line("  Security: VULNERABLE", COLORS["red"])
        
        self.grids["level1"].add_line("═" * 70, COLORS["amber"])
        self.grids["level1"].add_line("  3/5 ATTACKS SUCCEEDED", COLORS["amber"])
        self.grids["level1"].add_line("  Security: PARTIAL", COLORS["amber"])
        
        self.grids["level2"].add_line("═" * 70, COLORS["green"])
        self.grids["level2"].add_line("  0/5 ATTACKS SUCCEEDED", COLORS["green"])
        self.grids["level2"].add_line("  Security: PROTECTED", COLORS["green"])
        
        self.grids["level3"].add_line("═" * 70, COLORS["green"])
        self.grids["level3"].add_line("  0/5 ATTACKS SUCCEEDED", COLORS["green"])
        self.grids["level3"].add_line("  Security: FULL PROTECTION", COLORS["green"])
        
        self.add_frame(int(FPS * 5))  # 5 seconds
    
    def encode_video(self):
        """Save frames as images (fallback when ffmpeg unavailable)."""
        print(f"Saving {len(self.frames)} frames as images...")
        
        frame_dir = self.output_path.parent / "frames"
        frame_dir.mkdir(parents=True, exist_ok=True)
        
        for i, frame in enumerate(self.frames):
            if i % 100 == 0:
                print(f"  Saving frame {i}/{len(self.frames)}...")
            
            img = Image.fromarray(frame)
            img.save(frame_dir / f"frame_{i:04d}.png")
        
        print(f"✓ Frames saved to {frame_dir}")
        print(f"  To encode video:")
        print(f"  ffmpeg -framerate {FPS} -i {frame_dir}/frame_%04d.png -c:v libx264 -preset medium -crf 18 -pix_fmt yuv420p {self.output_path}")
    
    def render_full_demo(self, attacks: list):
        """Render complete demo video."""
        print("Rendering hermes-aegis demo video...")
        
        # Intro
        print("  Rendering intro...")
        self.render_intro()
        
        # Each attack
        for i, attack in enumerate(attacks):
            print(f"  Rendering attack {i+1}/{len(attacks)}: {attack['name']}...")
            self.simulate_attack(attack)
        
        # Outro
        print("  Rendering outro...")
        self.render_outro()
        
        # Encode
        self.encode_video()


def main():
    # Load attacks
    from attack_prompts import get_all_attacks
    attacks = get_all_attacks()
    
    # Render demo
    renderer = DemoRenderer("output/aegis_demo_v1.mp4")
    renderer.render_full_demo(attacks)


if __name__ == "__main__":
    main()
