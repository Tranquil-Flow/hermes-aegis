#!/usr/bin/env python3
"""
Render hermes-aegis demo video V2 - Enhanced with ASCII art animations.
Shows 4 protection levels responding to security threats in real-time.
"""

import numpy as np
from PIL import Image, ImageDraw, ImageFont
import subprocess
from pathlib import Path
import json
import random
import math

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
    "dim_red": (100, 0, 0),
    "dim_amber": (100, 65, 0),
    "dim_green": (0, 100, 0),
    "dim_cyan": (0, 100, 100),
}

# ASCII art
SKULL_SMALL = [
    "   ___   ",
    " ,'   `. ",
    "/  o o  \\",
    "|   ^   |",
    " \\  v  / ",
    "  `---'  ",
]

SHIELD_SMALL = [
    "   ___   ",
    "  /   \\  ",
    " | ✓✓✓ | ",
    " |  ✓  | ",
    "  \\ ^ /  ",
    "   `-'   ",
]

LOCK_SMALL = [
    "  .---.  ",
    " /     \\ ",
    "|   O   |",
    "|-------|",
    "| ===== |",
    "`-------'",
]

WARNING_SMALL = [
    "   /\\    ",
    "  /  \\   ",
    " / !! \\  ",
    "/______\\ ",
]

# Matrix characters for rain effect
MATRIX_CHARS = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨ"


class MatrixRain:
    """Matrix-style falling characters effect."""
    
    def __init__(self, width: int, height: int, density: float = 0.02):
        self.width = width
        self.height = height
        self.columns = int(width / 12)  # One column every 12 pixels
        self.drops = [random.randint(-20, 0) for _ in range(self.columns)]
        self.chars = [random.choice(MATRIX_CHARS) for _ in range(self.columns)]
        self.density = density
        
    def update(self):
        """Update rain positions."""
        for i in range(self.columns):
            if self.drops[i] > self.height / 20:
                if random.random() < 0.05:  # 5% chance to reset
                    self.drops[i] = 0
                    self.chars[i] = random.choice(MATRIX_CHARS)
            self.drops[i] += 1
            
    def render(self, canvas: np.ndarray, x_offset: int, y_offset: int, color: tuple):
        """Render rain on canvas."""
        img = Image.fromarray(canvas)
        draw = ImageDraw.Draw(img)
        
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 12)
        except:
            font = ImageFont.load_default()
        
        for i in range(self.columns):
            if self.drops[i] > 0:
                x = x_offset + (i * 12)
                y = y_offset + (self.drops[i] * 20)
                if y < y_offset + self.height:
                    # Fade effect - brighter at head
                    alpha = min(1.0, self.drops[i] / 5.0)
                    fade_color = tuple(int(c * alpha) for c in color)
                    draw.text((x, y), self.chars[i], fill=fade_color, font=font)
        
        return np.array(img)


class Particle:
    """Single particle for effects."""
    def __init__(self, x, y, vx=0, vy=0, char='*', color=(255,255,255), lifetime=30):
        self.x = x
        self.y = y
        self.vx = vx
        self.vy = vy
        self.char = char
        self.color = color
        self.lifetime = lifetime
        self.age = 0
        
    def update(self):
        self.x += self.vx
        self.y += self.vy
        self.vy += 0.5  # Gravity
        self.age += 1
        
    def is_alive(self):
        return self.age < self.lifetime


class ParticleSystem:
    """Manage particle effects."""
    def __init__(self):
        self.particles = []
        
    def emit_burst(self, x, y, color, count=20):
        """Emit burst of particles."""
        chars = ['*', '·', '○', '●', '◦', '◉']
        for _ in range(count):
            angle = random.uniform(0, 2 * math.pi)
            speed = random.uniform(2, 8)
            vx = math.cos(angle) * speed
            vy = math.sin(angle) * speed
            self.particles.append(
                Particle(x, y, vx, vy, random.choice(chars), color, random.randint(15, 30))
            )
    
    def update(self):
        """Update all particles."""
        self.particles = [p for p in self.particles if p.is_alive()]
        for p in self.particles:
            p.update()
    
    def render(self, canvas: np.ndarray, font):
        """Render particles on canvas."""
        img = Image.fromarray(canvas)
        draw = ImageDraw.Draw(img)
        
        for p in self.particles:
            alpha = 1.0 - (p.age / p.lifetime)
            fade_color = tuple(int(c * alpha) for c in p.color)
            draw.text((int(p.x), int(p.y)), p.char, fill=fade_color, font=font)
        
        return np.array(img)


class TerminalGrid:
    """Represents one of the 4 terminal quadrants."""
    
    def __init__(self, name: str, level: int, color: tuple, dim_color: tuple):
        self.name = name
        self.level = level
        self.color = color
        self.dim_color = dim_color
        self.lines = []
        self.max_lines = 22
        self.matrix_rain = None
        self.pulse_alpha = 0.0
        self.pulse_direction = 1
        
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
        
    def enable_matrix_rain(self, width, height):
        """Enable matrix rain effect for this terminal."""
        self.matrix_rain = MatrixRain(width, height, density=0.02)
    
    def update_pulse(self):
        """Update pulse effect."""
        self.pulse_alpha += 0.1 * self.pulse_direction
        if self.pulse_alpha >= 1.0:
            self.pulse_direction = -1
            self.pulse_alpha = 1.0
        elif self.pulse_alpha <= 0.0:
            self.pulse_direction = 1
            self.pulse_alpha = 0.0


class DemoRenderer:
    """Renders the 4-quadrant demo video with enhanced effects."""
    
    def __init__(self, output_path: str):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create fonts
        try:
            self.font = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", FONT_SIZE)
            self.font_large = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 18)
            self.font_small = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 10)
        except:
            try:
                self.font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", FONT_SIZE)
                self.font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 18)
                self.font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 10)
            except:
                self.font = ImageFont.load_default()
                self.font_large = ImageFont.load_default()
                self.font_small = ImageFont.load_default()
        
        # Create 4 terminal grids
        self.grids = {
            "level0": TerminalGrid("Unprotected Hermes", 0, COLORS["red"], COLORS["dim_red"]),
            "level1": TerminalGrid("Docker Backend Only", 1, COLORS["amber"], COLORS["dim_amber"]),
            "level2": TerminalGrid("Aegis + Local", 2, COLORS["green"], COLORS["dim_green"]),
            "level3": TerminalGrid("Aegis + Docker", 3, COLORS["green"], COLORS["dim_green"]),
        }
        
        # Frame buffer
        self.frames = []
        
        # Particle system
        self.particles = ParticleSystem()
        
    def draw_ascii_art(self, draw, art: list, x: int, y: int, color: tuple):
        """Draw ASCII art at position."""
        for i, line in enumerate(art):
            draw.text((x, y + i * 15), line, fill=color, font=self.font_small)
    
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
            ("level0", 0, 0),
            ("level1", quad_width, 0),
            ("level2", 0, quad_height),
            ("level3", quad_width, quad_height),
        ]
        
        for grid_key, x_offset, y_offset in positions:
            grid = self.grids[grid_key]
            
            # Background effect - matrix rain for protected levels
            if grid.level >= 2 and grid.matrix_rain is not None:
                grid.matrix_rain.update()
                canvas = grid.matrix_rain.render(
                    canvas, x_offset, y_offset, grid.dim_color
                )
                img = Image.fromarray(canvas)
                draw = ImageDraw.Draw(img)
            
            # Draw border with pulse effect
            border_color = grid.color
            if grid.pulse_alpha > 0:
                # Mix border color with white for pulse
                pulse_blend = grid.pulse_alpha * 0.5
                border_color = tuple(
                    int(c * (1 - pulse_blend) + 255 * pulse_blend) 
                    for c in grid.color
                )
            
            # Thicker border for emphasis
            for thickness in range(4):
                draw.rectangle(
                    [
                        x_offset + thickness, 
                        y_offset + thickness, 
                        x_offset + quad_width - 2 - thickness, 
                        y_offset + quad_height - 2 - thickness
                    ],
                    outline=border_color,
                    width=1
                )
            
            # Draw title bar
            title_y = y_offset + 10
            title_bg = [x_offset, y_offset, x_offset + quad_width, y_offset + 40]
            draw.rectangle(title_bg, fill=(10, 10, 10))
            
            # Center title text
            title_bbox = draw.textbbox((0, 0), grid.name, font=self.font_large)
            title_width = title_bbox[2] - title_bbox[0]
            title_x = x_offset + (quad_width - title_width) // 2
            draw.text((title_x, title_y), grid.name, fill=COLORS["cyan"], font=self.font_large)
            
            # Draw terminal lines
            line_y = y_offset + 50
            for i, (text, line_color) in enumerate(grid.lines):
                if line_y + 20 > y_offset + quad_height - 10:
                    break
                draw.text((x_offset + 10, line_y), text, fill=line_color, font=self.font)
                line_y += 18
        
        # Render particles on top
        canvas = np.array(img)
        canvas = self.particles.render(canvas, self.font)
        
        return canvas
    
    def add_frame(self, duration_frames: int = 1):
        """Add current state as frame(s)."""
        for _ in range(duration_frames):
            # Update particle system
            self.particles.update()
            
            # Update pulse effects
            for grid in self.grids.values():
                grid.update_pulse()
            
            frame = self.render_frame()
            self.frames.append(frame)
    
    def draw_ascii_icon(self, grid_key: str, icon_type: str):
        """Draw ASCII art icon in a grid."""
        grid = self.grids[grid_key]
        
        icons = {
            "skull": SKULL_SMALL,
            "shield": SHIELD_SMALL,
            "lock": LOCK_SMALL,
            "warning": WARNING_SMALL,
        }
        
        if icon_type in icons:
            for line in icons[icon_type]:
                grid.add_line(line, grid.color)
    
    def simulate_attack(self, attack: dict, duration: float = 8.0):
        """Simulate an attack across all 4 levels with enhanced visuals."""
        frames_for_attack = int(duration * FPS)
        
        # Phase 1: Show attack prompt (2s)
        prompt_short = attack["name"].upper()
        
        for grid in self.grids.values():
            grid.add_line("", COLORS["text"])
            grid.add_line(f">>> ATTACK: {prompt_short}", COLORS["cyan"])
            grid.add_line("", COLORS["text"])
        
        self.add_frame(int(FPS * 1.5))
        
        # Show prompt details
        prompt_lines = [
            attack["prompt"][i:i+50] 
            for i in range(0, min(len(attack["prompt"]), 150), 50)
        ]
        for line in prompt_lines:
            for grid in self.grids.values():
                grid.add_line(f"  {line}", COLORS["text"])
        
        self.add_frame(int(FPS * 1.5))
        
        # Phase 2: Show command being generated (1s)
        cmd = attack.get("expected_command", "command")
        for grid in self.grids.values():
            grid.add_line("", COLORS["text"])
            grid.add_line(f"$ {cmd}", COLORS["amber"])
        
        self.add_frame(int(FPS * 1))
        
        # Phase 3: Show results with ASCII art and effects (3s)
        quad_width = RESOLUTION[0] // 2
        quad_height = RESOLUTION[1] // 2
        
        positions = {
            "level0": (quad_width // 2, quad_height // 2),
            "level1": (quad_width + quad_width // 2, quad_height // 2),
            "level2": (quad_width // 2, quad_height + quad_height // 2),
            "level3": (quad_width + quad_width // 2, quad_height + quad_height // 2),
        }
        
        for grid_key in ["level0", "level1", "level2", "level3"]:
            grid = self.grids[grid_key]
            result = attack[grid_key]
            
            grid.add_line("", COLORS["text"])
            
            # Determine icon and effects
            if "❌" in result:
                # Attack succeeded - show skull
                grid.add_line("  ATTACK SUCCEEDED", COLORS["red"])
                self.draw_ascii_icon(grid_key, "skull")
                # Emit red particles
                px, py = positions[grid_key]
                self.particles.emit_burst(px, py, COLORS["red"], count=15)
                
            elif "⚠️" in result:
                # Partial protection
                grid.add_line("  PARTIAL PROTECTION", COLORS["amber"])
                self.draw_ascii_icon(grid_key, "warning")
                # Emit amber particles
                px, py = positions[grid_key]
                self.particles.emit_burst(px, py, COLORS["amber"], count=10)
                
            else:
                # Attack blocked
                grid.add_line("  ATTACK BLOCKED", COLORS["green"])
                self.draw_ascii_icon(grid_key, "shield")
                # Emit green particles
                px, py = positions[grid_key]
                self.particles.emit_burst(px, py, COLORS["green"], count=20)
                # Start pulse effect
                grid.pulse_alpha = 1.0
            
            grid.add_line("", COLORS["text"])
            grid.add_line(f"  {result}", 
                         COLORS["red"] if "❌" in result else 
                         COLORS["amber"] if "⚠️" in result else 
                         COLORS["green"])
        
        self.add_frame(int(FPS * 3))
        
        # Clear ASCII art
        for grid in self.grids.values():
            grid.add_line("", COLORS["text"])
    
    def render_intro(self):
        """Render intro sequence with effects."""
        # Clear all grids
        for grid in self.grids.values():
            grid.clear()
            
            # Enable matrix rain for protected levels
            if grid.level >= 2:
                grid.enable_matrix_rain(RESOLUTION[0] // 2, RESOLUTION[1] // 2)
        
        # Title card
        for grid in self.grids.values():
            grid.add_line("", COLORS["text"])
            grid.add_line("═" * 60, COLORS["cyan"])
            grid.add_line("", COLORS["text"])
        
        self.add_frame(int(FPS * 1))
        
        for grid in self.grids.values():
            grid.add_line(f"  {grid.name.upper()}", COLORS["cyan"])
            grid.add_line("", COLORS["text"])
            grid.add_line("═" * 60, COLORS["cyan"])
        
        self.add_frame(int(FPS * 2))
        
        # Show initialization
        for grid in self.grids.values():
            grid.add_line("", COLORS["text"])
            grid.add_line("  Initializing agent...", COLORS["text"])
        
        self.add_frame(int(FPS * 1))
        
        for grid in self.grids.values():
            grid.add_line("  Loading security modules...", COLORS["text"])
        
        self.add_frame(int(FPS * 1))
        
        # Show startup complete
        for grid_key in ["level0", "level1", "level2", "level3"]:
            grid = self.grids[grid_key]
            if grid.level == 0:
                grid.add_line("  ⚠️  NO PROTECTION ACTIVE", COLORS["red"])
            elif grid.level == 1:
                grid.add_line("  ⚠️  PARTIAL PROTECTION (Docker only)", COLORS["amber"])
            elif grid.level >= 2:
                grid.add_line("  ✓ AEGIS PROTECTION ACTIVE", COLORS["green"])
            
            grid.add_line("", COLORS["text"])
            grid.add_line("  Ready for testing.", COLORS["text"])
        
        self.add_frame(int(FPS * 2))
    
    def render_outro(self):
        """Render outro with summary and final score."""
        for grid in self.grids.values():
            grid.clear()
            grid.add_line("", COLORS["text"])
            grid.add_line("", COLORS["text"])
        
        self.add_frame(int(FPS * 1))
        
        # Summary scores
        scores = {
            "level0": ("5/5 ATTACKS SUCCEEDED", COLORS["red"], "VULNERABLE"),
            "level1": ("3/5 ATTACKS SUCCEEDED", COLORS["amber"], "PARTIAL"),
            "level2": ("0/5 ATTACKS SUCCEEDED", COLORS["green"], "PROTECTED"),
            "level3": ("0/5 ATTACKS SUCCEEDED", COLORS["green"], "FULL PROTECTION"),
        }
        
        for grid_key, (score, color, status) in scores.items():
            grid = self.grids[grid_key]
            grid.add_line("═" * 60, color)
            grid.add_line("", COLORS["text"])
            grid.add_line(f"  FINAL SCORE:", COLORS["cyan"])
            grid.add_line(f"  {score}", color)
            grid.add_line("", COLORS["text"])
            grid.add_line(f"  Security Status: {status}", color)
            grid.add_line("", COLORS["text"])
            grid.add_line("═" * 60, color)
            
            # Add appropriate icon
            if grid.level == 0:
                self.draw_ascii_icon(grid_key, "skull")
            elif grid.level == 1:
                self.draw_ascii_icon(grid_key, "warning")
            else:
                self.draw_ascii_icon(grid_key, "shield")
        
        self.add_frame(int(FPS * 4))
        
        # Final message
        for grid in self.grids.values():
            grid.add_line("", COLORS["text"])
            grid.add_line("", COLORS["text"])
        
        # Level 2 and 3 show success message
        self.grids["level2"].add_line("  Protect Your AI Agents", COLORS["green"])
        self.grids["level2"].add_line("  github.com/hermes-aegis", COLORS["cyan"])
        
        self.grids["level3"].add_line("  Defense In Depth", COLORS["green"])
        self.grids["level3"].add_line("  Vault + Scanning + Isolation", COLORS["cyan"])
        
        self.add_frame(int(FPS * 3))
    
    def save_frames(self):
        """Save frames as images."""
        print(f"Saving {len(self.frames)} frames as images...")
        
        frame_dir = self.output_path.parent / "frames_v2"
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
        print("Rendering hermes-aegis demo video V2 (Enhanced)...")
        
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
        
        # Save frames
        self.save_frames()


def main():
    # Load attacks
    from attack_prompts import get_all_attacks
    attacks = get_all_attacks()
    
    # Render demo
    renderer = DemoRenderer("output/aegis_demo_v2.mp4")
    renderer.render_full_demo(attacks)


if __name__ == "__main__":
    main()
