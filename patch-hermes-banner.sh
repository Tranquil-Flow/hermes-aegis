#!/bin/bash
# Patch Hermes banner.py to show Aegis status
# Run this after updating Hermes to reapply the patch

BANNER_FILE="$HOME/.hermes/hermes-agent/hermes_cli/banner.py"

if [ ! -f "$BANNER_FILE" ]; then
    echo "Error: Hermes banner.py not found at $BANNER_FILE"
    exit 1
fi

# Check if already patched
if grep -q "Aegis security status" "$BANNER_FILE"; then
    echo "✓ Banner already patched with Aegis status"
    exit 0
fi

echo "Patching Hermes banner to show Aegis status..."

# Create backup
cp "$BANNER_FILE" "$BANNER_FILE.backup"

# Apply patch using Python to be safe
python3 << 'EOF'
import sys

banner_file = sys.argv[1]
with open(banner_file, 'r') as f:
    content = f.read()

# Find the insertion point
search_str = '''    left_lines.append(f"[dim {dim}]{cwd}[/]")
    if session_id:
        left_lines.append(f"[dim {session_color}]Session: {session_id}[/]")
    left_content = "\\n".join(left_lines)'''

replacement = '''    left_lines.append(f"[dim {dim}]{cwd}[/]")
    if session_id:
        left_lines.append(f"[dim {session_color}]Session: {session_id}[/]")
    
    # Add Aegis security status if active
    if os.getenv("TERMINAL_ENV") == "aegis":
        try:
            from hermes_aegis.detect import detect_tier
            tier = detect_tier()
            left_lines.append(f"[bold cyan]Security: Aegis Tier {tier} 🛡️[/]")
        except:
            pass  # Aegis not available, skip
    
    left_content = "\\n".join(left_lines)'''

if search_str in content:
    content = content.replace(search_str, replacement)
    with open(banner_file, 'w') as f:
        f.write(content)
    print("✓ Patch applied successfully")
else:
    print("✗ Could not find insertion point - Hermes banner may have changed")
    print("  Manual patching required")
    sys.exit(1)
EOF

python3 "$BANNER_FILE.backup" "$BANNER_FILE"

echo ""
echo "Backup saved to: $BANNER_FILE.backup"
echo "Patch complete! Start a new Hermes session to see the Aegis status."
