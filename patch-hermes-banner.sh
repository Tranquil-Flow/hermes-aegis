#!/bin/bash
# Patch Hermes to show Aegis status in the welcome banner
# Run this after updating Hermes to reapply the patches

set -e

echo "=========================================="
echo "  Patching Hermes for Aegis Banner"
echo "=========================================="
echo ""

# Patch 1: cli.py (main banner function used in CLI)
CLI_FILE="$HOME/.hermes/hermes-agent/cli.py"
if [ ! -f "$CLI_FILE" ]; then
    echo "✗ cli.py not found at $CLI_FILE"
    exit 1
fi

if grep -q "Aegis security status" "$CLI_FILE"; then
    echo "✓ cli.py already patched"
else
    echo "Patching cli.py..."
    
    # Create backup
    cp "$CLI_FILE" "$CLI_FILE.backup-$(date +%Y%m%d-%H%M%S)"
    
    # Apply patch
    python3 << 'PATCH_CLI_PY'
import sys
with open(sys.argv[1], 'r') as f:
    content = f.read()

search = '''    # Add session ID if provided
    if session_id:
        left_lines.append(f"[dim {_session_c}]Session: {session_id}[/]")
    left_content = "\\n".join(left_lines)'''

replacement = '''    # Add session ID if provided
    if session_id:
        left_lines.append(f"[dim {_session_c}]Session: {session_id}[/]")
    
    # Add Aegis security status if active
    if os.getenv("TERMINAL_ENV") == "aegis":
        try:
            import sys
            aegis_path = os.path.join(os.path.expanduser('~'), 'Projects', 'hermes-aegis', 'src')
            if aegis_path not in sys.path:
                sys.path.insert(0, aegis_path)
            from hermes_aegis.detect import detect_tier
            tier = detect_tier()
            left_lines.append(f"[bold cyan]Security: Aegis Tier {tier} 🛡️[/]")
        except:
            pass  # Aegis not available, skip silently
    
    left_content = "\\n".join(left_lines)'''

if search in content:
    with open(sys.argv[1], 'w') as f:
        f.write(content.replace(search, replacement))
    print("✓ cli.py patched")
else:
    print("✗ Could not find insertion point in cli.py")
    sys.exit(1)
PATCH_CLI_PY
    
    python3 "$CLI_FILE" &> /dev/null
fi

echo ""

# Patch 2: hermes_cli/banner.py (fallback/alternate banner)
BANNER_FILE="$HOME/.hermes/hermes-agent/hermes_cli/banner.py"
if [ ! -f "$BANNER_FILE" ]; then
    echo "⚠ banner.py not found (optional)"
else
    if grep -q "Aegis security status" "$BANNER_FILE"; then
        echo "✓ banner.py already patched"
    else
        echo "Patching banner.py..."
        
        # Create backup
        cp "$BANNER_FILE" "$BANNER_FILE.backup-$(date +%Y%m%d-%H%M%S)"
        
        # Apply patch
        python3 << 'PATCH_BANNER_PY'
import sys
with open(sys.argv[1], 'r') as f:
    content = f.read()

search = '''    left_lines.append(f"[dim {dim}]{cwd}[/]")
    if session_id:
        left_lines.append(f"[dim {session_color}]Session: {session_id}[/]")
    left_content = "\\n".join(left_lines)'''

replacement = '''    left_lines.append(f"[dim {dim}]{cwd}[/]")
    if session_id:
        left_lines.append(f"[dim {session_color}]Session: {session_id}[/]")
    
    # Add Aegis security status if active
    if os.getenv("TERMINAL_ENV") == "aegis":
        try:
            import sys
            aegis_path = os.path.join(os.path.expanduser('~'), 'Projects', 'hermes-aegis', 'src')
            if aegis_path not in sys.path:
                sys.path.insert(0, aegis_path)
            from hermes_aegis.detect import detect_tier
            tier = detect_tier()
            left_lines.append(f"[bold cyan]Security: Aegis Tier {tier} 🛡️[/]")
        except:
            pass  # Aegis not available, skip silently
    
    left_content = "\\n".join(left_lines)'''

if search in content:
    with open(sys.argv[1], 'w') as f:
        f.write(content.replace(search, replacement))
    print("✓ banner.py patched")
else:
    print("⚠ Could not patch banner.py (may not be needed)")
PATCH_BANNER_PY
        
        python3 "$BANNER_FILE" &> /dev/null
    fi
fi

echo ""

# Clear Python cache
echo "Clearing Python cache..."
rm -f ~/.hermes/hermes-agent/__pycache__/cli.cpython-*.pyc
rm -f ~/.hermes/hermes-agent/hermes_cli/__pycache__/banner.cpython-*.pyc

echo ""
echo "=========================================="
echo "  ✓ Hermes Banner Patched!"
echo "=========================================="
echo ""
echo "Start a new terminal and run 'hermes' to see:"
echo "  Security: Aegis Tier X 🛡️"
echo ""
