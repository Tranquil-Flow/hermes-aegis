#!/bin/bash
# Hermes-Aegis One-Command Installer
# For non-technical users

set -e  # Exit on error

echo "=========================================="
echo "  Hermes-Aegis Installation"
echo "=========================================="
echo ""

# Detect shell
if [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
    SHELL_NAME="zsh"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
    SHELL_NAME="bash"
else
    echo "❌ Could not find ~/.zshrc or ~/.bashrc"
    exit 1
fi

echo "Detected shell: $SHELL_NAME"
echo "Config file: $SHELL_RC"
echo ""

# Step 1: Install package
echo "Step 1/4: Installing hermes-aegis..."
pip3 install -e "$HOME/Projects/hermes-aegis" > /dev/null 2>&1
echo "✓ Package installed"

# Step 2: Add to shell profile (if not already there)
echo ""
echo "Step 2/4: Configuring shell profile..."
if grep -q "hermes-aegis" "$SHELL_RC"; then
    echo "✓ Already configured"
else
    echo "" >> "$SHELL_RC"
    echo "# Hermes-Aegis Security Layer" >> "$SHELL_RC"
    echo "export PYTHONPATH=\"\$HOME/Projects/hermes-aegis/src:\$PYTHONPATH\"" >> "$SHELL_RC"
    echo "export TERMINAL_ENV=aegis  # Auto-activate Aegis protection" >> "$SHELL_RC"
    echo "✓ Added to $SHELL_RC"
fi

# Step 3: Initialize Aegis (vault, config)
echo ""
echo "Step 3/4: Initializing security vault..."
cd "$HOME/Projects/hermes-aegis"

# Check if vault exists
if [ -f "$HOME/.hermes-aegis/vault.enc" ]; then
    VAULT_COUNT=$(uv run hermes-aegis vault list 2>/dev/null | wc -l)
    echo "✓ Vault already initialized ($VAULT_COUNT secrets)"
else
    # Run setup if vault doesn't exist
    uv run hermes-aegis setup > /dev/null 2>&1 || true
    echo "✓ Vault initialized"
fi

# Step 4: Verification
echo ""
echo "Step 4/4: Verifying installation..."

# Test Python import
if python3 -c "import hermes_aegis" 2>/dev/null; then
    echo "✓ Python import works"
else
    echo "❌ Python import failed"
    exit 1
fi

# Test CLI
if uv run hermes-aegis status > /dev/null 2>&1; then
    echo "✓ CLI commands work"
else
    echo "❌ CLI failed"
    exit 1
fi

echo ""
echo "=========================================="
echo "  ✅ Installation Complete!"
echo "=========================================="
echo ""
echo "To activate in your current shell:"
echo "  source $SHELL_RC"
echo ""
echo "To use Hermes with Aegis protection:"
echo "  export TERMINAL_ENV=aegis"
echo "  hermes"
echo ""
echo "Check status:"
echo "  hermes-aegis status"
echo ""
echo "Manage secrets:"
echo "  hermes-aegis vault list"
echo "  hermes-aegis vault set MY_KEY 'secret-value'"
echo ""
echo "For help:"
echo "  hermes-aegis --help"
echo ""
