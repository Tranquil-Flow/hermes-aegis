#!/bin/bash
# Quick verification that Aegis banner integration is working

echo "=== Aegis Banner Integration Check ==="
echo ""

# Check TERMINAL_ENV
if [ "$TERMINAL_ENV" = "aegis" ]; then
    echo "✓ TERMINAL_ENV=aegis is set"
else
    echo "✗ TERMINAL_ENV not set or wrong value: $TERMINAL_ENV"
    echo "  Add to ~/.zshrc or ~/.bashrc:"
    echo "  export TERMINAL_ENV=aegis"
    exit 1
fi

# Check sitecustomize for Hermes Python
HERMES_PYTHON="$HOME/.hermes/hermes-agent/venv/bin/python3"
if [ ! -f "$HERMES_PYTHON" ]; then
    echo "✗ Hermes venv Python not found at $HERMES_PYTHON"
    exit 1
fi

PYTHON_VERSION=$("$HERMES_PYTHON" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
SITECUSTOMIZE="$HOME/.local/lib/python${PYTHON_VERSION}/site-packages/sitecustomize.py"

if [ -f "$SITECUSTOMIZE" ]; then
    if grep -q "Hermes-Aegis" "$SITECUSTOMIZE"; then
        echo "✓ sitecustomize.py installed ($SITECUSTOMIZE)"
    else
        echo "✗ sitecustomize.py exists but Aegis not found"
        exit 1
    fi
else
    echo "✗ sitecustomize.py not found at $SITECUSTOMIZE"
    echo "  Run: ~/.hermes/hermes-agent/venv/bin/python3 aegis-loader.py install"
    exit 1
fi

# Test that Aegis loads
echo ""
echo "Testing Aegis integration with Hermes Python..."
"$HERMES_PYTHON" -c "
import hermes_aegis.integration
result = hermes_aegis.integration.register_aegis_backend()
if result and hermes_aegis.integration._PATCHED:
    print('✓ Aegis backend registered successfully')
else:
    print('✗ Aegis backend registration failed')
    exit(1)
" 2>/dev/null

if [ $? -eq 0 ]; then
    echo ""
    echo "=========================================="
    echo "  Aegis banner integration is READY!"
    echo "=========================================="
    echo ""
    echo "Start a new Hermes session to see:"
    echo "  Security: Aegis Tier X 🛡️"
    echo ""
    echo "appearing in the welcome banner."
else
    echo "✗ Integration test failed"
    exit 1
fi
