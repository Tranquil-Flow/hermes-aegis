#!/bin/bash
# Debug Aegis Installation

echo "=========================================="
echo "  Aegis Installation Debug"
echo "=========================================="
echo ""

echo "1. Shell Configuration:"
echo "   Current shell: $SHELL"
echo "   Running: $(ps -p $$ -o comm=)"
echo ""

echo "2. Environment Variables:"
echo "   TERMINAL_ENV = $TERMINAL_ENV"
if [ "$TERMINAL_ENV" = "aegis" ]; then
    echo "   ✓ Correct!"
else
    echo "   ✗ Should be 'aegis', is '$TERMINAL_ENV'"
fi
echo ""

echo "   PYTHONPATH = $PYTHONPATH"
if [[ "$PYTHONPATH" == *"hermes-aegis"* ]]; then
    echo "   ✓ Contains hermes-aegis"
else
    echo "   ✗ Missing hermes-aegis path"
fi
echo ""

echo "3. Config Files:"
if [ -f ~/.zshrc ]; then
    if grep -q "TERMINAL_ENV=aegis" ~/.zshrc; then
        echo "   ✓ ~/.zshrc has TERMINAL_ENV=aegis"
    else
        echo "   ✗ ~/.zshrc missing TERMINAL_ENV=aegis"
    fi
fi

if [ -f ~/.bashrc ]; then
    if grep -q "TERMINAL_ENV=aegis" ~/.bashrc; then
        echo "   ✓ ~/.bashrc has TERMINAL_ENV=aegis"
    else
        echo "   ✗ ~/.bashrc missing TERMINAL_ENV=aegis"
    fi
fi
echo ""

echo "4. Auto-Loader:"
SITECUSTOMIZE="$HOME/Library/Python/3.13/lib/python/site-packages/sitecustomize.py"
if [ -f "$SITECUSTOMIZE" ]; then
    echo "   ✓ sitecustomize.py exists"
else
    echo "   ✗ sitecustomize.py not found"
fi
echo ""

echo "5. Aegis Status:"
cd ~/Projects/hermes-aegis
uv run hermes-aegis status
echo ""

echo "=========================================="
echo "  Fix Commands"
echo "=========================================="
echo ""
if [ "$TERMINAL_ENV" != "aegis" ]; then
    echo "Run this in your terminal:"
    echo "  source ~/.zshrc"
    echo "  echo \$TERMINAL_ENV"
    echo ""
fi

echo "Then try Hermes again:"
echo "  hermes"
echo ""
