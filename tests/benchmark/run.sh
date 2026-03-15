#!/usr/bin/env bash
# Run the full Aegis red-team security benchmark.
# Usage: ./tests/benchmark/run.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Auto-detect python: prefer .venv, fall back to system
if [ -x "$PROJECT_ROOT/.venv/bin/python" ]; then
    PYTHON="$PROJECT_ROOT/.venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON=python3
else
    echo "ERROR: No python found. Create a venv or install python3." >&2
    exit 1
fi

echo "Using: $PYTHON"
echo ""

# Run the benchmark harness
cd "$PROJECT_ROOT"
PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" \
    exec "$PYTHON" -m tests.benchmark.harness "$@"
