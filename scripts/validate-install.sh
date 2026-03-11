#!/bin/bash
# Validate hermes-aegis installation and basic functionality

set -e

echo "════════════════════════════════════════════════════════════"
echo "Hermes Aegis Installation Validator"
echo "════════════════════════════════════════════════════════════"
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track results
PASSED=0
FAILED=0

check() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $1"
        ((PASSED++))
    else
        echo -e "${RED}✗${NC} $1"
        ((FAILED++))
    fi
}

# 1. Check Python version
echo "Checking Python version..."
python3 --version | grep -E "3\.(10|11|12|13)" > /dev/null
check "Python 3.10+ installed"

# 2. Check hermes-aegis is importable
echo ""
echo "Checking hermes-aegis package..."
python3 -c "import hermes_aegis" 2>/dev/null
check "hermes-aegis package importable"

# 3. Check CLI is available
echo ""
echo "Checking CLI..."
which hermes-aegis > /dev/null 2>&1 || python3 -m hermes_aegis.cli --help > /dev/null 2>&1
check "hermes-aegis CLI available"

# 4. Check dependencies
echo ""
echo "Checking dependencies..."
python3 -c "import click" 2>/dev/null
check "click installed"

python3 -c "import cryptography" 2>/dev/null
check "cryptography installed"

python3 -c "import keyring" 2>/dev/null
check "keyring installed"

python3 -c "import nest_asyncio" 2>/dev/null
check "nest_asyncio installed"

python3 -c "import pytest" 2>/dev/null
check "pytest installed (dev dependency)"

# 5. Check tier detection
echo ""
echo "Checking tier detection..."
TIER=$(hermes-aegis status 2>/dev/null | grep "Tier:" | awk '{print $2}' || echo "0")
if [ "$TIER" = "1" ] || [ "$TIER" = "2" ]; then
    check "Tier detection working (detected Tier $TIER)"
else
    check "Tier detection FAILED"
fi

# 6. Check Docker (optional)
echo ""
echo "Checking Docker availability (optional)..."
if docker info > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Docker available (Tier 2 capable)"
    DOCKER_OK=true
else
    echo -e "${YELLOW}⚠${NC} Docker not available (Tier 1 only)"
    DOCKER_OK=false
fi

# 7. Check file structure
echo ""
echo "Checking file structure..."
[ -f "pyproject.toml" ]
check "pyproject.toml exists"

[ -f "src/hermes_aegis/__init__.py" ]
check "Package __init__.py exists"

[ -f "src/hermes_aegis/cli.py" ]
check "CLI module exists"

[ -f "src/hermes_aegis/detect.py" ]
check "detect.py exists"

[ -f "docs/IMPLEMENTATION-PLAN.md" ]
check "Implementation plan exists"

[ -f "docs/DESIGN.md" ]
check "Design doc exists"

# 8. Test basic CLI commands
echo ""
echo "Testing CLI commands..."
hermes-aegis --help > /dev/null 2>&1
check "hermes-aegis --help works"

hermes-aegis status > /dev/null 2>&1
check "hermes-aegis status works"

# 9. Check Git repository
echo ""
echo "Checking Git repository..."
[ -d ".git" ]
check "Git repository initialized"

COMMITS=$(git log --oneline 2>/dev/null | wc -l | tr -d ' ')
if [ "$COMMITS" -gt 0 ]; then
    check "Git has commits ($COMMITS commits)"
else
    check "Git repository FAILED"
fi

# Summary
echo ""
echo "════════════════════════════════════════════════════════════"
echo "Validation Summary"
echo "════════════════════════════════════════════════════════════"
echo -e "${GREEN}Passed: $PASSED${NC}"
[ $FAILED -gt 0 ] && echo -e "${RED}Failed: $FAILED${NC}" || echo -e "Failed: 0"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed! hermes-aegis is ready.${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Review implementation plan: cat docs/IMPLEMENTATION-PLAN.md"
    echo "  2. Start implementation: Begin with Task 2 (Encrypted Vault)"
    echo "  3. Run tests as you go: pytest tests/ -v"
    echo ""
    if [ "$DOCKER_OK" = true ]; then
        echo "Docker is available — you can build Tier 2 features."
    else
        echo "Docker not available — focus on Tier 1 features first."
    fi
    exit 0
else
    echo -e "${RED}✗ Some checks failed. Please fix issues above.${NC}"
    exit 1
fi
