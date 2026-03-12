#!/usr/bin/env bash
# Red Team Comparison Demo — 3 tiers of security
# Shows the same 9 attacks across: local, unprotected Docker, Aegis-hardened Docker
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RED_TEAM_SCRIPT="$SCRIPT_DIR/tests/red_team/malicious_agent.py"

# Find a local image with Python
IMAGE=""
AVAILABLE=$(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null)
for candidate in "ofac-auto-updater:latest" "ofac-auto-updater:test"; do
    if echo "$AVAILABLE" | grep -q "^${candidate}$"; then
        IMAGE="$candidate"
        break
    fi
done

if [ -z "$IMAGE" ]; then
    echo "No Python-capable Docker image found locally."
    echo "Available images:"
    echo "$AVAILABLE" | head -10
    exit 1
fi

echo ""
echo -e "${BOLD}${CYAN}  =========================================================${NC}"
echo -e "${BOLD}${CYAN}   Red Team Attack Simulation -- 3-Tier Comparison${NC}"
echo -e "${BOLD}${CYAN}   Same 9 attacks. Three environments. Watch the diff.${NC}"
echo -e "${BOLD}${CYAN}  =========================================================${NC}"
echo ""
sleep 1

# ===================================================================
# PHASE 1: LOCAL -- no container, no Aegis, just raw host
# ===================================================================
echo -e "${BOLD}${RED}  ---------------------------------------------------------${NC}"
echo -e "${BOLD}${RED}  PHASE 1: LOCAL EXECUTION (no container, no Aegis)${NC}"
echo -e "${BOLD}${RED}  ---------------------------------------------------------${NC}"
echo -e "${DIM}  Running directly on host -- full access to everything${NC}"
echo ""

# Run locally but with fake secrets in env (don't leak real ones in output)
LOCAL_OUTPUT=$(OPENAI_API_KEY="sk-proj-FAKE1234567890abcdefghijklmnop" \
    ANTHROPIC_API_KEY="sk-ant-api03-FAKE1234567890abcdef" \
    SECRET_PASSWORD="hunter2" \
    python3 "$RED_TEAM_SCRIPT" 2>&1 || true)

echo "$LOCAL_OUTPUT"
echo ""

LOCAL_FAILS=$(echo "$LOCAL_OUTPUT" | grep -c '"status": "FAIL"' || true)
LOCAL_PROTECTED=$(echo "$LOCAL_OUTPUT" | grep -c '"status": "PROTECTED"' || true)

echo -e "${RED}  Result: ${LOCAL_FAILS}/12 attacks SUCCEEDED, ${LOCAL_PROTECTED}/12 blocked${NC}"
echo ""
sleep 2

# ===================================================================
# PHASE 2: DOCKER -- container but no hardening
# ===================================================================
echo -e "${BOLD}${YELLOW}  ---------------------------------------------------------${NC}"
echo -e "${BOLD}${YELLOW}  PHASE 2: DOCKER CONTAINER (no Aegis hardening)${NC}"
echo -e "${BOLD}${YELLOW}  ---------------------------------------------------------${NC}"
echo -e "${DIM}  Running in container: default network, secrets in env, full caps${NC}"
echo ""

DOCKER_OUTPUT=$(docker run --rm --platform linux/amd64 \
    -v "$RED_TEAM_SCRIPT:/workspace/malicious_agent.py:ro" \
    -e "OPENAI_API_KEY=sk-proj-FAKE1234567890abcdefghijklmnop" \
    -e "ANTHROPIC_API_KEY=sk-ant-api03-FAKE1234567890abcdef" \
    -e "SECRET_PASSWORD=hunter2" \
    "$IMAGE" \
    python3 /workspace/malicious_agent.py 2>&1 || true)

echo "$DOCKER_OUTPUT"
echo ""

DOCKER_FAILS=$(echo "$DOCKER_OUTPUT" | grep -c '"status": "FAIL"' || true)
DOCKER_PROTECTED=$(echo "$DOCKER_OUTPUT" | grep -c '"status": "PROTECTED"' || true)

echo -e "${YELLOW}  Result: ${DOCKER_FAILS}/12 attacks SUCCEEDED, ${DOCKER_PROTECTED}/12 blocked${NC}"
echo ""
sleep 2

# ===================================================================
# PHASE 3: AEGIS -- hardened container with all defenses
# ===================================================================
echo -e "${BOLD}${GREEN}  ---------------------------------------------------------${NC}"
echo -e "${BOLD}${GREEN}  PHASE 3: AEGIS-PROTECTED CONTAINER${NC}"
echo -e "${BOLD}${GREEN}  ---------------------------------------------------------${NC}"
echo -e "${DIM}  Running with: internal network, no secrets, caps dropped, read-only FS${NC}"
echo ""

# Create internal network
NETWORK="aegis-demo-net"
docker network create --internal --driver bridge "$NETWORK" &>/dev/null 2>&1 || true

AEGIS_OUTPUT=$(docker run --rm --platform linux/amd64 \
    -v "$RED_TEAM_SCRIPT:/workspace/malicious_agent.py:ro" \
    --network "$NETWORK" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --read-only \
    --tmpfs /tmp:size=64m \
    --pids-limit 256 \
    --memory 512m \
    "$IMAGE" \
    python3 /workspace/malicious_agent.py 2>&1 || true)

echo "$AEGIS_OUTPUT"
echo ""

# Cleanup
docker network rm "$NETWORK" &>/dev/null 2>&1 || true

AEGIS_FAILS=$(echo "$AEGIS_OUTPUT" | grep -c '"status": "FAIL"' || true)
AEGIS_PROTECTED=$(echo "$AEGIS_OUTPUT" | grep -c '"status": "PROTECTED"' || true)

echo -e "${GREEN}  Result: ${AEGIS_FAILS}/12 attacks succeeded, ${AEGIS_PROTECTED}/12 BLOCKED${NC}"
echo ""

# ===================================================================
# COMPARISON TABLE
# ===================================================================
echo -e "${BOLD}${CYAN}  ---------------------------------------------------------${NC}"
echo -e "${BOLD}${CYAN}  COMPARISON${NC}"
echo -e "${BOLD}${CYAN}  ---------------------------------------------------------${NC}"
echo ""
echo -e "  ${RED}LOCAL  (no protection):   ${LOCAL_FAILS}/12 attacks succeeded${NC}"
echo -e "  ${YELLOW}DOCKER (no hardening):    ${DOCKER_FAILS}/12 attacks succeeded${NC}"
echo -e "  ${GREEN}AEGIS  (full protection): ${AEGIS_FAILS}/12 attacks succeeded  (${AEGIS_PROTECTED}/12 blocked)${NC}"
echo ""

# Helper: color a status word
color_status() {
    if [ "$1" = "FAIL" ]; then
        printf "${RED}FAIL${NC}"
    else
        printf "${GREEN}SAFE${NC}"
    fi
}

# Parse results from each phase for side-by-side
ATTACKS=("env_secrets" "vault_read" "http_exfil" "direct_tcp" "dns_tunnel" "raw_socket" "curl_exfil" "fs_escape" "ssh_read" "supply_chain" "chunked_exfil" "reverse_shell")
LABELS=("Env secrets   " "Vault access  " "HTTP exfil    " "Direct TCP    " "DNS tunneling " "Raw socket    " "Curl exfil    " "FS escape     " "SSH key read  " "Supply chain  " "Chunked exfil " "Reverse shell ")

# Column layout: 2 indent + 18 label + 10 col + 10 col + 10 col
echo -e "${BOLD}  Attack breakdown:${NC}"
echo ""
echo -e "  ATTACK                ${RED}Local${NC}     ${YELLOW}Docker${NC}    ${GREEN}Aegis${NC}"
echo -e "  ${DIM}------------------  --------  --------  --------${NC}"

for i in "${!ATTACKS[@]}"; do
    attack="${ATTACKS[$i]}"
    label="${LABELS[$i]}"

    local_status="FAIL"
    echo "$LOCAL_OUTPUT" | grep -q "\"$attack\"" && {
        echo "$LOCAL_OUTPUT" | grep -A2 "\"$attack\"" | grep -q '"PROTECTED"' && local_status="SAFE"
    }
    docker_status="FAIL"
    echo "$DOCKER_OUTPUT" | grep -q "\"$attack\"" && {
        echo "$DOCKER_OUTPUT" | grep -A2 "\"$attack\"" | grep -q '"PROTECTED"' && docker_status="SAFE"
    }
    aegis_status="FAIL"
    echo "$AEGIS_OUTPUT" | grep -q "\"$attack\"" && {
        echo "$AEGIS_OUTPUT" | grep -A2 "\"$attack\"" | grep -q '"PROTECTED"' && aegis_status="SAFE"
    }

    # label is 14 chars, pad to 18 with extra 4 spaces, then 10-wide columns (FAIL/SAFE=4 + 6 pad)
    echo -e "  ${label}        $(color_status $local_status)      $(color_status $docker_status)      $(color_status $aegis_status)"
done

echo -e "  ${DIM}------------------  --------  --------  --------${NC}"
echo ""
echo -e "${BOLD}${GREEN}  =========================================================${NC}"
echo -e "${BOLD}${GREEN}  Local:  ${LOCAL_FAILS}/12 attacks succeed -- your keys are exposed${NC}"
echo -e "${BOLD}${GREEN}  Docker: ${DOCKER_FAILS}/12 attacks succeed -- containers aren't enough${NC}"
echo -e "${BOLD}${GREEN}  Aegis:  ${AEGIS_FAILS}/12 attacks succeed -- defense in depth works${NC}"
echo -e "${BOLD}${GREEN}${NC}"
echo -e "${BOLD}${GREEN}  Aegis adds: encrypted vault, MITM proxy key injection,${NC}"
echo -e "${BOLD}${GREEN}  internal network, read-only FS, dropped capabilities,${NC}"
echo -e "${BOLD}${GREEN}  SHA-256 audit trail, BIP39 seed phrase detection.${NC}"
echo -e "${BOLD}${GREEN}  =========================================================${NC}"
echo ""
