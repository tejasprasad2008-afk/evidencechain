#!/usr/bin/env bash
# EvidenceChain installer for SANS SIFT Workstation
# Usage: bash install.sh [--with-keys]
#
# This script:
#   1. Verifies we're on a SIFT Workstation (or Ubuntu/Debian)
#   2. Installs Python 3.10+ and pip if needed
#   3. Installs the evidencechain package in editable mode
#   4. Verifies SIFT forensic tools are available
#   5. Creates working directories
#   6. Runs smoke tests
#   7. Prints MCP configuration for the agent

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[-]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "========================================"
echo "  EvidenceChain Installer"
echo "  Autonomous Forensic Investigation"
echo "========================================"
echo ""

# -----------------------------------------------------------------------
# Step 1: System check
# -----------------------------------------------------------------------
info "Checking system..."

if [ -f /etc/sift-version ] || [ -f /etc/sift/version ]; then
    ok "SIFT Workstation detected"
elif [ -f /etc/debian_version ]; then
    warn "Not a SIFT Workstation, but Debian/Ubuntu detected. Proceeding."
else
    warn "Not a SIFT Workstation. Some forensic tools may be missing."
fi

# -----------------------------------------------------------------------
# Step 2: Python check
# -----------------------------------------------------------------------
info "Checking Python..."

PYTHON=""
for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" &>/dev/null; then
        ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            PYTHON="$candidate"
            ok "Found $candidate ($ver)"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    fail "Python 3.10+ is required but not found."
    info "Install with: sudo apt-get install python3.11 python3.11-venv python3-pip"
    exit 1
fi

# -----------------------------------------------------------------------
# Step 3: Install evidencechain
# -----------------------------------------------------------------------
info "Installing EvidenceChain..."

cd "$SCRIPT_DIR"

# Create virtual environment if not in one
if [ -z "${VIRTUAL_ENV:-}" ]; then
    if [ ! -d ".venv" ]; then
        info "Creating virtual environment..."
        "$PYTHON" -m venv .venv
    fi
    # shellcheck disable=SC1091
    source .venv/bin/activate
    ok "Virtual environment activated"
fi

pip install --quiet --upgrade pip
pip install --quiet -e ".[dev]"
ok "EvidenceChain installed"

# -----------------------------------------------------------------------
# Step 4: Verify SIFT forensic tools
# -----------------------------------------------------------------------
info "Checking forensic tools..."

TOOLS_OK=0
TOOLS_MISSING=0

check_tool() {
    if command -v "$1" &>/dev/null; then
        ok "  $1"
        TOOLS_OK=$((TOOLS_OK + 1))
    else
        warn "  $1 — not found (install SIFT Workstation for full functionality)"
        TOOLS_MISSING=$((TOOLS_MISSING + 1))
    fi
}

# Disk tools
check_tool "fls"
check_tool "mactime"
check_tool "yara"

# Memory tools
check_tool "vol3" || check_tool "vol.py" || true

# EZ Tools (may be in /opt or /usr/local)
for tool in MFTECmd PECmd AmcacheParser EvtxECmd RECmd; do
    if command -v "$tool" &>/dev/null || [ -f "/opt/EZTools/$tool" ] || [ -f "/usr/local/bin/$tool" ]; then
        ok "  $tool"
        TOOLS_OK=$((TOOLS_OK + 1))
    else
        warn "  $tool — not found"
        TOOLS_MISSING=$((TOOLS_MISSING + 1))
    fi
done

# Plaso
check_tool "log2timeline.py"
check_tool "psort.py"

echo ""
info "Tools: $TOOLS_OK found, $TOOLS_MISSING missing"

if [ "$TOOLS_MISSING" -gt 0 ]; then
    warn "Some tools are missing. Install SIFT: curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash"
fi

# -----------------------------------------------------------------------
# Step 5: Create working directories
# -----------------------------------------------------------------------
info "Creating working directories..."

mkdir -p /cases 2>/dev/null || warn "/cases directory requires sudo (create manually)"
mkdir -p ./analysis/exports ./analysis/audit ./reports

ok "Directories ready"

# -----------------------------------------------------------------------
# Step 6: Run smoke tests
# -----------------------------------------------------------------------
info "Running smoke tests..."

TESTS_PASSED=0
TESTS_FAILED=0

for testfile in tests/test_block*.py; do
    if [ -f "$testfile" ]; then
        name=$(basename "$testfile" .py)
        if "$PYTHON" "$testfile" >/dev/null 2>&1; then
            ok "  $name"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            fail "  $name"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
done

echo ""
if [ "$TESTS_FAILED" -eq 0 ]; then
    ok "All $TESTS_PASSED test suites passed"
else
    fail "$TESTS_FAILED test suite(s) failed out of $((TESTS_PASSED + TESTS_FAILED))"
fi

# -----------------------------------------------------------------------
# Step 7: Optional API keys
# -----------------------------------------------------------------------
if [ "${1:-}" = "--with-keys" ]; then
    echo ""
    info "Configure threat intelligence API keys (optional, press Enter to skip):"
    read -rp "  VirusTotal API key: " VT_KEY
    read -rp "  AbuseIPDB API key: " ABUSEIPDB_KEY
    read -rp "  AlienVault OTX key: " OTX_KEY

    cat > .env <<ENVEOF
VT_API_KEY=${VT_KEY}
ABUSEIPDB_API_KEY=${ABUSEIPDB_KEY}
OTX_API_KEY=${OTX_KEY}
ENVEOF
    ok "API keys saved to .env"
fi

# -----------------------------------------------------------------------
# Step 8: Print MCP configuration
# -----------------------------------------------------------------------
echo ""
echo "========================================"
echo "  Installation Complete"
echo "========================================"
echo ""
info "Add this to your agent's MCP configuration:"
echo ""
cat <<MCPEOF
{
  "mcpServers": {
    "evidencechain": {
      "command": "$SCRIPT_DIR/.venv/bin/python3",
      "args": ["-m", "evidencechain"],
      "cwd": "$SCRIPT_DIR/src",
      "env": {
        "EVIDENCE_BASE_DIR": "/cases"
      }
    }
  }
}
MCPEOF

echo ""
info "To start investigating:"
echo "  1. Place evidence in /cases/"
echo "  2. Start your AI agent with the MCP config above"
echo "  3. The agent will use the 21 forensic tools to analyze the evidence"
echo ""
ok "Ready to find evil."
