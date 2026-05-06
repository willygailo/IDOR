#!/bin/bash
# ============================================================
# IDOR Bug Bounty Workspace — Setup Script
# ============================================================
# Installs Python venv and all required dependencies.
# Run once before using any scripts.
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh

set -e

GREEN="\033[92m"
CYAN="\033[96m"
YELLOW="\033[93m"
RED="\033[91m"
BOLD="\033[1m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "╔══════════════════════════════════════════╗"
echo "║    IDOR Workspace Setup                  ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${RESET}"

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] Python 3 not found. Install it first: sudo apt install python3${RESET}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
echo -e "${GREEN}[+] Found: $PYTHON_VERSION${RESET}"

# Create virtual environment
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}[*] Creating virtual environment...${RESET}"
    python3 -m venv venv
    echo -e "${GREEN}[+] venv created${RESET}"
else
    echo -e "${GREEN}[+] venv already exists${RESET}"
fi

# Activate and install
echo -e "${YELLOW}[*] Installing dependencies...${RESET}"
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo -e "${GREEN}[+] Dependencies installed${RESET}"

# Make scripts executable
chmod +x poc/scripts/*.py
chmod +x run.py

echo ""
echo -e "${GREEN}${BOLD}[✓] Setup complete!${RESET}"
echo ""
echo -e "  To activate the environment:"
echo -e "    ${CYAN}source venv/bin/activate${RESET}"
echo ""
echo -e "  To launch the main menu:"
echo -e "    ${CYAN}python3 run.py${RESET}"
echo ""
