#!/bin/bash
# NetHawk Simple Setup Script
# Just install dependencies and run the Python tool

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🦅 NetHawk Simple Setup${NC}"
echo -e "${YELLOW}Installing dependencies and setting up NetHawk...${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${RED}❌ Don't run as root!${NC}"
    exit 1
fi

# Install system dependencies
echo -e "${BLUE}📦 Installing system dependencies...${NC}"
sudo apt update
sudo apt install -y python3 python3-pip python3-venv aircrack-ng hashcat hcxtools iw iproute2 git wget

# Install additional tools for cap2hccapx
echo -e "${BLUE}🔧 Installing additional tools...${NC}"
sudo apt install -y hcxtools

# Check if cap2hccapx is available
echo -e "${BLUE}🔍 Verifying tools...${NC}"
if command -v cap2hccapx >/dev/null 2>&1; then
    echo -e "${GREEN}✅ cap2hccapx is available${NC}"
else
    echo -e "${YELLOW}⚠️  cap2hccapx not found in PATH${NC}"
    echo -e "${BLUE}🔍 Checking if hcxtools provides cap2hccapx...${NC}"
    
    # Try to refresh PATH
    hash -r
    
    # Check common locations
    if [ -f "/usr/bin/cap2hccapx" ]; then
        echo -e "${GREEN}✅ cap2hccapx found in /usr/bin/${NC}"
        echo -e "${BLUE}💡 Adding to PATH...${NC}"
        export PATH="/usr/bin:$PATH"
    elif [ -f "/usr/local/bin/cap2hccapx" ]; then
        echo -e "${GREEN}✅ cap2hccapx found in /usr/local/bin/${NC}"
        echo -e "${BLUE}💡 Adding to PATH...${NC}"
        export PATH="/usr/local/bin:$PATH"
    else
        echo -e "${YELLOW}⚠️  cap2hccapx not found, but hcxtools is installed${NC}"
        echo -e "${BLUE}💡 Try running: hash -r && which cap2hccapx${NC}"
        echo -e "${BLUE}💡 Or restart your terminal${NC}"
    fi
fi

# Install Python dependencies
echo -e "${BLUE}🐍 Installing Python dependencies...${NC}"
# Try multiple methods for Python dependency installation
if pip3 install --user -r requirements.txt 2>/dev/null; then
    echo -e "${GREEN}✅ Python dependencies installed with --user flag${NC}"
elif pip3 install --break-system-packages -r requirements.txt 2>/dev/null; then
    echo -e "${GREEN}✅ Python dependencies installed with --break-system-packages${NC}"
else
    echo -e "${YELLOW}⚠️  Failed to install Python dependencies automatically${NC}"
    echo -e "${BLUE}💡 Try one of these methods:${NC}"
    echo "  1. Create virtual environment: python3 -m venv nethawk_env && source nethawk_env/bin/activate && pip install -r requirements.txt"
    echo "  2. Use --break-system-packages: pip3 install --break-system-packages -r requirements.txt"
    echo "  3. Use --user flag: pip3 install --user -r requirements.txt"
fi

echo -e "${GREEN}✅ Setup complete!${NC}"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo "  python3 NetHawk.py                    # Run NetHawk"
echo "  python3 NetHawk.py --help             # Show help"
echo "  sudo python3 NetHawk.py               # Run with full privileges"
echo ""
echo -e "${BLUE}That's it! Simple and easy! 🦅${NC}"