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
echo -e "${BLUE}📦 Installing NetHawk dependencies...${NC}"
sudo apt update
sudo apt install -y python3 python3-pip aircrack-ng iw iproute2 nmap masscan nikto gobuster enum4linux samba-client dnsutils

# Verify tools are available
echo -e "${BLUE}🔍 Verifying NetHawk tools...${NC}"
tools=("airodump-ng" "nmap" "masscan" "nikto" "gobuster" "enum4linux")
for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ $tool is available${NC}"
    else
        echo -e "${YELLOW}⚠️  $tool not found${NC}"
    fi
done

# Install Python dependencies
echo -e "${BLUE}🐍 Installing Python dependencies...${NC}"

# Always use pip (not pip3) and never use --user in virtual environments
if pip install -r requirements.txt; then
    echo -e "${GREEN}✅ Python dependencies installed successfully${NC}"
else
    echo -e "${RED}❌ Failed to install Python dependencies${NC}"
    echo -e "${BLUE}💡 Manual installation:${NC}"
    echo "  pip install rich psutil requests"
    exit 1
fi

echo -e "${GREEN}✅ NetHawk setup complete!${NC}"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo "  python3 NetHawk.py                    # Run NetHawk"
echo "  sudo python3 NetHawk.py               # Run with full privileges"
echo ""
echo -e "${BLUE}NetHawk is ready! 🦅${NC}"