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

# Install Python dependencies
echo -e "${BLUE}🐍 Installing Python dependencies...${NC}"
pip3 install --user -r requirements.txt

echo -e "${GREEN}✅ Setup complete!${NC}"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo "  python3 NetHawk.py                    # Run NetHawk"
echo "  python3 NetHawk.py --help             # Show help"
echo "  sudo python3 NetHawk.py               # Run with full privileges"
echo ""
echo -e "${BLUE}That's it! Simple and easy! 🦅${NC}"
