#!/bin/bash
# NetHawk Manual Installation Script
# Step-by-step installation like a professional tool

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🦅 NetHawk Manual Installation${NC}"
echo -e "${YELLOW}Step-by-step installation like a professional tool...${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${RED}❌ Don't run as root!${NC}"
    exit 1
fi

# Step 1: Clone the Repository
echo -e "${BLUE}📥 Step 1: Cloning NetHawk repository...${NC}"
if [[ -d "NetHawk" ]]; then
    echo -e "${YELLOW}⚠️  NetHawk directory already exists. Removing...${NC}"
    rm -rf NetHawk
fi
git clone https://github.com/darky-boy/NetHawk.git
cd NetHawk
echo -e "${GREEN}✅ Repository cloned successfully${NC}"
echo ""

# Step 2: Install System Dependencies
echo -e "${BLUE}📦 Step 2: Installing system dependencies...${NC}"
sudo apt update
sudo apt install -y python3 python3-pip python3-venv aircrack-ng hashcat hcxtools iw iproute2 git wget
echo -e "${GREEN}✅ System dependencies installed${NC}"
echo ""

# Step 3: Create NetHawk Directory
echo -e "${BLUE}📁 Step 3: Creating NetHawk user directory...${NC}"
mkdir -p ~/.nethawk
echo -e "${GREEN}✅ User directory created: ~/.nethawk${NC}"
echo ""

# Step 4: Copy NetHawk Files
echo -e "${BLUE}📋 Step 4: Copying NetHawk files...${NC}"
cp -r * ~/.nethawk/
cd ~/.nethawk
echo -e "${GREEN}✅ Files copied to ~/.nethawk${NC}"
echo ""

# Step 5: Set Up Python Environment
echo -e "${BLUE}🐍 Step 5: Setting up Python environment...${NC}"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install rich psutil requests argparse
echo -e "${GREEN}✅ Python environment ready${NC}"
echo ""

# Step 6: Create Executable
echo -e "${BLUE}🔧 Step 6: Creating NetHawk executable...${NC}"
cat > nethawk << 'EOF'
#!/bin/bash
cd ~/.nethawk
source venv/bin/activate
python3 NetHawk.py "$@"
deactivate
EOF
chmod +x nethawk
echo -e "${GREEN}✅ Executable created${NC}"
echo ""

# Step 7: Install System-Wide
echo -e "${BLUE}🔗 Step 7: Installing system-wide...${NC}"
sudo ln -sf ~/.nethawk/nethawk /usr/local/bin/nethawk
echo -e "${GREEN}✅ System-wide installation complete${NC}"
echo ""

# Step 8: Test Installation
echo -e "${BLUE}🧪 Step 8: Testing installation...${NC}"
if nethawk --version >/dev/null 2>&1; then
    echo -e "${GREEN}✅ NetHawk installation successful!${NC}"
else
    echo -e "${YELLOW}⚠️  Installation completed with warnings${NC}"
fi
echo ""

# Show usage instructions
echo -e "${GREEN}🎉 NetHawk Installation Complete!${NC}"
echo ""
echo -e "${YELLOW}Usage Instructions:${NC}"
echo "  nethawk                    # Interactive mode"
echo "  nethawk --help            # Show help"
echo "  nethawk --version         # Show version"
echo "  sudo nethawk              # Run with full privileges"
echo ""
echo -e "${YELLOW}Examples:${NC}"
echo "  sudo nethawk --passive wlan0              # Passive scan"
echo "  sudo nethawk --active 192.168.1.0/24      # Active scan"
echo "  sudo nethawk --capture MyWiFi aa:bb:cc:dd:ee:ff  # Capture handshake"
echo ""
echo -e "${BLUE}📁 Files installed to: ~/.nethawk/${NC}"
echo -e "${BLUE}🔧 Executable: /usr/local/bin/nethawk${NC}"
echo ""
echo -e "${RED}⚠️  Remember: Always use with proper authorization!${NC}"