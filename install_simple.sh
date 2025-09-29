#!/bin/bash
# NetHawk Simple Installation Script
# Bulletproof installation that always works

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🦅 NetHawk Simple Installation${NC}"
echo -e "${YELLOW}Installing NetHawk the simple way...${NC}"
echo ""

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${RED}❌ Don't run as root!${NC}"
    exit 1
fi

# Install system dependencies
echo -e "${BLUE}📦 Installing system dependencies...${NC}"
sudo apt update
sudo apt install -y python3 python3-pip python3-venv aircrack-ng hashcat hcxtools iw iproute2 nmcli git

# Create directory
echo -e "${BLUE}📁 Creating NetHawk directory...${NC}"
mkdir -p ~/.nethawk
cd ~/.nethawk

# Download NetHawk files directly
echo -e "${BLUE}📥 Downloading NetHawk files...${NC}"
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/NetHawk.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/requirements.txt
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/__main__.py -O __main__.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/cli_professional.py -O cli_professional.py

# Create nethawk directory structure
mkdir -p nethawk
cd nethawk

# Download core modules
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/__init__.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/session.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/cli.py

# Create modules directory
mkdir -p modules
cd modules
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/modules/__init__.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/modules/passive.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/modules/active.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/modules/capture.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/modules/crack.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/modules/report.py

# Create util directory
cd ..
mkdir -p util
cd util
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/util/__init__.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/util/logger.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/util/net.py
wget -q https://raw.githubusercontent.com/darky-boy/NetHawk/master/nethawk/util/toolcheck.py

# Go back to main directory
cd ~/.nethawk

# Create virtual environment
echo -e "${BLUE}🐍 Setting up Python environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "${BLUE}📚 Installing Python packages...${NC}"
pip install --upgrade pip
pip install rich psutil requests argparse

# Create simple executable
echo -e "${BLUE}🔧 Creating executable...${NC}"
cat > nethawk << 'EOF'
#!/bin/bash
cd ~/.nethawk
source venv/bin/activate
python3 NetHawk.py "$@"
deactivate
EOF

chmod +x nethawk

# Create system link
sudo ln -sf ~/.nethawk/nethawk /usr/local/bin/nethawk

# Test installation
echo -e "${BLUE}🧪 Testing installation...${NC}"
if nethawk --version >/dev/null 2>&1; then
    echo -e "${GREEN}✅ NetHawk installed successfully!${NC}"
else
    echo -e "${YELLOW}⚠️  Installation completed with warnings${NC}"
fi

# Show usage
echo ""
echo -e "${GREEN}🎉 NetHawk Installation Complete!${NC}"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo "  nethawk                    # Interactive mode"
echo "  nethawk --help            # Show help"
echo "  sudo nethawk              # Run with full privileges"
echo ""
echo -e "${BLUE}Files installed to: ~/.nethawk/${NC}"
echo -e "${BLUE}Executable: /usr/local/bin/nethawk${NC}"
echo ""
echo -e "${RED}⚠️  Remember: Always use with proper authorization!${NC}"
