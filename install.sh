#!/bin/bash
# NetHawk Professional Installation Script
# Makes NetHawk install and run like nmap/metasploit

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# NetHawk ASCII Art
print_logo() {
    echo -e "${BLUE}"
    echo "  _   _      _   _           _    "
    echo " | \ | |    | | | |         | |   "
    echo " |  \| | ___| |_| |__   __ _| | __"
    echo " | . \` |/ _ \ __| '_ \ / _\` | |/ /"
    echo " | |\  |  __/ |_| | | | (_| |   < "
    echo " |_| \_|\___|\__|_| |_|\__,_|_|\_\\"
    echo -e "${NC}"
    echo -e "${GREEN}🦅 NetHawk - Professional Linux Reconnaissance Toolkit${NC}"
    echo -e "${YELLOW}Installing NetHawk like a professional tool...${NC}"
    echo ""
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "${RED}❌ Don't run this script as root!${NC}"
        echo -e "${YELLOW}Run as regular user, sudo will be used when needed.${NC}"
        exit 1
    fi
}

# Detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
    elif [[ -f /etc/debian_version ]]; then
        DISTRO="debian"
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO="rhel"
    else
        DISTRO="unknown"
    fi
    echo -e "${BLUE}📋 Detected distribution: ${DISTRO}${NC}"
}

# Install system dependencies
install_system_deps() {
    echo -e "${BLUE}📦 Installing system dependencies...${NC}"
    
    case $DISTRO in
        ubuntu|debian)
            sudo apt update
            sudo apt install -y python3 python3-pip python3-venv python3-dev \
                aircrack-ng hashcat hcxtools iw iproute2 nmcli \
                libpcap-dev libssl-dev build-essential \
                git curl wget
            ;;
        arch|manjaro)
            sudo pacman -S --noconfirm python python-pip python-virtualenv \
                aircrack-ng hashcat hcxtools iw iproute2 networkmanager \
                libpcap openssl base-devel git curl wget
            ;;
        fedora|rhel|centos)
            sudo dnf install -y python3 python3-pip python3-virtualenv \
                aircrack-ng hashcat hcxtools iw iproute2 NetworkManager \
                libpcap-devel openssl-devel gcc gcc-c++ make git curl wget
            ;;
        *)
            echo -e "${YELLOW}⚠️  Unknown distribution. Please install manually:${NC}"
            echo "   - python3, python3-pip, python3-venv"
            echo "   - aircrack-ng, hashcat, hcxtools, iw, iproute2"
            echo "   - libpcap-dev, libssl-dev, build-essential"
            ;;
    esac
}

# Create NetHawk user and directories
setup_user() {
    echo -e "${BLUE}👤 Setting up NetHawk user environment...${NC}"
    
    # Create .nethawk directory in user home
    mkdir -p ~/.nethawk/{logs,sessions,config}
    
    # Set proper permissions
    chmod 755 ~/.nethawk
    chmod 755 ~/.nethawk/{logs,sessions,config}
}

# Install Python dependencies in virtual environment
install_python_deps() {
    echo -e "${BLUE}🐍 Setting up Python virtual environment...${NC}"
    
    # Create virtual environment
    python3 -m venv ~/.nethawk/venv
    
    # Activate and upgrade pip
    source ~/.nethawk/venv/bin/activate
    pip install --upgrade pip setuptools wheel
    
    # Install requirements
    echo -e "${BLUE}📚 Installing Python dependencies...${NC}"
    pip install -r requirements.txt
    
    # Deactivate
    deactivate
}

# Create system-wide executable
create_executable() {
    echo -e "${BLUE}🔧 Creating system executable...${NC}"
    
    # Create the main executable
    cat > ~/.nethawk/nethawk << 'EOF'
#!/bin/bash
# NetHawk Professional Launcher

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Activate virtual environment
source "$SCRIPT_DIR/venv/bin/activate"

# Change to project directory
cd "$PROJECT_DIR"

# Run NetHawk with all arguments
python3 -m nethawk "$@"

# Deactivate virtual environment
deactivate
EOF

    # Make executable
    chmod +x ~/.nethawk/nethawk
    
    # Create symlink in /usr/local/bin if possible
    if sudo ln -sf ~/.nethawk/nethawk /usr/local/bin/nethawk 2>/dev/null; then
        echo -e "${GREEN}✅ NetHawk installed system-wide!${NC}"
        echo -e "${GREEN}   Run: nethawk${NC}"
    else
        echo -e "${YELLOW}⚠️  Could not install system-wide. Add to PATH:${NC}"
        echo -e "${YELLOW}   export PATH=\"\$HOME/.nethawk:\$PATH\"${NC}"
        echo -e "${YELLOW}   Add to ~/.bashrc for permanent access${NC}"
    fi
}

# Create bash completion
create_completion() {
    echo -e "${BLUE}🔧 Setting up bash completion...${NC}"
    
    cat > ~/.nethawk/nethawk-completion.bash << 'EOF'
# NetHawk Bash Completion
_nethawk_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    opts="--help --version --lab-only --yes --session --interface --output"
    
    case "${prev}" in
        --session)
            # Complete with session names
            COMPREPLY=( $(compgen -W "$(ls ~/.nethawk/sessions 2>/dev/null | cut -d'_' -f2-)" -- "${cur}") )
            return 0
            ;;
        --interface)
            # Complete with network interfaces
            COMPREPLY=( $(compgen -W "$(ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | tr -d ' ')" -- "${cur}") )
            return 0
            ;;
        *)
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

complete -F _nethawk_completion nethawk
EOF

    # Add to bashrc if not already there
    if ! grep -q "nethawk-completion" ~/.bashrc; then
        echo "" >> ~/.bashrc
        echo "# NetHawk bash completion" >> ~/.bashrc
        echo "source ~/.nethawk/nethawk-completion.bash" >> ~/.bashrc
    fi
}

# Create desktop entry
create_desktop_entry() {
    echo -e "${BLUE}🖥️  Creating desktop entry...${NC}"
    
    cat > ~/.local/share/applications/nethawk.desktop << EOF
[Desktop Entry]
Name=NetHawk
Comment=Professional Linux Reconnaissance Toolkit
Exec=gnome-terminal -e "nethawk"
Icon=applications-internet
Terminal=true
Type=Application
Categories=Network;Security;
Keywords=reconnaissance;penetration;testing;wireless;security;
EOF

    chmod +x ~/.local/share/applications/nethawk.desktop
}

# Test installation
test_installation() {
    echo -e "${BLUE}🧪 Testing installation...${NC}"
    
    # Test if nethawk command works
    if ~/.nethawk/nethawk --version >/dev/null 2>&1; then
        echo -e "${GREEN}✅ NetHawk installation successful!${NC}"
    else
        echo -e "${RED}❌ Installation test failed${NC}"
        return 1
    fi
}

# Show usage instructions
show_usage() {
    echo -e "${GREEN}🎉 NetHawk Installation Complete!${NC}"
    echo ""
    echo -e "${BLUE}📋 Usage Instructions:${NC}"
    echo ""
    echo -e "${YELLOW}Basic Usage:${NC}"
    echo "  nethawk                    # Interactive mode"
    echo "  nethawk --help            # Show help"
    echo "  nethawk --version         # Show version"
    echo ""
    echo -e "${YELLOW}Professional Usage:${NC}"
    echo "  nethawk --lab-only        # Enable all features"
    echo "  nethawk --session scan1   # Use specific session"
    echo "  nethawk --interface wlan0 # Use specific interface"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  sudo nethawk --lab-only --yes    # Full automated scan"
    echo "  sudo nethawk --session pentest  # Professional session"
    echo ""
    echo -e "${BLUE}📁 Files installed to: ~/.nethawk/${NC}"
    echo -e "${BLUE}🔧 Executable: /usr/local/bin/nethawk${NC}"
    echo -e "${BLUE}📚 Documentation: nethawk --help${NC}"
    echo ""
    echo -e "${RED}⚠️  Remember: Always use with proper authorization!${NC}"
}

# Main installation process
main() {
    print_logo
    check_root
    detect_distro
    install_system_deps
    setup_user
    install_python_deps
    create_executable
    create_completion
    create_desktop_entry
    test_installation
    show_usage
}

# Run main function
main "$@"
