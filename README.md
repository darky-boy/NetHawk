# 🦅 NetHawk - Professional Linux Reconnaissance Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Linux](https://img.shields.io/badge/platform-Linux-green.svg)](https://www.linux.org/)

**NetHawk** is a professional-grade Linux reconnaissance toolkit designed for ethical penetration testing and security research. Built with the same philosophy as industry-standard tools like nmap and metasploit, NetHawk provides comprehensive wireless and network reconnaissance capabilities.

## 🚀 Quick Start

### ⚡ One-Line Installation (Recommended)
```bash
curl -sSL https://raw.githubusercontent.com/darky-boy/NetHawk/master/install.sh | bash
```

### 📋 Manual Installation
```bash
git clone https://github.com/darky-boy/NetHawk.git
cd NetHawk
chmod +x install.sh
./install.sh
```

### 🎯 After Installation
```bash
# Run NetHawk (Interactive mode like Metasploit)
sudo nethawk

# Or use command line mode (like Nmap)
sudo nethawk --help
```

## ✨ Features

### 🔍 **Passive Reconnaissance**
- **Wireless Network Discovery** - Comprehensive WiFi network scanning
- **Client Device Detection** - Identify connected devices and their capabilities
- **Traffic Analysis** - Monitor wireless communications and protocols
- **Vendor Identification** - MAC address vendor lookup and device fingerprinting

### 🎯 **Active Reconnaissance**
- **Network Host Discovery** - Advanced host enumeration techniques
- **Port Scanning** - Comprehensive port and service detection
- **Service Enumeration** - Detailed service and version identification
- **Vulnerability Assessment** - Automated security testing capabilities

### 📡 **Handshake Operations**
- **WPA/WPA2 Handshake Capture** - Professional handshake collection
- **Deauthentication Attacks** - Controlled deauth for handshake capture
- **Monitor Mode Management** - Automatic interface configuration
- **Multiple Format Support** - .cap, .hccapx, and hashcat formats

### 🔓 **Password Cracking**
- **Dictionary Attacks** - Efficient wordlist-based cracking
- **Hashcat Integration** - GPU-accelerated password recovery
- **Custom Wordlists** - Support for custom and specialized wordlists
- **Progress Tracking** - Real-time cracking progress monitoring

### 📊 **Professional Reporting**
- **Multiple Formats** - HTML, PDF, JSON, and XML report generation
- **Executive Summaries** - High-level security assessment reports
- **Technical Details** - Comprehensive technical documentation
- **Evidence Collection** - Automated evidence gathering and preservation

## 🛠️ Installation

### System Requirements
- **Linux Distribution** (Ubuntu, Debian, Arch, CentOS, Fedora, etc.)
- **Python 3.8+** with pip and venv support
- **Root Privileges** for full functionality
- **Wireless Interface** supporting monitor mode
- **Required Tools** (automatically installed): aircrack-ng, hashcat, hcxtools, iw, nmap

### Automated Installation
```bash
# Download and run installation script
curl -sSL https://raw.githubusercontent.com/darky-boy/NetHawk/master/install.sh | bash

# Or clone and install manually
git clone https://github.com/darky-boy/NetHawk.git
cd NetHawk
./install.sh
```

### Manual Installation
```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv aircrack-ng hashcat hcxtools iw iproute2 nmcli

# Clone repository
git clone https://github.com/darky-boy/NetHawk.git
cd NetHawk

# Create virtual environment
python3 -m venv ~/.nethawk/venv
source ~/.nethawk/venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Create system executable
sudo ln -sf ~/.nethawk/nethawk /usr/local/bin/nethawk
```

## 🎮 Usage

### Interactive Mode (Like Metasploit)
```bash
# Start interactive session
sudo nethawk

# NetHawk Professional Commands:
nethawk > passive wlan0              # Passive wireless scan
nethawk > active 192.168.1.0/24     # Active network scan
nethawk > capture MyWiFi aa:bb:cc:dd:ee:ff  # Capture handshake
nethawk > crack handshake.cap       # Crack handshake
nethawk > report html               # Generate report
nethawk > help                      # Show help
nethawk > exit                      # Exit
```

### Command Line Mode (Like Nmap)
```bash
# Basic reconnaissance
sudo nethawk --passive wlan0                    # Passive scan
sudo nethawk --active 192.168.1.0/24            # Active scan
sudo nethawk --capture MyWiFi aa:bb:cc:dd:ee:ff # Capture handshake
sudo nethawk --crack handshake.cap              # Crack handshake
sudo nethawk --report                           # Generate report

# Advanced usage
sudo nethawk --session pentest --passive wlan0  # Named session
sudo nethawk --interface wlan1 --active 10.0.0.0/8  # Specific interface
```

### Professional Workflow
```bash
# 1. Start reconnaissance session
sudo nethawk --session client_audit

# 2. Passive wireless discovery
nethawk > passive wlan0

# 3. Active network scanning
nethawk > active 192.168.1.0/24

# 4. Capture handshakes (if authorized)
nethawk > capture TargetWiFi aa:bb:cc:dd:ee:ff

# 5. Crack passwords
nethawk > crack handshake.cap

# 6. Generate professional report
nethawk > report html
```

## 📋 Command Reference

### Core Commands
| Command | Description | Example |
|---------|-------------|---------|
| `passive [interface]` | Passive wireless scan | `passive wlan0` |
| `active <target>` | Active network scan | `active 192.168.1.0/24` |
| `capture <SSID> <BSSID>` | Capture WPA handshake | `capture MyWiFi aa:bb:cc:dd:ee:ff` |
| `crack <cap_file>` | Crack handshake | `crack handshake.cap` |
| `report [format]` | Generate report | `report html` |
| `sessions` | List sessions | `sessions` |
| `help` | Show help | `help` |
| `exit` | Exit NetHawk | `exit` |

### Command Line Options
| Option | Description | Example |
|--------|-------------|---------|
| `--passive` | Run passive scan | `nethawk --passive wlan0` |
| `--active <target>` | Run active scan | `nethawk --active 192.168.1.0/24` |
| `--capture <SSID> <BSSID>` | Capture handshake | `nethawk --capture MyWiFi aa:bb:cc:dd:ee:ff` |
| `--crack <file>` | Crack handshake | `nethawk --crack handshake.cap` |
| `--report` | Generate report | `nethawk --report` |
| `--session <name>` | Use specific session | `nethawk --session audit` |
| `--interface <iface>` | Use specific interface | `nethawk --interface wlan1` |
| `--help` | Show help | `nethawk --help` |
| `--version` | Show version | `nethawk --version` |

## 🔧 Configuration

### Environment Setup
```bash
# Check environment
nethawk --check-env

# Update dependencies
nethawk --update-deps

# Reset configuration
nethawk --reset-config
```

### Session Management
```bash
# List all sessions
nethawk --list-sessions

# Use specific session
nethawk --session my_audit

# Clean old sessions
nethawk --clean-sessions
```

## 📊 Output Formats

### Report Formats
- **HTML** - Interactive web reports with charts and graphs
- **PDF** - Professional PDF reports for client delivery
- **JSON** - Machine-readable data for integration
- **XML** - Structured data for enterprise systems

### Data Export
- **CSV** - Spreadsheet-compatible data export
- **TXT** - Plain text reports for documentation
- **PCAP** - Network traffic capture files
- **HCCAPX** - Hashcat-compatible handshake files

## ⚖️ Legal and Ethical Use

### ⚠️ **IMPORTANT LEGAL NOTICE**

**NetHawk is designed for authorized penetration testing and security research only.**

### ✅ **Authorized Use Cases**
- **Penetration Testing** - Authorized security assessments
- **Security Research** - Academic and professional research
- **Lab Environments** - Controlled testing environments
- **Educational Purposes** - Security training and education

### ❌ **Prohibited Use Cases**
- **Unauthorized Network Access** - Testing networks without permission
- **Malicious Activities** - Any illegal or harmful activities
- **Privacy Violations** - Unauthorized data collection
- **Commercial Use** - Using without proper licensing

### 🛡️ **Responsible Disclosure**
- Report vulnerabilities responsibly
- Follow responsible disclosure practices
- Respect privacy and confidentiality
- Comply with local laws and regulations

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/darky-boy/NetHawk.git
cd NetHawk
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Aircrack-ng Team** - For the excellent wireless security tools
- **Hashcat Team** - For the powerful password recovery tools
- **Nmap Team** - For inspiration on professional tool design
- **Metasploit Team** - For the interactive framework approach

## 📞 Support

- **Documentation** - [Wiki](https://github.com/darky-boy/NetHawk/wiki)
- **Issues** - [GitHub Issues](https://github.com/darky-boy/NetHawk/issues)
- **Discussions** - [GitHub Discussions](https://github.com/darky-boy/NetHawk/discussions)

---

**🦅 NetHawk - Professional Linux Reconnaissance Toolkit**

*Use responsibly and ethically. Always obtain proper authorization before testing.*