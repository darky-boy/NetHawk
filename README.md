# 🦅 NetHawk - Professional Network Security Tool

**NetHawk** is a comprehensive Linux network security and reconnaissance toolkit designed for ethical penetration testing and network analysis.

**Made By DarCy**

## 🚀 Quick Installation

### **Prerequisites**
- **Linux System** (Ubuntu, Debian, Kali Linux, etc.)
- **Python 3.8+**
- **Root privileges** (required for full functionality)
- **Wireless interface** (for WiFi operations)

### **Step 1: Clone the Repository**
```bash
git clone https://github.com/darky-boy/NetHawk.git
cd NetHawk
```

### **Step 2: Run Setup Script (Recommended)**
```bash
# Make setup script executable and run it
chmod +x setup.sh
./setup.sh
```

**OR Manual Installation:**
```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y aircrack-ng nmap nikto enum4linux dnsutils

# For Kali Linux (most tools pre-installed)
sudo apt update
```

### **Step 3: Run NetHawk**
```bash
# Run with full privileges (recommended)
sudo python3 NetHawk.py
```

## ✨ Features

### **🔍 1. Passive WiFi Scan**
- Discover nearby WiFi networks
- Analyze network security (WEP, WPA, WPA2, WPA3)
- Device detection and MAC address analysis
- No network interference

### **🎯 2. Active Network Scan**
- Host discovery and port scanning
- Service enumeration and OS detection
- Device type identification
- Comprehensive network mapping

### **📡 3. Handshake Capture + Deauth**
- Capture WPA/WPA2 handshakes
- Deauthentication attacks
- Save handshakes for analysis
- Professional handshake management

### **🔓 4. Vulnerability Assessment**
- Network vulnerability scanning
- Service-specific security checks
- CVE detection and analysis
- Risk assessment and reporting

### **🌐 5. Web Application Scanning**
- Web vulnerability detection
- Security header analysis
- Common web vulnerabilities
- Comprehensive web security assessment

### **🖥️ 6. SMB/Windows Enumeration**
- Windows system enumeration
- SMB service analysis
- User account discovery
- Share enumeration

### **🔍 7. DNS Reconnaissance**
- DNS record analysis
- Domain information gathering
- Subdomain discovery
- DNS security assessment

### **📊 8. Comprehensive Reporting**
- Professional security reports
- Executive summaries
- Technical details
- Actionable recommendations

## 🎮 Usage Guide

### **Interactive Mode (Recommended)**
```bash
sudo python3 NetHawk.py
```

**Main Menu Options:**
1. **Passive WiFi Scan** - Discover networks without interference
2. **Active Network Scan** - Comprehensive network analysis
3. **Handshake Capture + Deauth** - Capture authentication data
4. **Vulnerability Assessment** - Security vulnerability scanning
5. **Web Application Scanning** - Web security analysis
6. **SMB/Windows Enumeration** - Windows system analysis
7. **DNS Reconnaissance** - Domain and DNS analysis
8. **Comprehensive Reporting** - Generate professional reports
9. **Show Detection Methodology** - View technical details
0. **Exit** - Close the application

### **Session Management**
- **Automatic session creation** for each scan
- **Organized file structure** for results
- **JSON and text reports** for analysis
- **Timestamped sessions** for tracking

## 📁 File Structure

```
NetHawk/
├── NetHawk.py              # Main application
├── requirements.txt         # Python dependencies
├── README.md               # This file
├── sessions/               # Session data
│   └── session_X/          # Individual sessions
│       ├── handshakes/     # Captured handshakes
│       ├── vulnerabilities/ # Vulnerability reports
│       ├── logs/           # Session logs
│       └── reports/        # Generated reports
└── LEGAL.md               # Legal information
```

## 🛠️ Advanced Usage

### **Custom Network Scanning**
```bash
# Scan specific network range
sudo python3 NetHawk.py
# Select Option 2: Active Network Scan
# Enter target: 192.168.1.0/24
```

### **Handshake Capture**
```bash
# Capture handshake from specific network
sudo python3 NetHawk.py
# Select Option 3: Handshake Capture
# Enter target network details
```

### **Vulnerability Assessment**
```bash
# Assess network vulnerabilities
sudo python3 NetHawk.py
# Select Option 4: Vulnerability Assessment
# Choose scan type and target
```

## 🔧 Troubleshooting

### **Common Issues**

**1. Permission Denied**
```bash
# Solution: Run with sudo
sudo python3 NetHawk.py
```

**2. Missing Tools**
```bash
# Install required tools
sudo apt install aircrack-ng nmap nikto enum4linux dnsutils
```

**3. Wireless Interface Issues**
```bash
# Check wireless interface
iwconfig
# Enable monitor mode
sudo airmon-ng start wlan0
```

**4. Python Dependencies**
```bash
# Install Python packages
pip3 install -r requirements.txt
```

## ⚖️ Legal and Ethical Use

### **✅ Authorized Use Cases**
- **Authorized penetration testing**
- **Security research and education**
- **Lab environments and testing**
- **Personal network analysis**
- **Professional security assessments**

### **❌ Prohibited Activities**
- **Unauthorized network access**
- **Malicious activities**
- **Illegal surveillance**
- **Violation of privacy**
- **Criminal activities**

### **⚠️ Important Notice**
- **Always obtain proper authorization** before testing
- **Respect privacy and legal boundaries**
- **Use only on networks you own or have permission to test**
- **Follow local laws and regulations**

## 🤝 Contributing

We welcome contributions to improve NetHawk!

### **How to Contribute**
1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Test thoroughly**
5. **Submit a pull request**

### **Development Setup**
```bash
# Clone your fork
git clone https://github.com/your-username/NetHawk.git
cd NetHawk

# Create development environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Make changes and test
sudo python3 NetHawk.py
```

## 📄 License

This project is licensed under the **MIT License**. See the LICENSE file for details.

## 🆘 Support

### **Getting Help**
- **Check the troubleshooting section**
- **Review the documentation**
- **Open an issue on GitHub**
- **Join the community discussions**

### **Reporting Issues**
When reporting issues, please include:
- **Operating system and version**
- **Python version**
- **Error messages**
- **Steps to reproduce**
- **Expected vs actual behavior**

## 🏆 Acknowledgments

- **Made By DarCy** - Creator and maintainer
- **Open source community** - For excellent tools and libraries
- **Security researchers** - For methodology and techniques
- **Contributors** - For improvements and feedback

---

## 🎯 Quick Start Summary

```bash
# 1. Clone and setup
git clone https://github.com/darky-boy/NetHawk.git
cd NetHawk

# 2. Run setup script (recommended)
chmod +x setup.sh
./setup.sh

# 3. Run NetHawk
sudo python3 NetHawk.py
```

**🦅 NetHawk - Professional Network Security Tool**

*Use responsibly and ethically!*

---

**Made By DarCy** | **Professional Network Security** | **Ethical Hacking Tool**