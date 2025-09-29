# 🦅 NetHawk - Simple Linux Reconnaissance Tool

**NetHawk** is a simple, easy-to-use Linux reconnaissance toolkit for ethical penetration testing.

## 🚀 Quick Start

### **Step 1: Clone the Repository**
```bash
git clone https://github.com/darky-boy/NetHawk.git
cd NetHawk
```

### **Step 2: Run Setup Script**
```bash
chmod +x setup.sh
./setup.sh
```

### **Step 3: Use NetHawk**
```bash
# Run NetHawk
python3 NetHawk.py

# Or with help
python3 NetHawk.py --help

# With full privileges
sudo python3 NetHawk.py
```

## ✨ Features

- **🔍 Passive Wireless Scanning** - Discover WiFi networks and devices
- **🎯 Active Network Scanning** - Host discovery and port scanning
- **📡 Handshake Capture** - Capture WPA/WPA2 handshakes
- **🔓 Password Cracking** - Crack captured handshakes
- **📊 Reporting** - Generate professional reports

## 🎮 Usage Examples

### **Interactive Mode**
```bash
sudo python3 NetHawk.py
```

### **Command Line Mode**
```bash
# Passive scan
sudo python3 NetHawk.py --passive wlan0

# Active scan
sudo python3 NetHawk.py --active 192.168.1.0/24

# Capture handshake
sudo python3 NetHawk.py --capture MyWiFi aa:bb:cc:dd:ee:ff

# Crack handshake
sudo python3 NetHawk.py --crack handshake.cap

# Generate report
sudo python3 NetHawk.py --report
```

## 📋 Requirements

- **Linux System** (Ubuntu, Debian, Kali, etc.)
- **Python 3.8+**
- **Root privileges** for full functionality
- **Wireless interface** for WiFi operations

## ⚖️ Legal Notice

**NetHawk is for authorized testing only!**

- ✅ **Authorized penetration testing**
- ✅ **Lab environments**
- ✅ **Educational purposes**
- ❌ **Unauthorized network access**
- ❌ **Malicious activities**

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

---

**🦅 NetHawk - Simple and Easy Linux Reconnaissance Tool**

*Use responsibly and ethically!*