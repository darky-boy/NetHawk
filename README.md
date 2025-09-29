# NetHawk

**Terminal-first Linux reconnaissance toolkit for ethical pentesting & labs**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

## ⚠️ Legal Notice

**NetHawk is for authorized testing and lab environments only.**

- Only use on networks you own or have explicit written permission to test
- Unauthorized use on networks you do not own is illegal and unethical
- Always ensure you have explicit written permission before testing
- This tool is designed for educational purposes and authorized penetration testing

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/nethawk/nethawk.git
cd nethawk

# Install dependencies
pip install -r requirements.txt

# Install NetHawk
pip install -e .
```

### System Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install aircrack-ng hashcat hcxtools iw iproute2 nmap python3-rich

# Or install NetHawk with full dependencies
pip install -e ".[full]"
```

### Usage

```bash
# Safe mode (passive scans only)
python -m nethawk

# Enable lab features with consent prompts
python -m nethawk --lab-only

# Enable all features (automated consent)
python -m nethawk --lab-only --yes

# Use specific session ID
python -m nethawk --session my-test-session
```

## Features

### 🔍 Passive Scanning
- Wi-Fi network discovery
- Access point enumeration
- Client device detection
- Vendor identification via MAC OUI lookup

### 🎯 Active Scanning
- Network host discovery (ping sweep)
- Port scanning and service enumeration
- Banner grabbing and version detection
- Comprehensive network reconnaissance

### 📡 Handshake Capture
- WPA/WPA2 handshake capture
- Automatic monitor mode management
- Deauthentication attack capabilities
- Multiple target support

### 🔓 Handshake Cracking
- Support for aircrack-ng and hashcat
- Multiple wordlist support
- Progress tracking and live output
- Batch processing capabilities

### 📊 Reporting
- Comprehensive HTML reports
- JSON data export
- Session management
- Automated cleanup

## Safety Features

- **Lab-only mode**: Dangerous operations require `--lab-only` flag
- **Consent prompts**: Explicit user confirmation for sensitive operations
- **Legal warnings**: Clear notices about authorized use only
- **Session isolation**: Each run creates isolated session directories
- **Audit logging**: All operations logged for compliance

## Project Structure

```
nethawk/
├── bin/nethawk              # Executable launcher
├── nethawk/
│   ├── __main__.py          # Entry point
│   ├── cli.py               # Command-line interface
│   ├── session.py           # Session management
│   ├── util/                # Utilities
│   │   ├── toolcheck.py     # Dependency checking
│   │   ├── logger.py        # Logging system
│   │   └── net.py           # Network utilities
│   └── modules/             # Core modules
│       ├── passive.py       # Passive scanning
│       ├── active.py        # Active scanning
│       ├── capture.py       # Handshake capture
│       ├── crack.py         # Handshake cracking
│       └── report.py        # Report generation
├── requirements.txt         # Python dependencies
├── pyproject.toml          # Package configuration
└── README.md               # This file
```

## Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Code formatting
black nethawk/

# Type checking
mypy nethawk/
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Users must ensure they have proper authorization before using NetHawk on any network.
