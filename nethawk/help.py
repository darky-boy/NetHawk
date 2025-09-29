#!/usr/bin/env python3
"""
NetHawk Help System
Provides help and manual functionality
"""

import sys
import subprocess
from pathlib import Path

def show_help():
    """Show help message."""
    help_text = """
NetHawk - Linux Reconnaissance Toolkit v1.0

USAGE:
    nethawk [OPTIONS] COMMAND [ARGS...]

COMMANDS:
    passive      Perform passive wireless network scanning
    active       Perform active network host and port scanning  
    capture      Capture WPA/WPA2 handshakes from target networks
    crack        Crack captured handshakes using wordlists
    report       Generate comprehensive HTML/JSON/PDF reports
    session      Manage NetHawk sessions

OPTIONS:
    -h, --help           Show this help message and exit
    -v, --version        Show version information and exit
    -m, --man            Show manual page and exit
    --lab-only           Enable lab-only mode (default: enabled)
    --yes                Skip confirmation prompts
    --session PATH       Specify session directory path
    --verbose            Enable verbose output
    --debug              Enable debug mode

EXAMPLES:
    nethawk passive --interface wlan0 --duration 60
    nethawk active --target 192.168.1.0/24 --ports 22,80,443
    nethawk capture --target "TestNetwork" --bssid 00:11:22:33:44:55 --channel 6
    nethawk crack --cap-file handshakes/TestNetwork.cap --wordlist rockyou.txt
    nethawk report --format html --include-pdf
    nethawk session --list
    nethawk session --create "pentest_2024"

SAFETY FEATURES:
    - Lab-only mode prevents attacks on external networks
    - Session isolation keeps data organized and secure
    - Audit logging tracks all operations
    - Confirmation prompts for destructive operations

For detailed information, see: nethawk --man
For specific command help, see: nethawk COMMAND --help
"""
    print(help_text)

def show_manual():
    """Show manual page using man command."""
    try:
        man_path = Path(__file__).parent / "man" / "nethawk.1"
        if man_path.exists():
            subprocess.run(["man", str(man_path)])
        else:
            print("Manual page not found. Install man pages or check installation.")
            print(f"Manual source: {man_path}")
    except FileNotFoundError:
        print("'man' command not found. Please install man-db package.")
        print("Alternatively, view the manual source at: nethawk/man/nethawk.1")

def show_version():
    """Show version information."""
    version_text = """
NetHawk v1.0 - Linux Reconnaissance Toolkit

Copyright (C) 2024 NetHawk Project
This is free software; see the source for copying conditions.

Features:
  ✅ Passive wireless scanning
  ✅ Active network discovery  
  ✅ Handshake capture with deauth attacks
  ✅ Password cracking (aircrack-ng/hashcat)
  ✅ Professional HTML/JSON/PDF reporting
  ✅ Session-based data management
  ✅ Lab-only safety protections
  ✅ Comprehensive audit logging

Dependencies:
  - aircrack-ng suite (airodump-ng, aireplay-ng, aircrack-ng, airmon-ng)
  - nmap (network discovery and port scanning)
  - hashcat (optional, advanced password cracking)
  - hcxtools (optional, cap2hccapx for hashcat)
  - scapy (optional, Python networking library)
  - rich (Python library for colored terminal output)

For more information, see: nethawk --man
"""
    print(version_text)

def main():
    """Main help entry point."""
    if len(sys.argv) < 2:
        show_help()
        return 0
    
    command = sys.argv[1]
    
    if command in ["-h", "--help", "help"]:
        show_help()
    elif command in ["-v", "--version", "version"]:
        show_version()
    elif command in ["-m", "--man", "man"]:
        show_manual()
    else:
        print(f"Unknown command: {command}")
        show_help()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
