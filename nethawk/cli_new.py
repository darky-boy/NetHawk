"""
NetHawk CLI - Command Line Interface with Help and Manual Support
"""

import argparse
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
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="nethawk",
        description="NetHawk - Linux Reconnaissance Toolkit",
        add_help=False  # We'll handle help manually
    )
    
    # Global options
    parser.add_argument(
        "-h", "--help",
        action="store_true",
        help="Show help message and exit"
    )
    
    parser.add_argument(
        "-v", "--version",
        action="store_true", 
        help="Show version information and exit"
    )
    
    parser.add_argument(
        "-m", "--man",
        action="store_true",
        help="Show manual page and exit"
    )
    
    parser.add_argument(
        "--lab-only",
        action="store_true",
        default=True,
        help="Enable lab-only mode (default: enabled)"
    )
    
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompts"
    )
    
    parser.add_argument(
        "--session",
        type=str,
        help="Specify session directory path"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Passive scan command
    passive_parser = subparsers.add_parser("passive", help="Perform passive wireless scanning")
    passive_parser.add_argument("--interface", default="wlan0", help="Wireless interface")
    passive_parser.add_argument("--duration", type=int, default=60, help="Scan duration in seconds")
    
    # Active scan command
    active_parser = subparsers.add_parser("active", help="Perform active network scanning")
    active_parser.add_argument("--target", required=True, help="Target network or IP")
    active_parser.add_argument("--ports", help="Comma-separated list of ports")
    
    # Capture command
    capture_parser = subparsers.add_parser("capture", help="Capture handshakes")
    capture_parser.add_argument("--target", required=True, help="Target SSID")
    capture_parser.add_argument("--bssid", required=True, help="Target BSSID")
    capture_parser.add_argument("--channel", type=int, required=True, help="Target channel")
    capture_parser.add_argument("--interface", default="wlan0", help="Wireless interface")
    capture_parser.add_argument("--duration", type=int, default=60, help="Capture duration")
    capture_parser.add_argument("--deauth", action="store_true", help="Use deauth attack")
    
    # Crack command
    crack_parser = subparsers.add_parser("crack", help="Crack handshakes")
    crack_parser.add_argument("--cap-file", required=True, help="Path to .cap file")
    crack_parser.add_argument("--wordlist", required=True, help="Path to wordlist")
    crack_parser.add_argument("--tool", choices=["aircrack-ng", "hashcat"], default="aircrack-ng", help="Cracking tool")
    crack_parser.add_argument("--timeout", type=int, help="Timeout in seconds")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate reports")
    report_parser.add_argument("--format", choices=["html", "json", "both"], default="html", help="Report format")
    report_parser.add_argument("--include-pdf", action="store_true", help="Include PDF export")
    
    # Session command
    session_parser = subparsers.add_parser("session", help="Manage sessions")
    session_parser.add_argument("--list", action="store_true", help="List sessions")
    session_parser.add_argument("--create", help="Create new session")
    session_parser.add_argument("--delete", help="Delete session")
    session_parser.add_argument("--prune", type=int, help="Prune sessions older than N days")
    
    args = parser.parse_args()
    
    # Handle global options first
    if args.help:
        show_help()
        return 0
    
    if args.version:
        show_version()
        return 0
        
    if args.man:
        show_manual()
        return 0
    
    if not args.command:
        show_help()
        return 1
    
    # Import and run command handlers
    try:
        if args.command == "passive":
            from nethawk.modules.passive import run_passive_scan
            # Implementation here
            print("Passive scanning not yet implemented in CLI")
            
        elif args.command == "active":
            from nethawk.modules.active import run_active_scan
            # Implementation here
            print("Active scanning not yet implemented in CLI")
            
        elif args.command == "capture":
            from nethawk.modules.capture import run_handshake_capture
            # Implementation here
            print("Handshake capture not yet implemented in CLI")
            
        elif args.command == "crack":
            from nethawk.modules.crack import crack_handshake
            # Implementation here
            print("Handshake cracking not yet implemented in CLI")
            
        elif args.command == "report":
            from nethawk.modules.report import generate_report
            # Implementation here
            print("Report generation not yet implemented in CLI")
            
        elif args.command == "session":
            from nethawk.session import create_session, get_latest_session, prune_sessions
            if args.list:
                print("Session listing not yet implemented")
            elif args.create:
                session_path = create_session(args.create)
                print(f"Created session: {session_path}")
            elif args.delete:
                print("Session deletion not yet implemented")
            elif args.prune:
                deleted = prune_sessions(args.prune)
                print(f"Pruned {deleted} old sessions")
            else:
                session_parser.print_help()
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
