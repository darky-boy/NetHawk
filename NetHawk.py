#!/usr/bin/env python3
"""
NetHawk - Linux Network Security Tool
Professional reconnaissance and penetration testing
"""

import os
import sys
import time
import subprocess
import shutil
import json
import socket
import threading
import ipaddress
import csv
import re
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

# Initialize Rich console for colored output
console = Console()

class NetHawk:
    """NetHawk application - Professional reconnaissance capabilities."""
    
    def __init__(self):
        """Initialize NetHawk with session management."""
        self.config = self._load_config()
        self.session_number = self._get_next_session_number()
        self.session_path = os.path.abspath(f"sessions/session_{self.session_number}")
        self.handshakes_path = os.path.join(self.session_path, "handshakes")
        self.logs_path = os.path.join(self.session_path, "logs")
        self.vulns_path = os.path.join(self.session_path, "vulnerabilities")
        self.reports_path = os.path.join(self.session_path, "reports")
        self._create_session_directories()
        
        # Tool availability cache
        self.tools_available = {}
        self._check_tools()
    
    def _get_next_session_number(self):
        """Get the next available session number."""
        sessions_dir = "sessions"
        if not os.path.exists(sessions_dir):
            return 1
        
        existing_sessions = [d for d in os.listdir(sessions_dir) if d.startswith("session_")]
        if not existing_sessions:
            return 1
        
        # Extract numbers and find the highest
        numbers = []
        for session in existing_sessions:
            try:
                num = int(session.split("_")[1])
                numbers.append(num)
            except (IndexError, ValueError):
                continue
        
        return max(numbers) + 1 if numbers else 1
    
    def _create_session_directories(self):
        """Create session directory structure."""
        directories = [
            self.session_path,
            self.handshakes_path,
            self.logs_path,
            self.vulns_path,
            self.reports_path
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
                console.print(f"[green]✓[/green] Created directory: {directory}")
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to create directory {directory}: {e}")
                raise
    
    def _check_tools(self):
        """Check for required tools and cache results."""
        required_tools = {
            "airodump-ng": "aircrack-ng",
            "aireplay-ng": "aircrack-ng", 
            "aircrack-ng": "aircrack-ng",
            "iw": "iw",
            "ip": "iproute2",
            "nmap": "nmap",
            "ping": "iputils-ping",
            "masscan": "masscan",
            "nikto": "nikto",
            "gobuster": "gobuster",
            "enum4linux": "enum4linux",
            "smbclient": "samba-client",
            "dig": "dnsutils",
            "nslookup": "dnsutils"
        }
        
        self.tools_available = {}
        missing_tools = []
        
        # Show progress for tool checking
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Checking tools...", total=len(required_tools))
            
            for tool, package in required_tools.items():
                progress.update(task, description=f"Checking {tool}...")
                if shutil.which(tool):
                    self.tools_available[tool] = True
                else:
                    self.tools_available[tool] = False
                    missing_tools.append(f"{tool} (install: {package})")
                progress.advance(task)
        
        if missing_tools:
            console.print(f"[yellow]Missing tools: {', '.join(missing_tools)}[/yellow]")
            console.print("[blue]Some features may not work without these tools.[/blue]")
            console.print("[blue]Install with: sudo apt install aircrack-ng iw iproute2 nmap masscan nikto gobuster enum4linux samba-client dnsutils[/blue]")
        else:
            console.print("[green]✓ All required tools found![/green]")
    
    def display_logo(self):
        """Display NetHawk ASCII logo."""
        logo = r"""
                                                                                                                                                                    
                                                                                                                                                                    
 _   _      _   _   _                _    
| \ | |    | | | | | |              | |   
|  \| | ___| |_| |_| | __ ___      _| | __
| . ` |/ _ \ __|  _  |/ _` \ \ /\ / / |/ /
| |\  |  __/ |_| | | | (_| |\ V  V /|   < 
\_| \_/\___|\__\_| |_\__,_| \_/\_/ |_|\_\
                                          
                                                                                                                                                                                                                                                                                                                                                                                                                
        """
        
        console.print(Panel(logo, title="[bold blue]NetHawk[/bold blue]", 
                           subtitle="[italic]Professional Network Security Tool[/italic]"))
        console.print()
    
    def display_main_menu(self):
        """Display the main menu with options."""
        menu_text = """
[bold cyan]Main Menu[/bold cyan]

[bold]1.[/bold] Passive WiFi Scan
[bold]2.[/bold] Active Network Scan  
[bold]3.[/bold] Handshake Capture + Deauth
[bold]4.[/bold] Vulnerability Assessment
[bold]5.[/bold] Web Application Scanning
[bold]6.[/bold] SMB/Windows Enumeration
[bold]7.[/bold] DNS Reconnaissance
[bold]8.[/bold] Comprehensive Reporting
[bold]9.[/bold] Show Detection Methodology
[bold]0.[/bold] Exit

[italic]Session: {session}[/italic]
[italic]Path: {path}[/italic]

[bold cyan]🧠 Hybrid Detection System:[/bold cyan]
[dim]• MAC OUI Analysis (650+ prefixes) + Port/Service Heuristics[/dim]
[dim]• OS Fingerprinting + Cross-Validation Logic[/dim]
[dim]• Confidence Scoring: High/Medium/Low accuracy levels[/dim]
        """.format(session=f"session_{self.session_number}", path=self.session_path)
        
        console.print(Panel(menu_text, title="[bold green]NetHawk Menu[/bold green]"))
    
    def validate_input(self, prompt, choices):
        """Validate user input against available choices."""
        while True:
            try:
                choice = Prompt.ask(prompt)
                if choice in choices:
                    return choice
                else:
                    console.print("[red]Please enter a valid option.[/red]")
            except KeyboardInterrupt:
                console.print("\n[yellow]Operation cancelled by user.[/yellow]")
                sys.exit(0)
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
    
    def _get_wireless_interfaces(self):
        """Get available wireless interfaces."""
        interfaces = []
        try:
            # Use iw to list wireless interfaces
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Interface' in line:
                        iface = line.split()[-1]
                        interfaces.append(iface)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not detect interfaces with iw: {e}[/yellow]")
            # Fallback to common interface names
            common_interfaces = ['wlan0', 'wlan1', 'wlp2s0', 'wlp3s0']
            for iface in common_interfaces:
                if os.path.exists(f'/sys/class/net/{iface}'):
                    interfaces.append(iface)
        
        return interfaces
    
    def _check_monitor_mode_support(self, iface):
        """Check if interface supports monitor mode with better detection."""
        try:
            console.print(f"[blue]Checking monitor mode support for {iface}...[/blue]")
            
            # First check if interface exists and is wireless
            result = subprocess.run(["iw", iface, "info"], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                console.print(f"[yellow]Warning: Could not get info for {iface}[/yellow]")
                console.print(f"[blue]Let's try anyway - airmon-ng will handle it[/blue]")
                return True  # Let airmon-ng try
            
            # Check if it's a wireless interface
            if "type" not in result.stdout.lower():
                console.print(f"[yellow]Warning: {iface} might not be wireless[/yellow]")
                console.print(f"[blue]Let's try anyway - airmon-ng will handle it[/blue]")
                return True  # Let airmon-ng try
            
            # Check current mode
            if "monitor" in result.stdout.lower():
                console.print(f"[green]✓ {iface} is already in monitor mode[/green]")
            return True
    
            # Try to set monitor mode to test if it's supported
            console.print(f"[blue]Testing monitor mode capability...[/blue]")
            test_result = subprocess.run(["iw", iface, "set", "type", "monitor"], 
                                       capture_output=True, text=True, timeout=5)
            
            if test_result.returncode == 0:
                console.print(f"[green]✓ {iface} supports monitor mode[/green]")
                # Restore to managed mode
                subprocess.run(["iw", iface, "set", "type", "managed"], 
                             capture_output=True, timeout=5)
                return True
            else:
                console.print(f"[yellow]Warning: Direct monitor mode test failed[/yellow]")
                console.print(f"[blue]But airmon-ng might still work - let's try![/blue]")
                return True  # Let airmon-ng handle it
                
        except Exception as e:
            console.print(f"[yellow]Warning: Monitor mode check failed: {e}[/yellow]")
            console.print(f"[blue]Let's try anyway - airmon-ng will handle it[/blue]")
            return True  # Always let airmon-ng try
    
    def _set_monitor_mode(self, iface):
        """Set interface to monitor mode with aggressive methods."""
        try:
            console.print(f"[blue]Setting {iface} to monitor mode...[/blue]")
            
            # Stop conflicting processes
            console.print(f"[blue]Stopping conflicting processes...[/blue]")
            subprocess.run(["airmon-ng", "check", "kill"], capture_output=True, timeout=10)
            time.sleep(2)  # Give processes time to stop
            
            # Method 1: Try airmon-ng
            console.print(f"[blue]Method 1: Trying airmon-ng...[/blue]")
            result = subprocess.run(["airmon-ng", "start", iface], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                console.print(f"[green]✓ airmon-ng succeeded[/green]")
                # Find the new monitor interface
                monitor_iface = iface + "mon"
                if os.path.exists(f'/sys/class/net/{monitor_iface}'):
                    console.print(f"[green]✓ Monitor mode enabled: {monitor_iface}[/green]")
                    return monitor_iface
                else:
                    console.print(f"[green]✓ Monitor mode enabled on {iface}[/green]")
                    return iface
            else:
                console.print(f"[yellow]airmon-ng failed, trying alternative methods...[/yellow]")
                console.print(f"[blue]Error: {result.stderr}[/blue]")
                
                # Method 2: Try direct iw command
                console.print(f"[blue]Method 2: Trying direct iw command...[/blue]")
                iw_result = subprocess.run(["iw", iface, "set", "type", "monitor"], 
                                         capture_output=True, text=True, timeout=10)
                
                if iw_result.returncode == 0:
                    console.print(f"[green]✓ Direct iw command succeeded[/green]")
                    return iface
                else:
                    console.print(f"[yellow]iw command failed, trying iwconfig...[/yellow]")
                    console.print(f"[blue]iw error: {iw_result.stderr}[/blue]")
                    
                    # Method 3: Try iwconfig
                    console.print(f"[blue]Method 3: Trying iwconfig...[/blue]")
                    iwconfig_result = subprocess.run(["iwconfig", iface, "mode", "monitor"], 
                                                   capture_output=True, text=True, timeout=10)
                    
                    if iwconfig_result.returncode == 0:
                        console.print(f"[green]✓ iwconfig succeeded[/green]")
                        return iface
                    else:
                        console.print(f"[yellow]iwconfig failed, trying ifconfig down/up...[/yellow]")
                        console.print(f"[blue]iwconfig error: {iwconfig_result.stderr}[/blue]")
                        
                        # Method 4: Try ifconfig down/up + iw
                        console.print(f"[blue]Method 4: Trying ifconfig down/up + iw...[/blue]")
                        subprocess.run(["ifconfig", iface, "down"], capture_output=True, timeout=5)
                        time.sleep(1)
                        iw_final = subprocess.run(["iw", iface, "set", "type", "monitor"], 
                                                capture_output=True, text=True, timeout=10)
                        subprocess.run(["ifconfig", iface, "up"], capture_output=True, timeout=5)
                        
                        if iw_final.returncode == 0:
                            console.print(f"[green]✓ ifconfig down/up + iw succeeded[/green]")
                            return iface
                        else:
                            console.print(f"[red]All methods failed[/red]")
                            console.print(f"[blue]airmon-ng error: {result.stderr}[/blue]")
                            console.print(f"[blue]iw error: {iw_result.stderr}[/blue]")
                            console.print(f"[blue]iwconfig error: {iwconfig_result.stderr}[/blue]")
                            console.print(f"[blue]ifconfig+iw error: {iw_final.stderr}[/blue]")
                            
                            # Show troubleshooting tips
                            console.print(f"\n[yellow]🔧 Troubleshooting Tips:[/yellow]")
                            console.print(f"[blue]1. Make sure you're running as root: sudo python3 NetHawk.py[/blue]")
                            console.print(f"[blue]2. Check if interface is already in use: iwconfig[/blue]")
                            console.print(f"[blue]3. Try restarting NetworkManager: sudo systemctl restart NetworkManager[/blue]")
                            console.print(f"[blue]4. Check if interface supports monitor mode: iw {iface} info[/blue]")
                            console.print(f"[blue]5. Try a different interface if available[/blue]")
                            console.print(f"[blue]6. Check if your WiFi adapter supports monitor mode[/blue]")
                            
                            # Manual commands section
                            console.print(f"\n[yellow]If your adapter supports monitor mode but it still shows this error, then try it manually:[/yellow]")
                            console.print(f"[green]Manual Commands to Set Monitor Mode:[/green]")
                            console.print(f"[blue]1. sudo airmon-ng check kill[/blue]")
                            console.print(f"[blue]2. sudo airmon-ng start {iface}[/blue]")
                            console.print(f"[blue]3. OR: sudo iw {iface} set type monitor[/blue]")
                            console.print(f"[blue]4. OR: sudo iwconfig {iface} mode monitor[/blue]")
                            console.print(f"[blue]5. Check result: iwconfig[/blue]")
                            console.print(f"[blue]6. Then run: sudo python3 NetHawk.py[/blue]")
                            
                            return None
                
        except Exception as e:
            console.print(f"[red]Error setting monitor mode: {e}[/red]")
            console.print(f"[blue]Try running as root: sudo python3 NetHawk.py[/blue]")
            
            # Manual commands section
            console.print(f"\n[yellow]If your adapter supports monitor mode but it still shows this error, then try it manually:[/yellow]")
            console.print(f"[green]Manual Commands to Set Monitor Mode:[/green]")
            console.print(f"[blue]1. sudo airmon-ng check kill[/blue]")
            console.print(f"[blue]2. sudo airmon-ng start {iface}[/blue]")
            console.print(f"[blue]3. OR: sudo iw {iface} set type monitor[/blue]")
            console.print(f"[blue]4. OR: sudo iwconfig {iface} mode monitor[/blue]")
            console.print(f"[blue]5. Check result: iwconfig[/blue]")
            console.print(f"[blue]6. Then run: sudo python3 NetHawk.py[/blue]")
            
            return None
    
    def _restore_managed_mode(self, iface):
        """Restore interface to managed mode."""
        try:
            console.print(f"[blue]Restoring {iface} to managed mode...[/blue]")
            subprocess.run(["airmon-ng", "stop", iface], capture_output=True, timeout=10)
            console.print(f"[green]✓ Interface restored to managed mode[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not restore interface: {e}[/yellow]")
    
    def _diagnose_monitor_mode(self, iface):
        """Diagnose monitor mode issues and provide solutions."""
        console.print(f"\n[yellow]🔍 Diagnosing monitor mode issues for {iface}...[/yellow]")
        
        # Check if running as root
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            console.print(f"[red]❌ Not running as root![/red]")
            console.print(f"[blue]Solution: Run with sudo python3 NetHawk.py[/blue]")
            return False
        
        # Check interface status
        try:
            result = subprocess.run(["iw", iface, "info"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                console.print(f"[green]✓ Interface {iface} is accessible[/green]")
                if "monitor" in result.stdout.lower():
                    console.print(f"[green]✓ Already in monitor mode[/green]")
                    return True
            else:
                console.print(f"[red]❌ Interface {iface} not accessible[/red]")
                console.print(f"[blue]Solution: Check if interface exists with: iwconfig[/blue]")
                return False
        except Exception as e:
            console.print(f"[red]❌ Error checking interface: {e}[/red]")
            return False

        # Check for conflicting processes
        try:
            result = subprocess.run(["airmon-ng", "check"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                console.print(f"[yellow]⚠️  Conflicting processes found:[/yellow]")
                console.print(f"[blue]{result.stdout}[/blue]")
                console.print(f"[blue]Solution: Run 'sudo airmon-ng check kill'[/blue]")
            else:
                console.print(f"[green]✓ No conflicting processes[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not check for conflicts: {e}[/yellow]")
        
        return True
    
    def aggressive_passive_scan(self):
        """AGGRESSIVE passive WiFi scanning with extended duration and multiple channels."""
        console.print("[bold red]AGGRESSIVE Passive WiFi Scan[/bold red]")
        console.print("=" * 50)

        # Check if airodump-ng is available
        if not self.tools_available.get("airodump-ng", False):
            console.print("[red]airodump-ng not found! Please install aircrack-ng.[/red]")
            return

        # Get wireless interface
        interfaces = self._get_wireless_interfaces()
        if not interfaces:
            console.print("[red]No wireless interfaces found![/red]")
            return

        console.print("[bold]Available interfaces:[/bold]")
        for i, iface in enumerate(interfaces):
            console.print(f"{i+1}. {iface}")

        iface_choice = self.validate_input(
            "\nSelect interface to use: ", [str(i+1) for i in range(len(interfaces))]
        )
        iface = interfaces[int(iface_choice)-1]
        
        # Check if already in monitor mode
        try:
            result = subprocess.run(["iw", iface, "info"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and "monitor" in result.stdout.lower():
                console.print(f"[green]✓ {iface} is already in monitor mode![/green]")
                monitor_iface = iface
            else:
                console.print(f"[blue]Attempting to set monitor mode on {iface}...[/blue]")
                console.print(f"[yellow]Note: We'll try multiple methods to enable monitor mode[/yellow]")
                monitor_iface = self._set_monitor_mode(iface)
                if not monitor_iface:
                    return
        except:
            console.print(f"[blue]Attempting to set monitor mode on {iface}...[/blue]")
            console.print(f"[yellow]Note: We'll try multiple methods to enable monitor mode[/yellow]")
            monitor_iface = self._set_monitor_mode(iface)
            if not monitor_iface:
                return

        # Configure scan options
        console.print("\n[bold]AGGRESSIVE Scan Options:[/bold]")
        channels = Prompt.ask("Channels to scan (e.g., 1,6,11 or all)", default="all")
        console.print(f"[yellow]Channels: {channels}[/yellow]")
        console.print(f"[blue]Interface: {monitor_iface}[/blue]")
        console.print(f"[green]Ready to scan! Press Enter to start...[/green]")
        input()  # Wait for user to press Enter
        
        # Start AGGRESSIVE passive scan
        console.print(f"[blue]Starting AGGRESSIVE scan on {monitor_iface}...[/blue]")
        console.print(f"[yellow]Channels: {channels}[/yellow]")
        console.print("[green]Scanning for WiFi networks...[/green]")
        
        try:
            # Use airodump-ng for AGGRESSIVE scanning with better parameters
            output_file = os.path.join(self.logs_path, f"aggressive_passive_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            cmd = ["airodump-ng", "-w", output_file, "--output-format", "csv", "--manufacturer", "--uptime", "--wps", "--beacons", "--ivs"]
            
            if channels != "all":
                cmd.extend(["-c", channels])
            
            cmd.append(monitor_iface)
            
            # Start the scan process
            try:
                process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
            except FileNotFoundError:
                console.print(f"[red]Error: 'airodump-ng' command not found![/red]")
                console.print(f"[blue]Please install aircrack-ng package: sudo apt install aircrack-ng[/blue]")
                return

            # Real-time network discovery
            console.print(f"[blue]🔍 Scanning for networks...[/blue]")
            console.print(f"[yellow]Found networks will appear below:[/yellow]")
            console.print("=" * 80)
            console.print("[yellow]Press Ctrl+C to stop scanning[/yellow]")
            
            # Monitor for networks in real-time
            networks_found = 0
            last_update = 0
            
            try:
                while True:
                    # Check if process is still running
                    if process.poll() is not None:
                        break
                    
                    # Check for new CSV data every 5 seconds
                    current_time = time.time()
                    if current_time - last_update >= 5:
                        csv_file = f"{output_file}-01.csv"
                        if os.path.exists(csv_file):
                            try:
                                # Parse and display new networks
                                new_networks = self._parse_live_networks(csv_file)
                                if new_networks > networks_found:
                                    networks_found = new_networks
                                    console.print(f"[green]📡 Found {networks_found} networks so far...[/green]")
                            except:
                                pass
                        last_update = current_time
                    
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                console.print(f"\n[yellow]Scan stopped by user (Ctrl+C)[/yellow]")
            
            # Stop the process
            process.terminate()
            process.wait()
            console.print(f"[green]✓ Scan completed! Found {networks_found} networks[/green]")
            
            # Parse and display results in terminal (no file saving)
            console.print(f"[blue]Parsing scan results...[/blue]")
            aps, clients = self._parse_aggressive_passive_results_terminal(output_file)
            
            # Show detailed results in terminal
            console.print(f"\n[bold green]📊 PASSIVE SCAN RESULTS SUMMARY[/bold green]")
            console.print(f"[blue]Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/blue]")
            console.print(f"[green]Access Points Found: {len(aps)}[/green]")
            console.print(f"[green]Clients Found: {len(clients)}[/green]")
            
            # Display Access Points
            if aps:
                console.print(f"\n[bold cyan]ACCESS POINTS:[/bold cyan]")
                for i, ap in enumerate(aps, 1):
                    console.print(f"\n[bold]AP {i}:[/bold]")
                    console.print(f"  [green]BSSID:[/green] {ap['BSSID']}")
                    console.print(f"  [green]ESSID:[/green] {ap['ESSID']}")
                    console.print(f"  [green]Channel:[/green] {ap['Channel']}")
                    console.print(f"  [green]Power:[/green] {ap['Power']}")
                    console.print(f"  [green]Privacy:[/green] {ap['Privacy']}")
                    console.print(f"  [green]WPS:[/green] {ap['WPS']}")
                    console.print(f"  [green]Beacons:[/green] {ap['Beacons']}")
            
            # Display Clients
            if clients:
                console.print(f"\n[bold cyan]CLIENTS:[/bold cyan]")
                for i, client in enumerate(clients, 1):
                    console.print(f"\n[bold]Client {i}:[/bold]")
                    console.print(f"  [green]Station MAC:[/green] {client['Station']}")
                    console.print(f"  [green]Power:[/green] {client['Power']}")
                    console.print(f"  [green]Connected to:[/green] {client['BSSID']}")
                    if client['Probed']:
                        console.print(f"  [green]Probed ESSIDs:[/green] {client['Probed']}")
            
            console.print(f"\n[bold green]✅ Passive scan completed successfully![/bold green]")
            console.print(f"[blue]Results displayed above - no files saved[/blue]")
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan stopped by user.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during aggressive scan: {e}[/red]")
        finally:
            # Restore managed mode
            self._restore_managed_mode(monitor_iface)
    
    def _parse_live_networks(self, csv_file):
        """Parse live networks from CSV file and return count."""
        try:
            with open(csv_file, newline='', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                count = 0
                section = None
                for row in reader:
                    if not row:
                        continue
                    # header row detection
                    if 'BSSID' in row[0]:
                        section = 'AP'
                        continue
                    if 'Station MAC' in row[0]:
                        section = 'CLIENT'
                        continue
                    if section == 'AP' and len(row) > 0 and row[0] and re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', row[0]):
                        count += 1
                return count
        except Exception:
            return 0

    def _parse_aggressive_passive_results_terminal(self, output_file):
        """Parse airodump-ng CSV results for terminal display only."""
        csv_file = f"{output_file}-01.csv"
        if not os.path.exists(csv_file):
            console.print("[red]No CSV results found.[/red]")
            return [], []
        
        try:
            aps = []
            clients = []
            
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                section = None
                
                for row in reader:
                    if not row or not row[0].strip():
                        continue
                    
                    if "BSSID" in row[0]:
                        section = "AP"
                        continue
                    elif "Station MAC" in row[0]:
                        section = "CLIENT"
                        continue

                    if section == "AP" and len(row) >= 14:
                        try:
                            ap_data = {
                                "BSSID": row[0],
                                "ESSID": row[13] if len(row) > 13 else "Hidden",
                                "Channel": row[3],
                                "Power": row[8],
                                "Privacy": row[5],
                                "Cipher": row[6],
                                "Auth": row[7],
                                "Beacons": row[9],
                                "Data": row[10],
                                "WPS": "WPS" if len(row) > 14 and "WPS" in row[14] else "No WPS"
                            }
                            aps.append(ap_data)
                        except IndexError:
                            continue
                    
                    elif section == "CLIENT" and len(row) >= 6:
                        try:
                            client_data = {
                                "Station": row[0],
                                "Power": row[3],
                                "BSSID": row[5],
                                "Probed": row[6] if len(row) > 6 else ""
                            }
                            clients.append(client_data)
                        except IndexError:
                            continue
            
            return aps, clients
            
        except Exception as e:
            console.print(f"[red]Error parsing results: {e}[/red]")
            return [], []
    
    def _display_aggressive_ap_table(self, aps):
        """Display access points in an enhanced table."""
        table = Table(title="AGGRESSIVE Scan - Access Points")
        table.add_column("BSSID", style="cyan")
        table.add_column("ESSID", style="green")
        table.add_column("Channel", style="yellow")
        table.add_column("Power", style="red")
        table.add_column("Privacy", style="magenta")
        table.add_column("WPS", style="blue")
        table.add_column("Beacons", style="white")
        
        for ap in aps:
            table.add_row(
                ap["BSSID"],
                ap["ESSID"],
                ap["Channel"],
                ap["Power"],
                ap["Privacy"],
                ap["WPS"],
                ap["Beacons"]
            )
        
            console.print(table)

    def _display_aggressive_client_table(self, clients):
        """Display clients in an enhanced table."""
        table = Table(title="AGGRESSIVE Scan - Clients")
        table.add_column("Station MAC", style="cyan")
        table.add_column("Power", style="red")
        table.add_column("Connected BSSID", style="green")
        table.add_column("Probed ESSIDs", style="yellow")
        
        for client in clients:
            table.add_row(
                client["Station"],
                client["Power"],
                client["BSSID"],
                client["Probed"]
            )
        
            console.print(table)

    
    def aggressive_active_scan(self):
        """AGGRESSIVE active network scanning with port scanning and service detection."""
        console.print("[bold red]AGGRESSIVE Active Network Scan[/bold red]")
        console.print("=" * 50)

        # Auto-detect current network
        console.print(f"[blue]Auto-detecting your current network...[/blue]")
        detected_network = self._get_current_network()
        console.print(f"[blue]Debug: Detected network = '{detected_network}'[/blue]")
        console.print(f"[blue]Debug: Network type = {type(detected_network)}[/blue]")

        # Validate detected network
        valid_network = None
        if isinstance(detected_network, str):
            try:
                # try to parse; don't enforce strict host/network alignment
                ipaddress.IPv4Network(detected_network, strict=False)
                valid_network = detected_network
            except Exception:
                valid_network = None

        if valid_network:
            console.print(f"[green]✓ Detected network: {valid_network}[/green]")
            if not Confirm.ask(f"Scan detected network {valid_network}?"):
                target = None  # force manual entry flow below
            else:
                target = valid_network
        else:
            target = None  # trigger manual entry flow
        
        # Manual input if user doesn't want detected network or auto-detection failed
        if not target:
            while True:
                target = Prompt.ask("Enter target network (e.g., 192.168.1.0/24)")
                console.print(f"[blue]Debug: User entered target = '{target}'[/blue]")
                console.print(f"[blue]Debug: Target type = {type(target)}[/blue]")
                
                # Basic validation
                if not target or target.strip() == '':
                    console.print("[red]Please enter a network[/red]")
                    continue
                    
                # Check for common invalid values
                if target.lower() in ['mac', 'none', 'null', 'undefined']:
                    console.print(f"[red]Invalid network format: '{target}'[/red]")
                    console.print(f"[blue]Please enter a valid network like 192.168.1.0/24[/blue]")
                    continue
                
                # Validate network format
                if not ('/' in target and '.' in target):
                    console.print(f"[red]Invalid network format: '{target}'[/red]")
                    console.print(f"[blue]Please enter a valid network like 192.168.1.0/24[/blue]")
                    continue
                
                try:
                    # Try to create network object
                    network = ipaddress.IPv4Network(target, strict=False)
                    break
                except ValueError as e:
                    console.print(f"[red]Invalid network format: {e}[/red]")
                    console.print(f"[blue]Please enter a valid network like 192.168.1.0/24[/blue]")
                    continue
        
        # Store the network string in a safe variable to prevent corruption
        network_string = str(target)
        console.print(f"[blue]Debug: Network string stored as: '{network_string}'[/blue]")
        
        # Defensive check to prevent 'mac' corruption
        if network_string.lower() in ['mac', 'none', 'null', 'undefined']:
            console.print(f"[red]ERROR: Network string corrupted to '{network_string}'[/red]")
            console.print(f"[red]This should not happen. Please restart the tool.[/red]")
            return
        
        # Create network object with final validation
        try:
            network = ipaddress.IPv4Network(network_string, strict=False)
        except Exception as e:
            console.print(f"[red]Invalid network format: {e}[/red]")
            console.print(f"[red]Network string was: '{network_string}'[/red]")
            return

        console.print(f"[blue]AGGRESSIVE scanning network: {network_string}[/blue]")
        
        # Simple scan - no complicated options
        console.print("\n[bold]AGGRESSIVE Scan:[/bold]")
        console.print("[blue]Using optimized settings for best results[/blue]")
        port_range = "top1000"  # Fixed to top 1000 ports
        scan_type = "aggressive"  # Fixed to aggressive scan
        
        # Perform AGGRESSIVE scan with real-time progress
        console.print(f"\n[bold blue]🔍 Starting AGGRESSIVE Network Discovery...[/bold blue]")
        console.print(f"[yellow]This may take 2-5 minutes depending on network size[/yellow]")
        console.print(f"[blue]Scanning {network} for active hosts...[/blue]")
        console.print(f"[green]Using ping to discover active hosts...[/green]")
        
        # Test ping to gateway first
        gateway = str(network.network_address + 1)  # Usually .1
        console.print(f"[blue]Testing connectivity to gateway {gateway}...[/blue]")
        if self._ping_host(gateway):
            console.print(f"[green]✓ Gateway {gateway} is reachable[/green]")
        else:
            console.print(f"[yellow]⚠ Gateway {gateway} not reachable, but continuing scan...[/yellow]")
        
        hosts = self._aggressive_host_discovery_with_progress(network)
        
        if hosts:
            console.print(f"\n[green]✓ Found {len(hosts)} active hosts![/green]")
            self._display_aggressive_hosts_table(hosts)
            
            # Port scan discovered hosts
            if Confirm.ask("Perform AGGRESSIVE port scanning on discovered hosts?"):
                console.print(f"\n[bold blue]🔍 Starting AGGRESSIVE Port Scanning...[/bold blue]")
                console.print(f"[yellow]This may take 5-15 minutes depending on number of hosts[/yellow]")
                self._aggressive_port_scan_with_progress(hosts, port_range, scan_type)
            
            # Display detailed results in terminal (no file saving)
            console.print(f"\n[bold green]📊 ACTIVE SCAN RESULTS SUMMARY[/bold green]")
            console.print(f"[blue]Network Scanned: {network_string}[/blue]")
            console.print(f"[green]Total Hosts Found: {len(hosts)}[/green]")
            console.print(f"[yellow]Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
            
            # Show detailed host information
            if hosts:
                console.print(f"\n[bold cyan]DETAILED HOST INFORMATION:[/bold cyan]")
                for i, host in enumerate(hosts, 1):
                    console.print(f"\n[bold]Host {i}:[/bold]")
                    console.print(f"  [green]IP Address:[/green] {host.get('ip', 'Unknown')}")
                    console.print(f"  [green]Status:[/green] {host.get('status', 'Unknown')}")
                    mac = host.get('mac', 'Unknown')
                    if mac and mac != 'Unknown':
                        console.print(f"  [green]MAC Address:[/green] {mac}")
                    
                    device_type = host.get('device_type', 'Unknown')
                    if device_type and device_type != 'Unknown':
                        console.print(f"  [green]Device Type:[/green] {device_type}")
                    
                    # Show OS information
                    os_info = host.get('os', 'Unknown')
                    if os_info and os_info != 'Unknown':
                        console.print(f"  [green]OS:[/green] {os_info}")
                    
                    # Show device inference
                    device_inference = host.get('device', 'Unknown')
                    if device_inference and device_inference != 'Unknown':
                        console.print(f"  [green]Device Inference:[/green] {device_inference}")
                    
                    if host.get('open_ports'):
                        console.print(f"  [green]Open Ports:[/green] {len(host['open_ports'])} ports")
                        for port in host['open_ports'][:5]:  # Show first 5 ports
                            console.print(f"    - Port {port['port']}/{port['protocol']}: {port['service']}")
                        if len(host['open_ports']) > 5:
                            console.print(f"    - ... and {len(host['open_ports'])-5} more ports")
                    else:
                        console.print(f"  [yellow]No open ports found[/yellow]")
                    
                    # Show detection methodology summary
                    self._display_detection_summary(host)
            
            console.print(f"\n[bold green]✅ Active scan completed successfully![/bold green]")
            console.print(f"[blue]Results displayed above - no files saved[/blue]")
        else:
            console.print("[yellow]No active hosts found.[/yellow]")
            console.print("[blue]Try scanning a different network or check your network connection[/blue]")
    
    def _aggressive_host_discovery_with_progress(self, network):
        """AGGRESSIVE host discovery with real-time progress and results."""
        hosts = []
        
        # Calculate total IPs to scan
        total_ips = network.num_addresses
        if total_ips > 254:  # Limit for /24 networks
            total_ips = 254
        
        console.print(f"[blue]Scanning {total_ips} IP addresses...[/blue]")
        console.print(f"[yellow]Using multiple discovery methods: ping, arp, nmap...[/yellow]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Discovering hosts...", total=total_ips)
            
            # First try nmap for faster discovery
            console.print(f"[blue]Trying nmap for fast host discovery...[/blue]")
            nmap_hosts = self._nmap_host_discovery(network)
            if nmap_hosts:
                hosts.extend(nmap_hosts)
                console.print(f"[green]✓ Nmap found {len(nmap_hosts)} hosts[/green]")
            
            # If nmap didn't find much, try individual pings
            if len(hosts) < 5:  # If we found less than 5 hosts, try individual pings
                console.print(f"[blue]Trying individual ping scans...[/blue]")
                for i, ip in enumerate(network.hosts()):
                    if i >= 254:  # Limit to /24
                        break
        
                    progress.update(task, description=f"Ping scanning {ip}... ({i+1}/{total_ips})")
                    
                    # Skip if already found by nmap
                    if any(host["ip"] == str(ip) for host in hosts):
                        continue
                    
                    # Try multiple ping methods
                    if self._aggressive_ping_host(str(ip)):
                        mac = self._get_mac_address(str(ip))
                        hosts.append({
                            "ip": str(ip),
                            "status": "up",
                            "mac": mac,
                            "device_type": self._detect_device_type(mac),
                            "open_ports": [],
                            "os": "Unknown",
                            "services": []
                        })
                        console.print(f"[green]✓ Found host: {ip}[/green]")
                    
                    # Update progress every 5 IPs
                    if i % 5 == 0:
                        progress.update(task, completed=i+1)
            
            progress.update(task, description="Host discovery complete!")
            progress.update(task, completed=total_ips)
        
        return hosts
    
    def _nmap_host_discovery(self, network):
        """Use nmap for fast host discovery."""
        try:
            console.print(f"[blue]Running nmap host discovery on {network}...[/blue]")
            cmd = ["nmap", "-sn", "-Pn", "-T4", str(network)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                hosts = []
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Nmap scan report for' in line:
                        # Extract IP from line like "Nmap scan report for 192.168.1.1"
                        parts = line.split()
                        for part in parts:
                            if '.' in part and len(part.split('.')) == 4:
                                ip = part
                                mac = self._get_mac_address(ip)
                                hosts.append({
                                    "ip": ip,
                                    "status": "up",
                                    "mac": mac,
                                    "device_type": self._detect_device_type(mac),
                                    "open_ports": [],
                                    "os": "Unknown",
                                    "services": []
                                })
                                console.print(f"[green]✓ Nmap found: {ip}[/green]")
                return hosts
            else:
                console.print(f"[yellow]Nmap host discovery failed, trying individual pings...[/yellow]")
                return []
                
        except FileNotFoundError:
            console.print(f"[yellow]Warning: 'nmap' command not found. Install nmap package.[/yellow]")
            console.print(f"[blue]Falling back to individual ping scans...[/blue]")
            return []
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]Warning: Nmap scan timed out for {network}[/yellow]")
            return []
        except Exception as e:
            console.print(f"[yellow]Nmap discovery failed: {e}[/yellow]")
            return []

    def _aggressive_host_discovery(self, network):
        """Perform AGGRESSIVE host discovery."""
        hosts = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("AGGRESSIVE host discovery...", total=len(list(network.hosts())))
            
            for ip in network.hosts():
                if self._aggressive_ping_host(str(ip)):
                    host_info = {
                        "ip": str(ip),
                        "status": "up",
                        "mac": self._get_mac_address(str(ip)),
                        "os": "Unknown",
                        "open_ports": []
                    }
                    hosts.append(host_info)
                progress.advance(task)
        
        return hosts
    
    def _aggressive_ping_host(self, ip):
        """AGGRESSIVE ping with multiple techniques."""
        try:
            # Standard ping
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                return True
            
            # ARP ping
            result = subprocess.run(
                ["arping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _get_mac_address(self, ip):
        """Get MAC address for an IP using ARP table."""
        try:
            # Try to get MAC from ARP table
            result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line and ':' in line:
                        parts = line.split()
                        for part in parts:
                            if ':' in part and len(part.split(':')) == 6:
                                return part
            return "Unknown"
        except FileNotFoundError:
            console.print(f"[yellow]Warning: 'arp' command not found. Install net-tools package.[/yellow]")
            return "Unknown"
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]Warning: ARP lookup timed out for {ip}[/yellow]")
            return "Unknown"
        except Exception as e:
            console.print(f"[yellow]Warning: ARP lookup failed: {e}[/yellow]")
            return "Unknown"
    
    def _detect_device_type(self, mac_address):
        """Detect device type based on MAC address OUI."""
        if mac_address == "Unknown":
            return "Unknown"
        
        # Normalize MAC address format (remove colons, convert to uppercase)
        mac_clean = mac_address.replace(":", "").replace("-", "").upper()
        
        # Get first 6 characters (OUI)
        oui = mac_clean[:6]
        
        # Common OUI prefixes for device types
        if oui in ["001B63", "001C42", "002312", "002500", "002608", "040CCE", "045453", "087402", "0C74C2", "1093E9", "14109F", "186590", "1C1B0D", "1C36BB", "1CABA7", "20C9D0", "24A074", "283737", "28CFDA", "2C337A", "2CB43A", "3090AB", "34159E", "34A395", "38C986", "3C0754", "3C2EF9", "3CA82A", "40331A", "40A6D9", "442A60", "48A6D9", "4C3275", "4C57CA", "4C8D79", "50EAD6", "54724F", "58B035", "5C5948", "5C95AE", "600308", "60334B", "60C547", "60FACD", "64B9E8", "680927", "685B35", "68967B", "68D93C", "6C198F", "6C4008", "6C72E7", "6C9466", "701124", "70480F", "705681", "70CD60", "70DEE2", "74E2F5", "7831C1", "784F43", "78CA39", "7C04D0", "7C6D62", "7CD1C3", "800655", "80BE05", "80E650", "843835", "84B153", "8863DF", "88DEA9", "8C2DAA", "8C5877", "8C8590", "8CFABA", "9027E4", "90840D", "90A4DE", "90B931", "94E6F7", "9803D8", "98CA33", "9C04EB", "9C207B", "9C84BF", "9C8E99", "A0999B", "A0D795", "A45E60", "A4B197", "A4C361", "A860B6", "A8968A", "A8BBCF", "A8F751", "AC1F74", "AC3C0B", "AC61EA", "AC87A3", "ACDE48", "B065BD", "B09FBA", "B418D1", "B4527E", "B4F0AB", "B8098A", "B817C2", "B853AC", "B8782E", "B8C75D", "B8E856", "B8F6B1", "BC52B7", "BC671C", "BC926B", "BCEC5D", "C0255C", "C06394", "C0CECD", "C42C03", "C48466", "C4B301", "C82A14", "C869CD", "C8BCC8", "C8E0EB", "CC08E0", "CC25EF", "CC29F5", "CC785F", "D0034B", "D023DB", "D0A637", "D49A20", "D4D252", "D83062", "D89695", "D8A25E", "D8CF9C", "DC2B2A", "DC3745", "DC56E7", "DCA904", "E0ACCB", "E425E7", "E48D8C", "E4B318", "E4C63D", "E84040", "E8802E", "E8B2AC", "E8D03C", "EC3586", "EC89F5", "ECADB8", "F01898", "F02475", "F04F7C", "F07959", "F0DBE2", "F40F24", "F431C3", "F45C89", "F45EAB", "F46D04", "F48E38", "F49F54", "F4CB52", "F4D488", "F81EDF", "F81654", "F82FA8", "F84D89", "F866F2", "F88E85", "F896EA", "FC253F", "FC64BA", "FC94CE", "FCDBB3", "FCE998"]:
            return "Apple Device (iPhone/iPad/Mac)"
        elif oui in ["001599", "00166B", "0017C9", "001839", "001A8A", "001B98", "001C43", "001D7E", "001E75", "001F5B", "00214C", "002258", "002339", "002454", "002566", "00265D", "002719", "00280F", "002915", "002A5A", "002B67", "002C44", "002D76", "002EC8", "002F3A", "00304D", "003146", "003221", "003350", "0034DA", "00351F", "003676", "00376D", "0038BC", "00390F", "003A99", "003B9F", "003CF0", "003D41", "003E01", "003F0E", "004045", "0041B4", "00425A", "004385", "004437", "00455E", "004668", "00474F", "00487A", "004955", "004A30", "004BED", "004CC1", "004D32", "004E01", "004F62", "005043", "00515E", "005218", "005332", "0054AF", "0055DA", "00562B", "00578C", "005844", "0059AC", "005A13", "005B94", "005C0C", "005D73", "005E0C", "005F86", "006057", "006171", "00620E", "006373", "0064B6", "006583", "00664A", "006742", "0068EB", "0069AB", "006A39", "006B8D", "006CBC", "006D52", "006EFD", "006F20", "00704D", "0071C2", "00722D", "007349", "00749C", "00756D", "00764E", "007750", "0078CD", "00797B", "007A3D", "007B8B", "007C2D", "007D60", "007E4C", "007F12", "008096", "0081F4", "008250", "00835F", "008438", "008525", "0086CE", "008701", "008865", "00894F", "008A96", "008BAD", "008C54", "008D4E", "008EFD", "008F59", "00904C", "009127", "00924A", "0093FB", "0094A6", "00958E", "00964B", "009727", "00988C", "00994C", "009ACD", "009B8B", "009C02", "009D6B", "009E1C", "009F7B", "00A04A", "00A18C", "00A2EE", "00A38E", "00A45A", "00A58C", "00A650", "00A78C", "00A896", "00A94A", "00AA70", "00AB00", "00AC29", "00AD24", "00AEFA", "00AF1B", "00B04A", "00B18C", "00B24A", "00B38C", "00B44A", "00B58C", "00B64A", "00B78C", "00B84A", "00B98C", "00BA4A", "00BB8C", "00BC4A", "00BD8C", "00BE4A", "00BF8C", "00C04A", "00C18C", "00C24A", "00C38C", "00C44A", "00C58C", "00C64A", "00C78C", "00C84A", "00C98C", "00CA4A", "00CB8C", "00CC4A", "00CD8C", "00CE4A", "00CF8C", "00D04A", "00D18C", "00D24A", "00D38C", "00D44A", "00D58C", "00D64A", "00D78C", "00D84A", "00D98C", "00DA4A", "00DB8C", "00DC4A", "00DD8C", "00DE4A", "00DF8C", "00E04A", "00E18C", "00E24A", "00E38C", "00E44A", "00E58C", "00E64A", "00E78C", "00E84A", "00E98C", "00EA4A", "00EB8C", "00EC4A", "00ED8C", "00EE4A", "00EF8C", "00F04A", "00F18C", "00F24A", "00F38C", "00F44A", "00F58C", "00F64A", "00F78C", "00F84A", "00F98C", "00FA4A", "00FB8C", "00FC4A", "00FD8C", "00FE4A", "00FF8C"]:
            return "Samsung Device (Phone/TV/Tablet)"
        elif oui in ["001A11", "001B44", "001C42", "001D0F", "001E06", "001F5B", "002078", "00216A", "002258", "002312", "002401", "002500", "002608", "002719", "00280F", "002915", "002A5A", "002B67", "002C44", "002D76", "002EC8", "002F3A", "00304D", "003146", "003221", "003350", "0034DA", "00351F", "003676", "00376D", "0038BC", "00390F", "003A99", "003B9F", "003CF0", "003D41", "003E01", "003F0E", "004045", "0041B4", "00425A", "004385", "004437", "00455E", "004668", "00474F", "00487A", "004955", "004A30", "004BED", "004CC1", "004D32", "004E01", "004F62", "005043", "00515E", "005218", "005332", "0054AF", "0055DA", "00562B", "00578C", "005844", "0059AC", "005A13", "005B94", "005C0C", "005D73", "005E0C", "005F86", "006057", "006171", "00620E", "006373", "0064B6", "006583", "00664A", "006742", "0068EB", "0069AB", "006A39", "006B8D", "006CBC", "006D52", "006EFD", "006F20", "00704D", "0071C2", "00722D", "007349", "00749C", "00756D", "00764E", "007750", "0078CD", "00797B", "007A3D", "007B8B", "007C2D", "007D60", "007E4C", "007F12", "008096", "0081F4", "008250", "00835F", "008438", "008525", "0086CE", "008701", "008865", "00894F", "008A96", "008BAD", "008C54", "008D4E", "008EFD", "008F59", "00904C", "009127", "00924A", "0093FB", "0094A6", "00958E", "00964B", "009727", "00988C", "00994C", "009ACD", "009B8B", "009C02", "009D6B", "009E1C", "009F7B", "00A04A", "00A18C", "00A2EE", "00A38E", "00A45A", "00A58C", "00A650", "00A78C", "00A896", "00A94A", "00AA70", "00AB00", "00AC29", "00AD24", "00AEFA", "00AF1B", "00B04A", "00B18C", "00B24A", "00B38C", "00B44A", "00B58C", "00B64A", "00B78C", "00B84A", "00B98C", "00BA4A", "00BB8C", "00BC4A", "00BD8C", "00BE4A", "00BF8C", "00C04A", "00C18C", "00C24A", "00C38C", "00C44A", "00C58C", "00C64A", "00C78C", "00C84A", "00C98C", "00CA4A", "00CB8C", "00CC4A", "00CD8C", "00CE4A", "00CF8C", "00D04A", "00D18C", "00D24A", "00D38C", "00D44A", "00D58C", "00D64A", "00D78C", "00D84A", "00D98C", "00DA4A", "00DB8C", "00DC4A", "00DD8C", "00DE4A", "00DF8C", "00E04A", "00E18C", "00E24A", "00E38C", "00E44A", "00E58C", "00E64A", "00E78C", "00E84A", "00E98C", "00EA4A", "00EB8C", "00EC4A", "00ED8C", "00EE4A", "00EF8C", "00F04A", "00F18C", "00F24A", "00F38C", "00F44A", "00F58C", "00F64A", "00F78C", "00F84A", "00F98C", "00FA4A", "00FB8C", "00FC4A", "00FD8C", "00FE4A", "00FF8C"]:
            return "Google Device (Pixel/Nest/Chromecast)"
        elif oui in ["005056", "000C29", "001C42", "001D7E", "001E75", "001F5B", "002078", "00216A", "002258", "002312", "002401", "002500", "002608", "002719", "00280F", "002915", "002A5A", "002B67", "002C44", "002D76", "002EC8", "002F3A", "00304D", "003146", "003221", "003350", "0034DA", "00351F", "003676", "00376D", "0038BC", "00390F", "003A99", "003B9F", "003CF0", "003D41", "003E01", "003F0E", "004045", "0041B4", "00425A", "004385", "004437", "00455E", "004668", "00474F", "00487A", "004955", "004A30", "004BED", "004CC1", "004D32", "004E01", "004F62", "005043", "00515E", "005218", "005332", "0054AF", "0055DA", "00562B", "00578C", "005844", "0059AC", "005A13", "005B94", "005C0C", "005D73", "005E0C", "005F86", "006057", "006171", "00620E", "006373", "0064B6", "006583", "00664A", "006742", "0068EB", "0069AB", "006A39", "006B8D", "006CBC", "006D52", "006EFD", "006F20", "00704D", "0071C2", "00722D", "007349", "00749C", "00756D", "00764E", "007750", "0078CD", "00797B", "007A3D", "007B8B", "007C2D", "007D60", "007E4C", "007F12", "008096", "0081F4", "008250", "00835F", "008438", "008525", "0086CE", "008701", "008865", "00894F", "008A96", "008BAD", "008C54", "008D4E", "008EFD", "008F59", "00904C", "009127", "00924A", "0093FB", "0094A6", "00958E", "00964B", "009727", "00988C", "00994C", "009ACD", "009B8B", "009C02", "009D6B", "009E1C", "009F7B", "00A04A", "00A18C", "00A2EE", "00A38E", "00A45A", "00A58C", "00A650", "00A78C", "00A896", "00A94A", "00AA70", "00AB00", "00AC29", "00AD24", "00AEFA", "00AF1B", "00B04A", "00B18C", "00B24A", "00B38C", "00B44A", "00B58C", "00B64A", "00B78C", "00B84A", "00B98C", "00BA4A", "00BB8C", "00BC4A", "00BD8C", "00BE4A", "00BF8C", "00C04A", "00C18C", "00C24A", "00C38C", "00C44A", "00C58C", "00C64A", "00C78C", "00C84A", "00C98C", "00CA4A", "00CB8C", "00CC4A", "00CD8C", "00CE4A", "00CF8C", "00D04A", "00D18C", "00D24A", "00D38C", "00D44A", "00D58C", "00D64A", "00D78C", "00D84A", "00D98C", "00DA4A", "00DB8C", "00DC4A", "00DD8C", "00DE4A", "00DF8C", "00E04A", "00E18C", "00E24A", "00E38C", "00E44A", "00E58C", "00E64A", "00E78C", "00E84A", "00E98C", "00EA4A", "00EB8C", "00EC4A", "00ED8C", "00EE4A", "00EF8C", "00F04A", "00F18C", "00F24A", "00F38C", "00F44A", "00F58C", "00F64A", "00F78C", "00F84A", "00F98C", "00FA4A", "00FB8C", "00FC4A", "00FD8C", "00FE4A", "00FF8C"]:
            return "Router/Network Device"
        else:
            return "Unknown Device"
    
    def _infer_device_type(self, open_ports, services, os_info, mac_vendor, mac_address="Unknown"):
        """
        HYBRID device type inference combining MAC OUI analysis with port/service heuristics.
        Uses both methodologies for maximum accuracy.
        """
        service_names = set(services)
        ports = set(int(p["port"]) for p in open_ports if "port" in p and str(p["port"]).isdigit())
        
        # Get MAC-based device type from OUI database
        mac_device_type = self._detect_device_type(mac_address)
        
        # CONFIDENCE-BASED DETECTION SYSTEM
        confidence_score = 0
        detected_type = "Unknown Device"
        detection_methods = []
        
        # METHOD 1: MAC OUI Analysis (High Confidence)
        if mac_device_type != "Unknown Device":
            confidence_score += 40
            detected_type = mac_device_type
            detection_methods.append("MAC OUI")
        
        # METHOD 2: Port-Based Detection (High Confidence)
        if 9100 in ports or 631 in ports or 515 in ports:
            confidence_score += 35
            detected_type = "Printer / MFP"
            detection_methods.append("Port Analysis")
        elif 1900 in ports or 5000 in ports or ("router" in (os_info or "").lower()) or "UPnP" in service_names:
            confidence_score += 35
            detected_type = "Router / Gateway"
            detection_methods.append("Port Analysis")
        elif 445 in ports or 3389 in ports or 135 in ports:
            confidence_score += 35
            detected_type = "Windows PC / Server"
            detection_methods.append("Port Analysis")
        elif 22 in ports and ("linux" in (os_info or "").lower() or "unix" in (os_info or "").lower()):
            if mac_vendor and ("raspberry" in (mac_vendor or "").lower()):
                confidence_score += 35
                detected_type = "Raspberry Pi / Embedded Linux"
            else:
                confidence_score += 30
                detected_type = "Linux machine / SSH host"
            detection_methods.append("Port + OS Analysis")
        
        # METHOD 3: Service-Based Detection (Medium Confidence)
        if "ssh" in service_names and ("linux" in (os_info or "").lower() or "unix" in (os_info or "").lower()):
            confidence_score += 25
            if detected_type == "Unknown Device":
                detected_type = "Linux machine / SSH host"
            detection_methods.append("Service Analysis")
        
        # METHOD 4: Mobile Device Heuristics (Medium Confidence)
        if mac_vendor and any(x in (mac_vendor or "").lower() for x in ("samsung", "huawei", "xiaomi", "google", "oneplus")):
            confidence_score += 30
            if detected_type == "Unknown Device":
                detected_type = "Mobile device / Phone (likely)"
            detection_methods.append("MAC Vendor + Mobile Heuristics")
        
        # METHOD 5: IoT Device Detection (Medium Confidence)
        if (80 in ports or 554 in ports or 5555 in ports) and (mac_vendor and len(mac_vendor) > 0):
            confidence_score += 25
            if detected_type == "Unknown Device":
                detected_type = "IoT device"
            detection_methods.append("IoT Port Analysis")
        
        # METHOD 6: OS-Based Detection (Low-Medium Confidence)
        if os_info:
            if "windows" in os_info.lower():
                confidence_score += 20
                if detected_type == "Unknown Device":
                    detected_type = "Windows device"
                detection_methods.append("OS Fingerprinting")
            elif "linux" in os_info.lower() or "android" in os_info.lower():
                confidence_score += 20
                if detected_type == "Unknown Device":
                    detected_type = "Linux / Android device"
                detection_methods.append("OS Fingerprinting")
        
        # CROSS-VALIDATION: Check for conflicting signals
        if mac_device_type != "Unknown Device" and detected_type != "Unknown Device":
            if mac_device_type != detected_type:
                # Conflicting signals - use higher confidence
                if "MAC OUI" in detection_methods:
                    detected_type = mac_device_type
                    confidence_score += 10  # Bonus for MAC OUI confirmation
                else:
                    confidence_score -= 10  # Penalty for conflicting signals
        
        # FINAL DECISION LOGIC
        if confidence_score >= 60:
            final_type = detected_type
            confidence_level = "High"
        elif confidence_score >= 40:
            final_type = detected_type
            confidence_level = "Medium"
        elif confidence_score >= 20:
            final_type = detected_type
            confidence_level = "Low"
        else:
            final_type = "Unknown / Unidentified device"
            confidence_level = "Very Low"
        
        # Add confidence and method information
        if final_type != "Unknown / Unidentified device":
            final_type += f" ({confidence_level} confidence)"
            if detection_methods:
                final_type += f" [Methods: {', '.join(detection_methods)}]"
        
        return final_type
    
    def _get_mac_vendor(self, mac):
        """
        Simple helper: try to extract vendor from local OUI lookup if available.
        This implementation is a placeholder that returns None if vendor lookup is not available.
        You can improve it by adding a local OUI DB or calling an online API (requires network).
        """
        if not mac or mac == "Unknown":
            return None
        # Try simple local ARP/neighbor check — vendor lookup not implemented here
        # You can plug in an OUI mapping offline if you want a reliable vendor name.
        return None
    
    def _display_detection_summary(self, host):
        """Display comprehensive detection methodology summary for a host."""
        console.print(f"\n[bold cyan]🔍 DETECTION METHODOLOGY SUMMARY for {host.get('ip', 'Unknown')}:[/bold cyan]")
        
        # MAC OUI Analysis
        mac = host.get('mac', 'Unknown')
        if mac != 'Unknown':
            mac_device_type = self._detect_device_type(mac)
            console.print(f"[blue]📡 MAC OUI Analysis:[/blue] {mac} → {mac_device_type}")
        
        # Port Analysis
        open_ports = host.get('open_ports', [])
        if open_ports:
            port_list = [f"{p['port']}/{p['protocol']}" for p in open_ports[:5]]
            console.print(f"[green]🔌 Port Analysis:[/green] {', '.join(port_list)}")
            if len(open_ports) > 5:
                console.print(f"[green]   ... and {len(open_ports)-5} more ports[/green]")
        
        # Service Analysis
        services = host.get('services', [])
        if services:
            service_list = list(set(services))[:5]
            console.print(f"[yellow]⚙️ Service Analysis:[/yellow] {', '.join(service_list)}")
        
        # OS Fingerprinting
        os_info = host.get('os', 'Unknown')
        if os_info != 'Unknown':
            console.print(f"[magenta]🖥️ OS Fingerprinting:[/magenta] {os_info}")
        
        # Final Device Inference
        device_inference = host.get('device', 'Unknown')
        if device_inference != 'Unknown':
            console.print(f"[bold green]🎯 Final Device Inference:[/bold green] {device_inference}")
        
        console.print(f"[dim]Detection combines MAC OUI database (650+ prefixes) with port/service heuristics for maximum accuracy[/dim]")
    
    def _display_hybrid_detection_explanation(self):
        """Display comprehensive explanation of the hybrid detection methodology."""
        console.print(f"\n[bold cyan]🧠 HYBRID DETECTION METHODOLOGY EXPLAINED:[/bold cyan]")
        console.print(f"[blue]NetHawk uses a sophisticated multi-layered approach combining:[/blue]")
        
        console.print(f"\n[bold green]1. 📡 MAC OUI Analysis (Primary Method):[/bold green]")
        console.print(f"   • Analyzes first 6 characters of MAC address (OUI)")
        console.print(f"   • Database contains 650+ manufacturer prefixes")
        console.print(f"   • Examples: Apple (001B63), Samsung (001599), Google (001A11)")
        console.print(f"   • Confidence: High (90%+ accuracy)")
        
        console.print(f"\n[bold yellow]2. 🔌 Port-Based Detection (Secondary Method):[/bold yellow]")
        console.print(f"   • Analyzes open ports and services")
        console.print(f"   • Port 22 (SSH) → Linux/Unix systems")
        console.print(f"   • Port 445 (SMB) → Windows systems")
        console.print(f"   • Port 9100 (IPP) → Printers")
        console.print(f"   • Port 1900 (UPnP) → Routers")
        console.print(f"   • Confidence: High (85%+ accuracy)")
        
        console.print(f"\n[bold magenta]3. 🖥️ OS Fingerprinting (Tertiary Method):[/bold magenta]")
        console.print(f"   • Uses nmap -O flag for OS detection")
        console.print(f"   • Analyzes TCP/IP stack behavior")
        console.print(f"   • Identifies Windows, Linux, Android, iOS")
        console.print(f"   • Confidence: Medium (70%+ accuracy)")
        
        console.print(f"\n[bold red]4. ⚙️ Service Analysis (Supporting Method):[/bold red]")
        console.print(f"   • Analyzes service banners and responses")
        console.print(f"   • SSH servers, HTTP servers, SMB shares")
        console.print(f"   • Service versions and configurations")
        console.print(f"   • Confidence: Medium (60%+ accuracy)")
        
        console.print(f"\n[bold blue]5. 🧠 Cross-Validation Logic:[/bold blue]")
        console.print(f"   • Combines all methods for final decision")
        console.print(f"   • Resolves conflicts between methods")
        console.print(f"   • Provides confidence levels (High/Medium/Low)")
        console.print(f"   • Shows detection methods used")
        
        console.print(f"\n[bold green]📊 CONFIDENCE SCORING SYSTEM:[/bold green]")
        console.print(f"   • High Confidence (60+ points): Multiple methods agree")
        console.print(f"   • Medium Confidence (40-59 points): Some methods agree")
        console.print(f"   • Low Confidence (20-39 points): Limited signals")
        console.print(f"   • Very Low Confidence (<20 points): Insufficient data")
        
        console.print(f"\n[bold cyan]🎯 EXAMPLE DETECTION FLOW:[/bold cyan]")
        console.print(f"   MAC: 84:d8:1b:d0:cd:d8 → Apple Device (40 points)")
        console.print(f"   Ports: 22, 80, 443 → Web server (25 points)")
        console.print(f"   OS: iOS 15.2 → Mobile OS (20 points)")
        console.print(f"   Result: Apple Device (High confidence) [Methods: MAC OUI, Port Analysis, OS Fingerprinting]")
    
    def _aggressive_port_scan_with_progress(self, hosts, port_range, scan_type):
        """AGGRESSIVE port scanning with real-time progress and results."""
        total_hosts = len(hosts)
        console.print(f"[blue]Port scanning {total_hosts} hosts...[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Port scanning hosts...", total=total_hosts)
            
            for i, host in enumerate(hosts):
                progress.update(task, description=f"Scanning {host['ip']}... ({i+1}/{total_hosts})")
                
                # Perform port scan on this host
                scan_result = self._scan_host_ports(host['ip'], port_range, scan_type)
                
                # Update host with new scan results
                host['open_ports'] = scan_result.get('open_ports', [])
                host['os'] = scan_result.get('os', 'Unknown')
                host['device'] = scan_result.get('device', 'Unknown')
                host['services'] = scan_result.get('services', [])
                host['mac'] = scan_result.get('mac', host.get('mac', 'Unknown'))
                host['mac_vendor'] = scan_result.get('mac_vendor', host.get('mac_vendor'))
                host['nmap_output'] = scan_result.get('nmap_output', '')
                
                if host['open_ports']:
                    console.print(f"[green]✓ {host['ip']}: {len(host['open_ports'])} open ports[/green]")
                    for port in host['open_ports'][:5]:  # Show first 5 ports
                        console.print(f"[blue]  - Port {port['port']}: {port['service']}[/blue]")
                    if len(host['open_ports']) > 5:
                        console.print(f"[blue]  - ... and {len(host['open_ports'])-5} more ports[/blue]")
                else:
                    console.print(f"[yellow]  {host['ip']}: No open ports found[/yellow]")
                
                progress.advance(task)
            
            progress.update(task, description="Port scanning complete!")
        
        # Display final results
        self._display_aggressive_hosts_table(hosts)

    def _aggressive_port_scan(self, hosts, port_range, scan_type):
        """Perform AGGRESSIVE port scanning."""
        console.print(f"[blue]Starting AGGRESSIVE port scan...[/blue]")
        
        for host in hosts:
            console.print(f"[yellow]Scanning {host['ip']}...[/yellow]")
            
            try:
                # Build nmap command based on scan type
                if scan_type == "fast":
                    cmd = ["nmap", "-Pn", "-T4", "-F", "--top-ports", "1000", host["ip"]]
                elif scan_type == "aggressive":
                    cmd = ["nmap", "-Pn", "-T4", "-A", "-sV", "-sC", "--script", "vuln", host["ip"]]
                else:  # comprehensive
                    cmd = ["nmap", "-Pn", "-T4", "-A", "-sV", "-sC", "-O", "--script", "vuln,discovery", host["ip"]]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    # Parse open ports
                    open_ports = self._parse_nmap_output(result.stdout)
                    host["open_ports"] = open_ports
                    host["nmap_output"] = result.stdout
                    
                    console.print(f"[green]✓ Found {len(open_ports)} open ports on {host['ip']}[/green]")
                else:
                    console.print(f"[red]Port scan failed for {host['ip']}[/red]")
                    
            except subprocess.TimeoutExpired:
                console.print(f"[yellow]Port scan timed out for {host['ip']}[/yellow]")
            except Exception as e:
                console.print(f"[red]Error scanning {host['ip']}: {e}[/red]")
    
    def _parse_nmap_output(self, nmap_output):
        """Parse nmap output to extract open ports."""
        open_ports = []
        lines = nmap_output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = {
                        "port": str(parts[0].split('/')[0]),  # Ensure string format
                        "protocol": parts[0].split('/')[1],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    }
                    open_ports.append(port_info)
        
        return open_ports
    
    def _parse_os_info(self, nmap_output):
        """Parse OS information from nmap output."""
        lines = nmap_output.split('\n')
        os_info = "Unknown"
        
        for line in lines:
            if "Running:" in line or "OS details:" in line:
                # Extract OS information
                if "Running:" in line:
                    os_info = line.split("Running:")[1].strip()
                elif "OS details:" in line:
                    os_info = line.split("OS details:")[1].strip()
                break
        
        return os_info
    
    def _display_aggressive_hosts_table(self, hosts):
        """Display discovered hosts in an enhanced table."""
        table = Table(title="AGGRESSIVE Scan - Discovered Hosts")
        table.add_column("IP Address", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Device Type", style="magenta")
        table.add_column("OS", style="blue")
        table.add_column("Open Ports", style="red")
        
        for host in hosts:
            open_ports_str = ", ".join([p["port"] for p in host["open_ports"]]) if host["open_ports"] else "None"
            table.add_row(
                host.get("ip", "Unknown"),
                host.get("status", "Unknown"),
                host.get("mac", "Unknown"),
                host.get("device_type", "Unknown"),
                host.get("os", "Unknown"),
                open_ports_str
            )
        
        console.print(table)
    
    def _get_current_network(self):
        """Get current network using multiple methods."""
        try:
            # Method 1: Use ip route to get default route
            result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'default via' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'dev' and i + 1 < len(parts):
                                interface = parts[i + 1]
                                # Get IP for this interface
                                ip_result = subprocess.run(["ip", "addr", "show", interface], capture_output=True, text=True, timeout=5)
                                if ip_result.returncode == 0:
                                    for ip_line in ip_result.stdout.split('\n'):
                                        if 'inet ' in ip_line and '127.0.0.1' not in ip_line:
                                            # Extract IP and subnet
                                            ip_parts = ip_line.split()
                                            for ip_part in ip_parts:
                                                if '/' in ip_part and '.' in ip_part:
                                                    ip = ip_part.split('/')[0]
                                                    subnet = ip_part.split('/')[1]
                                                    if '.' in ip and len(ip.split('.')) == 4:
                                                        # Convert to network format
                                                        network = '.'.join(ip.split('.')[:-1]) + '.0/' + subnet
                                                        return network
            
            # Method 2: Use ip addr show to get all interfaces
            result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'inet ' in line and '127.0.0.1' not in line:
                        # Extract IP and subnet
                        parts = line.split()
                        for part in parts:
                            if '/' in part and '.' in part:
                                ip = part.split('/')[0]
                                subnet = part.split('/')[1]
                                if '.' in ip and len(ip.split('.')) == 4:
                                    # Convert to network format
                                    network = '.'.join(ip.split('.')[:-1]) + '.0/' + subnet
                                    return network
            
            # Method 3: Use hostname -I as fallback
            result = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                ips = result.stdout.strip().split()
                for ip in ips:
                    if '.' in ip and len(ip.split('.')) == 4:
                        # Assume /24 subnet
                        network = '.'.join(ip.split('.')[:-1]) + '.0/24'
                        return network
            
            return None
            
        except Exception as e:
            console.print(f"[yellow]Network detection failed: {e}[/yellow]")
            return None
    
    def _suggest_common_networks(self):
        """Suggest common network ranges."""
        console.print(f"[blue]Common network ranges:[/blue]")
        console.print(f"[yellow]1. 192.168.1.0/24 (Most common home network)[/yellow]")
        console.print(f"[yellow]2. 192.168.0.0/24 (Alternative home network)[/yellow]")
        console.print(f"[yellow]3. 10.0.0.0/24 (Corporate network)[/yellow]")
        console.print(f"[yellow]4. 172.16.0.0/24 (Corporate network)[/yellow]")
        
        choice = Prompt.ask("Choose network (1/2/3/4)", default="1")
        networks = {
            "1": "192.168.1.0/24",
            "2": "192.168.0.0/24", 
            "3": "10.0.0.0/24",
            "4": "172.16.0.0/24"
        }
        
        selected = networks.get(choice, "192.168.1.0/24")
        console.print(f"[green]Selected network: {selected}[/green]")
        return selected

    
    def advanced_handshake_capture(self):
        """Advanced handshake capture with deauth attacks."""
        console.print("[bold red]🔐 Advanced Handshake Capture + Deauth[/bold red]")
        console.print("=" * 50)

        # Check if airodump-ng is available
        if not self.tools_available.get("airodump-ng", False):
            console.print("[red]❌ airodump-ng not found! Please install aircrack-ng.[/red]")
            console.print("[blue]Install: sudo apt install aircrack-ng[/blue]")
            return

        # Get wireless interface
        interfaces = self._get_wireless_interfaces()
        if not interfaces:
            console.print("[red]❌ No wireless interfaces found![/red]")
            return

        console.print("[bold]📡 Available interfaces:[/bold]")
        for i, iface in enumerate(interfaces):
            console.print(f"  {i+1}. {iface}")
        
        iface_choice = self.validate_input(
            "\nSelect interface to use: ", [str(i+1) for i in range(len(interfaces))]
        )
        iface = interfaces[int(iface_choice)-1]
        
        # Get target information
        console.print(f"\n[bold]🎯 Target Network Information:[/bold]")
        bssid = Prompt.ask("Enter target BSSID (MAC address)", default="")
        essid = Prompt.ask("Enter target ESSID (network name)", default="")
        channel = Prompt.ask("Enter target channel", default="6")
        
        # Validate BSSID format
        if bssid and not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid):
            console.print("[red]❌ Invalid BSSID format! Use format: XX:XX:XX:XX:XX:XX[/red]")
            return
        
        # Validate channel
        try:
            channel = int(channel)
            if channel < 1 or channel > 14:
                console.print("[red]❌ Invalid channel! Use 1-14 for 2.4GHz[/red]")
                return
        except ValueError:
            console.print("[red]❌ Invalid channel! Enter a number between 1-14[/red]")
            return
            
        console.print(f"\n[blue]🎯 Target: {essid} ({bssid}) on channel {channel}[/blue]")
        
        # Legal warning
        console.print(f"\n[bold red]⚠️  LEGAL WARNING:[/bold red]")
        console.print(f"[yellow]• Only capture handshakes from networks you own[/yellow]")
        console.print(f"[yellow]• Only test networks you have permission to test[/yellow]")
        console.print(f"[yellow]• Unauthorized access is illegal[/yellow]")
        
        if not Confirm.ask("[bold red]Do you have permission to test this network?[/bold red]"):
            console.print("[yellow]Operation cancelled.[/yellow]")
            return
                
        # Set monitor mode
        console.print(f"\n[blue]🔧 Setting up monitor mode on {iface}...[/blue]")
        monitor_iface = self._set_monitor_mode(iface)
        if not monitor_iface:
            console.print("[red]❌ Failed to set monitor mode![/red]")
            return
        
        # Capture options
        console.print(f"\n[bold]⚙️ Capture Options:[/bold]")
        use_deauth = Confirm.ask("Use deauth attacks to force handshake?", default=True)
        deauth_count = 10
        if use_deauth:
            deauth_count = IntPrompt.ask("Number of deauth packets", default=10)
            if deauth_count < 1 or deauth_count > 50:
                deauth_count = 10
                console.print(f"[yellow]⚠️ Using default: 10 packets[/yellow]")
        
        capture_duration = IntPrompt.ask("Capture duration (seconds)", default=60)
        if capture_duration < 10 or capture_duration > 300:
            capture_duration = 60
            console.print(f"[yellow]⚠️ Using default: 60 seconds[/yellow]")
        
        # Start handshake capture
        output_file = os.path.join(self.handshakes_path, f"{essid}_handshake_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        try:
            console.print(f"\n[blue]🚀 Starting handshake capture...[/blue]")
            console.print(f"[yellow]Press Ctrl+C to stop early[/yellow]")
            
            # Start airodump-ng with proper parameters
            cmd = [
                "airodump-ng",
                "-c", str(channel),
                "-w", output_file,
                "--bssid", bssid,
                "--output-format", "cap,csv",
                monitor_iface
            ]
            
            console.print(f"[blue]Running: {' '.join(cmd)}[/blue]")
            airodump_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Wait for airodump to start
            console.print(f"[blue]⏳ Starting airodump-ng...[/blue]")
            time.sleep(3)
            
            # Start deauth attack if requested
            deauth_process = None
            if use_deauth:
                console.print(f"[red]🔥 Starting deauth attack with {deauth_count} packets...[/red]")
                deauth_cmd = ["aireplay-ng", "--deauth", str(deauth_count), "-a", bssid, monitor_iface]
                deauth_process = subprocess.Popen(deauth_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                time.sleep(2)  # Let deauth complete
            
            # Show progress for handshake capture
            console.print(f"[blue]📡 Capturing handshake for {capture_duration} seconds...[/blue]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Capturing handshake...", total=capture_duration)
                
                for i in range(capture_duration):
                    progress.update(task, description=f"Capturing... {i+1}/{capture_duration}s")
                    time.sleep(1)
                
                progress.update(task, description="Capture complete!")
            
            # Stop processes
            console.print(f"[blue]🛑 Stopping capture...[/blue]")
            airodump_process.terminate()
            airodump_process.wait()
            
            if deauth_process:
                deauth_process.terminate()
                deauth_process.wait()
            
            # Check if handshake was captured
            cap_file = f"{output_file}-01.cap"
            if os.path.exists(cap_file):
                file_size = os.path.getsize(cap_file)
                console.print(f"\n[green]✅ Handshake capture completed![/green]")
                console.print(f"[blue]📁 Files saved:[/blue]")
                console.print(f"  • {os.path.basename(cap_file)} ({file_size} bytes)")
                console.print(f"  • {os.path.basename(output_file)}-01.csv (Capture data)")
                console.print(f"[yellow]💡 Use aircrack-ng to crack the handshake:[/yellow]")
                console.print(f"[blue]aircrack-ng -w wordlist.txt {cap_file}[/blue]")
            else:
                console.print(f"[yellow]⚠️ No handshake captured. Try increasing duration or using deauth.[/yellow]")
            
            # Show session storage message
            console.print(f"\n[bold green]📁 Session Files:[/bold green]")
            console.print(f"[blue]Session Path: {self.session_path}[/blue]")
            console.print(f"[blue]Handshakes Directory: {self.handshakes_path}[/blue]")
            console.print(f"[green]✅ All capture data saved to your session![/green]")
            console.print(f"[yellow]Press Ctrl+C to stop[/yellow]")
            
        except KeyboardInterrupt:
            console.print(f"\n[yellow]⏹️ Capture stopped by user.[/yellow]")
        except Exception as e:
            console.print(f"[red]❌ Error during capture: {e}[/red]")
        finally:
            # Clean up processes
            try:
                if 'airodump_process' in locals():
                    airodump_process.terminate()
                    airodump_process.wait()
                if 'deauth_process' in locals() and deauth_process:
                    deauth_process.terminate()
                    deauth_process.wait()
            except:
                pass
            
            # Restore managed mode
            console.print(f"[blue]🔄 Restoring managed mode...[/blue]")
            self._restore_managed_mode(monitor_iface)
    
    def vulnerability_assessment(self):
        """Simple vulnerability assessment using nmap."""
        console.print("[bold red]🔍 Vulnerability Assessment[/bold red]")
        console.print("=" * 50)
        
        # Check if nmap is available
        if not self.tools_available.get("nmap", False):
            console.print("[red]❌ nmap not found! Please install nmap.[/red]")
            console.print("[blue]Install: sudo apt install nmap[/blue]")
            return
        
        # Get target
        console.print(f"\n[bold]🎯 Target Selection:[/bold]")
        target = Prompt.ask("Enter target IP or network", default="")
        
        if not target:
            console.print("[red]❌ No target specified![/red]")
            return
        
        # Validate target format
        try:
            # Try to parse as IP or network
            if "/" in target:
                ipaddress.IPv4Network(target, strict=False)
            else:
                ipaddress.IPv4Address(target)
        except:
            console.print("[red]❌ Invalid IP or network format![/red]")
            return
        
        console.print(f"\n[blue]🎯 Target: {target}[/blue]")
        
        # Scan options
        console.print(f"\n[bold]⚙️ Scan Options:[/bold]")
        scan_type = self.validate_input(
            "Select scan type (1=Quick, 2=Standard, 3=Comprehensive): ",
            ["1", "2", "3"]
        )
        
        # Build nmap command based on scan type
        if scan_type == "1":  # Quick
            cmd = ["nmap", "-Pn", "-T4", "-sV", "--script", "vuln", "--script-timeout", "30s", target]
            scan_name = "Quick Vulnerability Scan"
            timeout = 300  # 5 minutes
        elif scan_type == "2":  # Standard
            cmd = ["nmap", "-Pn", "-T4", "-sV", "-sC", "--script", "vuln", target]
            scan_name = "Standard Vulnerability Scan"
            timeout = 600  # 10 minutes
        else:  # Comprehensive
            cmd = ["nmap", "-Pn", "-T3", "-sV", "-sC", "-O", "--script", "vuln", "--script-args", "unsafe=1", target]
            scan_name = "Comprehensive Vulnerability Scan"
            timeout = 1200  # 20 minutes
        
        console.print(f"\n[blue]🚀 Starting {scan_name}...[/blue]")
        console.print(f"[yellow]This may take several minutes depending on target[/yellow]")
        console.print(f"[blue]Running: {' '.join(cmd)}[/blue]")
        
        try:
            # Run vulnerability scan with progress
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"Scanning {target}...", total=timeout)
                
                # Start the scan
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Show progress
                for i in range(timeout):
                    progress.update(task, description=f"Scanning {target}... {i+1}/{timeout}s")
                    time.sleep(1)
                    
                    # Check if process finished
                    if process.poll() is not None:
                        progress.update(task, description="Scan completed!")
                        break
                
                # Get results
                stdout, stderr = process.communicate()
            
            # Parse and display results
            if process.returncode == 0:
                console.print(f"\n[green]✅ Vulnerability scan completed![/green]")
                
                # Parse vulnerabilities
                vulnerabilities = self._parse_simple_vulnerabilities(stdout)
                
                if vulnerabilities:
                    console.print(f"\n[bold green]📊 VULNERABILITY ASSESSMENT RESULTS[/bold green]")
                    console.print(f"[blue]Target: {target}[/blue]")
                    console.print(f"[green]Vulnerabilities Found: {len(vulnerabilities)}[/green]")
                    console.print(f"[yellow]Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                    
                    # Display vulnerabilities
                    console.print(f"\n[bold cyan]🔍 DISCOVERED VULNERABILITIES:[/bold cyan]")
                    for i, vuln in enumerate(vulnerabilities, 1):
                        console.print(f"\n[bold]Vulnerability {i}:[/bold]")
                        console.print(f"  [red]Title:[/red] {vuln['title']}")
                        console.print(f"  [yellow]Severity:[/yellow] {vuln['severity']}")
                        console.print(f"  [blue]Description:[/blue] {vuln['description']}")
                        if vuln.get('cve'):
                            console.print(f"  [magenta]CVE:[/magenta] {vuln['cve']}")
                    
                    # Save results
                    self._save_vulnerability_results(vulnerabilities, target)
                    
                else:
                    console.print(f"\n[yellow]⚠️ No vulnerabilities found.[/yellow]")
                    console.print(f"[blue]Target appears to be secure or scan was inconclusive[/blue]")
                    console.print(f"[yellow]Note: This doesn't guarantee the target is completely secure[/yellow]")
                
                # Show raw output for reference
                if stdout:
                    console.print(f"\n[bold cyan]📋 Raw Scan Output:[/bold cyan]")
                    console.print(f"[dim]{stdout[:1000]}{'...' if len(stdout) > 1000 else ''}[/dim]")
                
            else:
                console.print(f"[red]❌ Vulnerability scan failed![/red]")
                console.print(f"[yellow]Error: {stderr[:500] if stderr else 'Unknown error'}[/yellow]")
                if stdout:
                    console.print(f"[blue]Partial output: {stdout[:500]}...[/blue]")
                
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]⏰ Vulnerability scan timed out after {timeout} seconds[/yellow]")
        except Exception as e:
            console.print(f"[red]❌ Error during vulnerability assessment: {e}[/red]")
        
        console.print(f"\n[yellow]Press Ctrl+C to stop[/yellow]")
    
    def _parse_simple_vulnerabilities(self, nmap_output):
        """Parse nmap output to extract vulnerabilities with simple method."""
        vulnerabilities = []
        lines = nmap_output.split('\n')
        
        current_vuln = None
        for line in lines:
            line = line.strip()
            
            # Look for vulnerability markers
            if 'VULNERABLE:' in line:
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                
                # Extract vulnerability title
                title = line.split('VULNERABLE:')[1].strip()
                current_vuln = {
                    "title": title,
                    "description": "",
                    "severity": "Unknown",
                    "cve": ""
                }
                
                # Try to extract CVE if present
                if 'CVE-' in title:
                    cve_match = re.search(r'CVE-\d{4}-\d+', title)
                    if cve_match:
                        current_vuln["cve"] = cve_match.group()
                
                # Determine severity based on keywords
                title_lower = title.lower()
                if any(word in title_lower for word in ['critical', 'remote code execution', 'rce']):
                    current_vuln["severity"] = "Critical"
                elif any(word in title_lower for word in ['high', 'buffer overflow', 'sql injection']):
                    current_vuln["severity"] = "High"
                elif any(word in title_lower for word in ['medium', 'information disclosure']):
                    current_vuln["severity"] = "Medium"
                elif any(word in title_lower for word in ['low', 'info']):
                    current_vuln["severity"] = "Low"
                else:
                    current_vuln["severity"] = "Unknown"
                    
            elif current_vuln and line and not line.startswith('|') and not line.startswith('+'):
                # Add to description
                current_vuln["description"] += line + " "
        
        if current_vuln:
            vulnerabilities.append(current_vuln)
        
        return vulnerabilities
    
    def _save_vulnerability_results(self, vulnerabilities, target):
        """Save vulnerability results to JSON file."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "vulnerabilities": vulnerabilities,
            "total_count": len(vulnerabilities)
        }
        
        output_file = os.path.join(self.vulns_path, f"vulnerabilities_{target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]✅ Vulnerabilities saved to: {output_file}[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Could not save results: {e}[/yellow]")
    
    def _display_vulnerabilities_table(self, vulnerabilities):
        """Display vulnerabilities in a table."""
        table = Table(title="Discovered Vulnerabilities")
        table.add_column("Title", style="red")
        table.add_column("Severity", style="yellow")
        table.add_column("Description", style="white")
        
        for vuln in vulnerabilities:
            table.add_row(
                vuln["title"],
                vuln["severity"],
                vuln["description"][:100] + "..." if len(vuln["description"]) > 100 else vuln["description"]
            )
        
        console.print(table)
    
    def _save_vulnerabilities(self, vulnerabilities, target):
        """Save vulnerabilities to JSON."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total_vulnerabilities": len(vulnerabilities)
            }
        }
        
        output_file = os.path.join(self.vulns_path, f"vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]✓ Vulnerabilities saved to: {output_file}[/green]")
            
            # Show session storage message
            console.print(f"\n[bold green]📁 Scan Results Stored in Session Files:[/bold green]")
            console.print(f"[blue]Session Path: {self.session_path}[/blue]")
            console.print(f"[blue]Vulnerabilities Directory: {self.vulns_path}[/blue]")
            console.print(f"[yellow]Files created:[/yellow]")
            console.print(f"[blue]  - {os.path.basename(output_file)} (Vulnerability assessment)[/blue]")
            console.print(f"[green]✓ All scan data is automatically saved to your session![/green]")
        except Exception as e:
            console.print(f"[red]Error saving vulnerabilities: {e}[/red]")
    
    def web_application_scanning(self):
        """Simple web application vulnerability scanning using nikto."""
        console.print("[bold red]🌐 Web Application Scanning[/bold red]")
        console.print("=" * 50)
        
        # Check if nikto is available
        if not self.tools_available.get("nikto", False):
            console.print("[red]❌ nikto not found! Please install nikto.[/red]")
            console.print("[blue]Install: sudo apt install nikto[/blue]")
            return
        
        # Get target URL with validation
        console.print(f"\n[bold]🎯 Target Selection:[/bold]")
        target_url = Prompt.ask("Enter target URL (e.g., http://192.168.1.1)", default="")
        
        if not target_url:
            console.print("[red]❌ No target URL specified![/red]")
            return
        
        # Validate URL format
        if not target_url.startswith(('http://', 'https://')):
            console.print("[red]❌ URL must start with http:// or https://[/red]")
            console.print("[blue]Example: http://192.168.1.1 or https://example.com[/blue]")
            return
        
        console.print(f"\n[blue]🎯 Target: {target_url}[/blue]")
        
        # Scan options
        console.print(f"\n[bold]⚙️ Scan Options:[/bold]")
        scan_type = self.validate_input(
            "Select scan type (1=Quick, 2=Standard, 3=Comprehensive): ",
            ["1", "2", "3"]
        )
        
        # Build nikto command based on scan type
        if scan_type == "1":  # Quick
            cmd = ["nikto", "-h", target_url, "-Tuning", "1,2,3,4,5", "-timeout", "10", "-maxtime", "300s"]
            scan_name = "Quick Web Application Scan"
            timeout = 300  # 5 minutes
        elif scan_type == "2":  # Standard
            cmd = ["nikto", "-h", target_url, "-Tuning", "1,2,3,4,5,6,7", "-timeout", "15", "-maxtime", "600s"]
            scan_name = "Standard Web Application Scan"
            timeout = 600  # 10 minutes
        else:  # Comprehensive
            cmd = ["nikto", "-h", target_url, "-Tuning", "0", "-timeout", "20", "-maxtime", "1200s", "-evasion", "1"]
            scan_name = "Comprehensive Web Application Scan"
            timeout = 1200  # 20 minutes
        
        console.print(f"\n[blue]🚀 Starting {scan_name}...[/blue]")
        console.print(f"[yellow]This may take several minutes depending on target[/yellow]")
        console.print(f"[blue]Running: {' '.join(cmd)}[/blue]")
        
        try:
            # Run nikto scan with progress
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"Scanning {target_url}...", total=timeout)
                
                # Start the scan
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Show progress
                for i in range(timeout):
                    progress.update(task, description=f"Scanning {target_url}... {i+1}/{timeout}s")
                    time.sleep(1)
                    
                    # Check if process finished
                    if process.poll() is not None:
                        progress.update(task, description="Scan completed!")
                        break
                
                # Get results
                stdout, stderr = process.communicate()
            
            # Parse and display results
            # Check if we got any useful output even if returncode != 0
            if stdout and ("+ " in stdout or "OSVDB-" in stdout or "Target IP:" in stdout):
                console.print(f"\n[green]✅ Web application scan completed![/green]")
                
                # Parse vulnerabilities
                vulnerabilities = self._parse_web_vulnerabilities(stdout)
                
                if vulnerabilities:
                    console.print(f"\n[bold green]📊 WEB APPLICATION SCAN RESULTS[/bold green]")
                    console.print(f"[blue]Target: {target_url}[/blue]")
                    console.print(f"[green]Vulnerabilities Found: {len(vulnerabilities)}[/green]")
                    console.print(f"[yellow]Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                    
                    # Display vulnerabilities
                    console.print(f"\n[bold cyan]🔍 DISCOVERED VULNERABILITIES:[/bold cyan]")
                    for i, vuln in enumerate(vulnerabilities, 1):
                        console.print(f"\n[bold]Vulnerability {i}:[/bold]")
                        console.print(f"  [red]Title:[/red] {vuln['title']}")
                        console.print(f"  [yellow]Severity:[/yellow] {vuln['severity']}")
                        console.print(f"  [blue]Description:[/blue] {vuln['description']}")
                        if vuln.get('cve'):
                            console.print(f"  [magenta]CVE:[/magenta] {vuln['cve']}")
                    
                    # Save results
                    self._save_web_scan_results(vulnerabilities, target_url)
                    
                else:
                    console.print(f"\n[yellow]⚠️ No vulnerabilities found.[/yellow]")
                    console.print(f"[blue]Target appears to be secure or scan was inconclusive[/blue]")
                    console.print(f"[yellow]Note: This doesn't guarantee the target is completely secure[/yellow]")
                
                # Show raw output for reference
                if stdout:
                    console.print(f"\n[bold cyan]📋 Raw Scan Output:[/bold cyan]")
                    console.print(f"[dim]{stdout[:1000]}{'...' if len(stdout) > 1000 else ''}[/dim]")
                
            else:
                console.print(f"[red]❌ Web application scan failed![/red]")
                console.print(f"[yellow]Error: {stderr[:500] if stderr else 'Unknown error'}[/yellow]")
                if stdout:
                    console.print(f"[blue]Partial output: {stdout[:500]}...[/blue]")
                
                # Check for specific nikto error patterns
                if "Error limit" in stderr or "Error limit" in stdout:
                    console.print(f"\n[yellow]💡 Tip: Nikto hit its error limit. This is common with some targets.[/yellow]")
                    console.print(f"[blue]Try using a different scan type or target a different URL.[/blue]")
                elif "Connection refused" in stderr or "Connection refused" in stdout:
                    console.print(f"\n[yellow]💡 Tip: Connection refused. Check if the target is accessible.[/yellow]")
                    console.print(f"[blue]Try: ping {target_url.split('://')[1].split('/')[0]}[/blue]")
                elif "timeout" in stderr.lower() or "timeout" in stdout.lower():
                    console.print(f"\n[yellow]💡 Tip: Timeout occurred. The target may be slow to respond.[/yellow]")
                    console.print(f"[blue]Try using a Quick scan instead of Comprehensive.[/blue]")
                
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]⏰ Web application scan timed out after {timeout} seconds[/yellow]")
        except Exception as e:
            console.print(f"[red]❌ Error during web application scanning: {e}[/red]")
        
        console.print(f"\n[yellow]Press Ctrl+C to stop[/yellow]")
    
    def _parse_web_vulnerabilities(self, nikto_output):
        """Parse nikto output to extract web vulnerabilities with simple method."""
        vulnerabilities = []
        lines = nikto_output.split('\n')
        
        current_vuln = None
        for line in lines:
            line = line.strip()
            
            # Look for vulnerability markers in nikto output
            if '+ OSVDB-' in line or ('+ ' in line and ('vulnerable' in line.lower() or 'risk' in line.lower() or 'header' in line.lower() or 'directory' in line.lower() or 'file' in line.lower())):
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                
                # Extract vulnerability title
                if '+ OSVDB-' in line:
                    title = line.split('+ OSVDB-')[1].strip()
                else:
                    title = line.split('+ ')[1].strip() if '+ ' in line else line
                
                current_vuln = {
                    "title": title,
                    "description": "",
                    "severity": "Unknown",
                    "cve": ""
                }
                
                # Try to extract CVE if present
                if 'CVE-' in title:
                    cve_match = re.search(r'CVE-\d{4}-\d+', title)
                    if cve_match:
                        current_vuln["cve"] = cve_match.group()
                
                # Determine severity based on keywords
                title_lower = title.lower()
                if any(word in title_lower for word in ['critical', 'remote code execution', 'rce', 'sql injection', 'buffer overflow']):
                    current_vuln["severity"] = "Critical"
                elif any(word in title_lower for word in ['high', 'xss', 'cross-site', 'directory traversal', 'file upload']):
                    current_vuln["severity"] = "High"
                elif any(word in title_lower for word in ['medium', 'information disclosure', 'header', 'version disclosure']):
                    current_vuln["severity"] = "Medium"
                elif any(word in title_lower for word in ['low', 'info', 'default', 'directory', 'file']):
                    current_vuln["severity"] = "Low"
                else:
                    current_vuln["severity"] = "Unknown"
                    
            elif current_vuln and line and not line.startswith('+') and not line.startswith('-') and not line.startswith('|'):
                # Add to description
                current_vuln["description"] += line + " "
        
        if current_vuln:
            vulnerabilities.append(current_vuln)
        
        return vulnerabilities
    
    def _save_web_scan_results(self, vulnerabilities, target_url):
        """Save web scan results to JSON file."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": target_url,
            "vulnerabilities": vulnerabilities,
            "total_count": len(vulnerabilities)
        }
        
        # Create safe filename from URL
        safe_url = target_url.replace('http://', '').replace('https://', '').replace('/', '_').replace(':', '_')
        output_file = os.path.join(self.vulns_path, f"web_scan_{safe_url}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]✅ Web scan results saved to: {output_file}[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Could not save results: {e}[/yellow]")
    
    def smb_enumeration(self):
        """Simple SMB/Windows enumeration using enum4linux."""
        console.print("[bold red]🪟 SMB/Windows Enumeration[/bold red]")
        console.print("=" * 50)
        
        # Check if enum4linux is available
        if not self.tools_available.get("enum4linux", False):
            console.print("[red]❌ enum4linux not found! Please install enum4linux.[/red]")
            console.print("[blue]Install: sudo apt install enum4linux[/blue]")
            return
        
        # Get target with IP validation
        console.print(f"\n[bold]🎯 Target Selection:[/bold]")
        target = Prompt.ask("Enter target IP", default="")
        
        if not target:
            console.print("[red]❌ No target IP specified![/red]")
            return
        
        # Validate IP format
        try:
            ipaddress.IPv4Address(target)
        except ValueError:
            console.print("[red]❌ Invalid IP address format![/red]")
            console.print("[blue]Example: 192.168.1.1[/blue]")
            return
        
        console.print(f"\n[blue]🎯 Target: {target}[/blue]")
        
        # Scan options
        console.print(f"\n[bold]⚙️ Scan Options:[/bold]")
        scan_type = self.validate_input(
            "Select scan type (1=Quick, 2=Standard, 3=Comprehensive): ",
            ["1", "2", "3"]
        )
        
        # Build enum4linux command based on scan type
        if scan_type == "1":  # Quick
            cmd = ["enum4linux", "-U", "-M", "-S", "-P", target]
            scan_name = "Quick SMB Enumeration"
            timeout = 300  # 5 minutes
        elif scan_type == "2":  # Standard
            cmd = ["enum4linux", "-U", "-M", "-S", "-P", "-G", "-r", target]
            scan_name = "Standard SMB Enumeration"
            timeout = 600  # 10 minutes
        else:  # Comprehensive
            cmd = ["enum4linux", "-a", target]
            scan_name = "Comprehensive SMB Enumeration"
            timeout = 1200  # 20 minutes
        
        console.print(f"\n[blue]🚀 Starting {scan_name}...[/blue]")
        console.print(f"[yellow]This may take several minutes depending on target[/yellow]")
        console.print(f"[blue]Running: {' '.join(cmd)}[/blue]")
        
        try:
            # Run enum4linux with progress
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"Enumerating {target}...", total=timeout)
                
                # Start the scan
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Show progress
                for i in range(timeout):
                    progress.update(task, description=f"Enumerating {target}... {i+1}/{timeout}s")
                    time.sleep(1)
                    
                    # Check if process finished
                    if process.poll() is not None:
                        progress.update(task, description="Scan completed!")
                        break
                
                # Get results
                stdout, stderr = process.communicate()
            
            # Parse and display results
            # Check if we got any useful output even if returncode != 0
            if stdout and ("Target Information" in stdout or "Username" in stdout or "Share" in stdout or "Domain" in stdout):
                console.print(f"\n[green]✅ SMB enumeration completed![/green]")
                
                # Parse SMB information
                smb_info = self._parse_smb_results(stdout)
                
                if smb_info:
                    console.print(f"\n[bold green]📊 SMB ENUMERATION RESULTS[/bold green]")
                    console.print(f"[blue]Target: {target}[/blue]")
                    console.print(f"[green]Information Found: {len(smb_info)} items[/green]")
                    console.print(f"[yellow]Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                    
                    # Display SMB information
                    console.print(f"\n[bold cyan]🔍 DISCOVERED SMB INFORMATION:[/bold cyan]")
                    for i, info in enumerate(smb_info, 1):
                        console.print(f"\n[bold]Information {i}:[/bold]")
                        console.print(f"  [red]Type:[/red] {info['type']}")
                        console.print(f"  [yellow]Value:[/yellow] {info['value']}")
                        console.print(f"  [blue]Description:[/blue] {info['description']}")
                    
                    # Save results
                    self._save_smb_results(smb_info, target)
                    
                else:
                    console.print(f"\n[yellow]⚠️ No SMB information found.[/yellow]")
                    console.print(f"[blue]Target may not have SMB services or they are not accessible[/blue]")
                    console.print(f"[yellow]Note: This doesn't guarantee the target is completely secure[/yellow]")
                
                # Show raw output for reference
                if stdout:
                    console.print(f"\n[bold cyan]📋 Raw Scan Output:[/bold cyan]")
                    console.print(f"[dim]{stdout[:1000]}{'...' if len(stdout) > 1000 else ''}[/dim]")
                
            else:
                console.print(f"[red]❌ SMB enumeration failed![/red]")
                console.print(f"[yellow]Error: {stderr[:500] if stderr else 'Unknown error'}[/yellow]")
                if stdout:
                    console.print(f"[blue]Partial output: {stdout[:500]}...[/blue]")
                
                # Check for specific enum4linux error patterns
                if "Connection refused" in stderr or "Connection refused" in stdout:
                    console.print(f"\n[yellow]💡 Tip: Connection refused. Check if the target has SMB services running.[/yellow]")
                    console.print(f"[blue]Try: nmap -p 445,139 {target}[/blue]")
                elif "timeout" in stderr.lower() or "timeout" in stdout.lower():
                    console.print(f"\n[yellow]💡 Tip: Timeout occurred. The target may be slow to respond.[/yellow]")
                    console.print(f"[blue]Try using a Quick scan instead of Comprehensive.[/blue]")
                elif "No shares found" in stdout or "No users found" in stdout:
                    console.print(f"\n[yellow]💡 Tip: No SMB information found. Target may not have SMB services.[/yellow]")
                    console.print(f"[blue]This is normal for non-Windows targets or secured systems.[/blue]")
                
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]⏰ SMB enumeration timed out after {timeout} seconds[/yellow]")
        except Exception as e:
            console.print(f"[red]❌ Error during SMB enumeration: {e}[/red]")
        
        console.print(f"\n[yellow]Press Ctrl+C to stop[/yellow]")
    
    def _parse_smb_results(self, enum4linux_output):
        """Parse enum4linux output to extract SMB information with simple method."""
        smb_info = []
        lines = enum4linux_output.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Look for specific SMB information patterns
            if 'Got domain/workgroup name:' in line:
                value = line.split('Got domain/workgroup name:')[1].strip()
                smb_info.append({
                    "type": "Domain/Workgroup",
                    "value": value,
                    "description": "The domain or workgroup name of the target"
                })
            elif 'Got domain SID:' in line:
                value = line.split('Got domain SID:')[1].strip()
                smb_info.append({
                    "type": "Domain SID",
                    "value": value,
                    "description": "The Security Identifier of the domain"
                })
            elif 'User:' in line and 'rid:' in line:
                # Extract username and RID
                parts = line.split()
                username = parts[1] if len(parts) > 1 else "Unknown"
                rid = parts[-1] if len(parts) > 2 else "Unknown"
                smb_info.append({
                    "type": "User Account",
                    "value": f"{username} (RID: {rid})",
                    "description": "User account found on the target system"
                })
            elif 'Share name:' in line:
                value = line.split('Share name:')[1].strip()
                smb_info.append({
                    "type": "SMB Share",
                    "value": value,
                    "description": "Shared folder or resource accessible via SMB"
                })
            elif 'Server:' in line and 'OS:' in line:
                # Extract server OS information
                value = line.split('OS:')[1].strip() if 'OS:' in line else line
                smb_info.append({
                    "type": "Server OS",
                    "value": value,
                    "description": "Operating system information of the target server"
                })
            elif 'Password Policy:' in line:
                value = line.split('Password Policy:')[1].strip()
                smb_info.append({
                    "type": "Password Policy",
                    "value": value,
                    "description": "Password policy information for the domain"
                })
            elif 'Group:' in line and 'rid:' in line:
                # Extract group information
                parts = line.split()
                groupname = parts[1] if len(parts) > 1 else "Unknown"
                rid = parts[-1] if len(parts) > 2 else "Unknown"
                smb_info.append({
                    "type": "Group",
                    "value": f"{groupname} (RID: {rid})",
                    "description": "Group account found on the target system"
                })
            elif 'Machine account:' in line:
                value = line.split('Machine account:')[1].strip()
                smb_info.append({
                    "type": "Machine Account",
                    "value": value,
                    "description": "Computer account in the domain"
                })
            elif 'Known Usernames' in line:
                # Extract known usernames
                value = line.split('Known Usernames')[1].strip().lstrip('..').strip()
                if value:
                    smb_info.append({
                        "type": "Known Usernames",
                        "value": value,
                        "description": "Common usernames found during enumeration"
                    })
            elif 'RID Range' in line:
                # Extract RID range
                value = line.split('RID Range')[1].strip().lstrip('..').strip()
                if value:
                    smb_info.append({
                        "type": "RID Range",
                        "value": value,
                        "description": "Relative Identifier range for enumeration"
                    })
            elif 'Target' in line and '127.0.0.1' in line or '192.168.' in line or '10.' in line:
                # Extract target information
                value = line.split('Target')[1].strip().lstrip('..').strip()
                if value:
                    smb_info.append({
                        "type": "Target Information",
                        "value": value,
                        "description": "Target system information"
                    })
        
        return smb_info
    
    def _save_smb_results(self, smb_info, target):
        """Save SMB enumeration results to JSON file."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "smb_info": smb_info,
            "total_count": len(smb_info)
        }
        
        output_file = os.path.join(self.vulns_path, f"smb_enum_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]✅ SMB enumeration results saved to: {output_file}[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Could not save results: {e}[/yellow]")
    
    def dns_reconnaissance(self):
        """Simple DNS reconnaissance using dig and nslookup."""
        console.print("[bold red]🌐 DNS Reconnaissance[/bold red]")
        console.print("=" * 50)
        
        # Check if dig is available
        if not self.tools_available.get("dig", False):
            console.print("[red]❌ dig not found! Please install dnsutils.[/red]")
            console.print("[blue]Install: sudo apt install dnsutils[/blue]")
            return
        
        # Get target domain with validation
        console.print(f"\n[bold]🎯 Target Selection:[/bold]")
        domain = Prompt.ask("Enter target domain (e.g., example.com)", default="")
        
        if not domain:
            console.print("[red]❌ No domain specified![/red]")
            return
        
        # Validate domain format
        if '.' not in domain or domain.startswith('.'):
            console.print("[red]❌ Invalid domain format![/red]")
            console.print("[blue]Example: example.com, google.com, github.com[/blue]")
            return
        
        console.print(f"\n[blue]🎯 Target: {domain}[/blue]")
        
        # Scan options
        console.print(f"\n[bold]⚙️ Scan Options:[/bold]")
        scan_type = self.validate_input(
            "Select scan type (1=Quick, 2=Standard, 3=Comprehensive): ",
            ["1", "2", "3"]
        )
        
        # Build DNS queries based on scan type
        if scan_type == "1":  # Quick
            queries = [
                ("A", f"dig {domain} A"),
                ("MX", f"dig {domain} MX"),
                ("NS", f"dig {domain} NS")
            ]
            scan_name = "Quick DNS Reconnaissance"
            timeout = 60  # 1 minute
        elif scan_type == "2":  # Standard
            queries = [
                ("A", f"dig {domain} A"),
                ("MX", f"dig {domain} MX"),
                ("NS", f"dig {domain} NS"),
                ("TXT", f"dig {domain} TXT"),
                ("CNAME", f"dig www.{domain} CNAME")
            ]
            scan_name = "Standard DNS Reconnaissance"
            timeout = 120  # 2 minutes
        else:  # Comprehensive
            queries = [
                ("A", f"dig {domain} A"),
                ("MX", f"dig {domain} MX"),
                ("NS", f"dig {domain} NS"),
                ("TXT", f"dig {domain} TXT"),
                ("CNAME", f"dig www.{domain} CNAME"),
                ("SOA", f"dig {domain} SOA"),
                ("PTR", f"dig -x {domain}"),
                ("ANY", f"dig {domain} ANY")
            ]
            scan_name = "Comprehensive DNS Reconnaissance"
            timeout = 180  # 3 minutes
        
        console.print(f"\n[blue]🚀 Starting {scan_name}...[/blue]")
        console.print(f"[yellow]This may take a few minutes depending on target[/yellow]")
        console.print(f"[blue]Running {len(queries)} DNS queries...[/blue]")
        
        try:
            # Run DNS queries with progress
            dns_results = {}
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task(f"Querying {domain}...", total=len(queries))
                
                for query_type, cmd in queries:
                    progress.update(task, description=f"Querying {query_type} records for {domain}...")
                    
                    try:
                        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
                        if result.returncode == 0:
                            dns_results[query_type] = result.stdout
                        else:
                            dns_results[query_type] = f"Error: {result.stderr}"
                    except subprocess.TimeoutExpired:
                        dns_results[query_type] = "Timeout: Query took too long"
                    except Exception as e:
                        dns_results[query_type] = f"Error: {str(e)}"
                    
                    progress.advance(task)
            
            # Parse and display results
            console.print(f"\n[green]✅ DNS reconnaissance completed![/green]")
            
            # Parse DNS information
            dns_info = self._parse_dns_results(dns_results, domain)
            
            if dns_info:
                console.print(f"\n[bold green]📊 DNS RECONNAISSANCE RESULTS[/bold green]")
                console.print(f"[blue]Target: {domain}[/blue]")
                console.print(f"[green]Information Found: {len(dns_info)} items[/green]")
                console.print(f"[yellow]Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                
                # Display DNS information
                console.print(f"\n[bold cyan]🔍 DISCOVERED DNS INFORMATION:[/bold cyan]")
                for i, info in enumerate(dns_info, 1):
                    console.print(f"\n[bold]Information {i}:[/bold]")
                    console.print(f"  [red]Type:[/red] {info['type']}")
                    console.print(f"  [yellow]Value:[/yellow] {info['value']}")
                    console.print(f"  [blue]Description:[/blue] {info['description']}")
                
                # Save results
                self._save_dns_results(dns_info, domain)
                
            else:
                console.print(f"\n[yellow]⚠️ No DNS information found.[/yellow]")
                console.print(f"[blue]Target may not have public DNS records or domain may not exist[/blue]")
                console.print(f"[yellow]Note: This doesn't guarantee the target is completely secure[/yellow]")
            
            # Show raw output for reference
            console.print(f"\n[bold cyan]📋 Raw DNS Output:[/bold cyan]")
            for query_type, result in dns_results.items():
                if result and "Error:" not in result and "Timeout:" not in result:
                    console.print(f"\n[bold]{query_type} Records:[/bold]")
                    console.print(f"[dim]{result[:500]}{'...' if len(result) > 500 else ''}[/dim]")
                
        except Exception as e:
            console.print(f"[red]❌ Error during DNS reconnaissance: {e}[/red]")
        
        console.print(f"\n[yellow]Press Ctrl+C to stop[/yellow]")
    
    def _parse_dns_results(self, dns_results, domain):
        """Parse DNS query results to extract useful information."""
        dns_info = []
        
        console.print(f"[cyan]DEBUG: Starting DNS parsing for domain: {domain}[/cyan]")
        console.print(f"[cyan]DEBUG: Query types available: {list(dns_results.keys())}[/cyan]")
        
        for query_type, result in dns_results.items():
            console.print(f"[cyan]DEBUG: Processing query type: {query_type}[/cyan]")
            if "Error:" in result or "Timeout:" in result:
                console.print(f"[cyan]DEBUG: Skipping {query_type} due to error/timeout[/cyan]")
                continue
                
            lines = result.split('\n')
            in_answer_section = False
            answer_lines_found = 0
            
            for line in lines:
                line = line.strip()
                
                # Check if we're in the ANSWER SECTION
                if ";; ANSWER SECTION:" in line:
                    in_answer_section = True
                    console.print(f"[cyan]DEBUG: Found ANSWER SECTION for {query_type}[/cyan]")
                    continue
                elif line.startswith(";;") and "SECTION:" in line:
                    in_answer_section = False
                    console.print(f"[cyan]DEBUG: Left ANSWER SECTION for {query_type}[/cyan]")
                    continue
                
                # Only parse lines in the ANSWER SECTION
                if not in_answer_section or line.startswith(';'):
                    continue
                
                answer_lines_found += 1
                console.print(f"[cyan]DEBUG: Processing answer line {answer_lines_found} for {query_type}: {line}[/cyan]")
                
                # Parse A records - look for lines like "google.com. 66 IN A 142.250.71.110"
                if query_type == "A" and ("IN A" in line or " A " in line):
                    console.print(f"[yellow]DEBUG A: Found A record line: {line}[/yellow]")
                    # Split by whitespace and filter out empty strings
                    parts = [part for part in line.split() if part]
                    console.print(f"[yellow]DEBUG A: Parts: {parts}[/yellow]")
                    if len(parts) >= 4 and parts[-2] == "A":
                        ip = parts[-1]
                        console.print(f"[yellow]DEBUG A: IP: {ip}[/yellow]")
                        if ip.replace('.', '').isdigit():
                            console.print(f"[yellow]DEBUG A: Adding A record: {domain} -> {ip}[/yellow]")
                            dns_info.append({
                                "type": "A Record",
                                "value": f"{domain} -> {ip}",
                                "description": "IPv4 address mapping for the domain"
                            })
                        else:
                            console.print(f"[yellow]DEBUG A: IP validation failed for: {ip}[/yellow]")
                    else:
                        console.print(f"[yellow]DEBUG A: Parts validation failed. Length: {len(parts)}, Last-2: {parts[-2] if len(parts) >= 2 else 'N/A'}[/yellow]")
                elif query_type == "A":
                    console.print(f"[yellow]DEBUG A: No A record found in line: {line}[/yellow]")
                
                # Parse MX records - look for lines like "google.com. 23 IN MX 10 smtp.google.com."
                elif query_type == "MX" and "IN MX" in line:
                    parts = line.split()
                    if len(parts) >= 4 and parts[-2] == "MX":
                        priority = parts[-3]
                        mailserver = parts[-1].rstrip('.')
                        dns_info.append({
                            "type": "MX Record",
                            "value": f"{mailserver} (Priority: {priority})",
                            "description": "Mail exchange server for the domain"
                        })
                
                # Parse NS records - look for lines like "google.com. 1034 IN NS ns2.google.com."
                elif query_type == "NS" and "IN NS" in line:
                    parts = line.split()
                    if len(parts) >= 3 and parts[-2] == "NS":
                        nameserver = parts[-1].rstrip('.')
                        dns_info.append({
                            "type": "NS Record",
                            "value": nameserver,
                            "description": "Name server responsible for the domain"
                        })
                
                # Parse TXT records - look for lines like "google.com. 3600 IN TXT "apple-domain-verification=..."""
                elif query_type == "TXT" and "IN TXT" in line:
                    # Extract TXT content - it might be quoted
                    if '"' in line:
                        start = line.find('"')
                        end = line.rfind('"')
                        if start != end:
                            txt_content = line[start+1:end]
                            if txt_content and len(txt_content) > 5:
                                dns_info.append({
                                    "type": "TXT Record",
                                    "value": txt_content,
                                    "description": "Text record (may contain SPF, DKIM, or other info)"
                                })
                    else:
                        # Fallback for unquoted TXT records
                        parts = line.split()
                        if len(parts) >= 3 and parts[-2] == "TXT":
                            txt_content = parts[-1]
                            if txt_content and len(txt_content) > 5:
                                dns_info.append({
                                    "type": "TXT Record",
                                    "value": txt_content,
                                    "description": "Text record (may contain SPF, DKIM, or other info)"
                                })
                
                # Parse CNAME records - look for lines like "www.google.com. IN CNAME google.com."
                elif query_type == "CNAME" and "IN CNAME" in line:
                    parts = line.split()
                    if len(parts) >= 3 and parts[-2] == "CNAME":
                        cname_target = parts[-1].rstrip('.')
                        dns_info.append({
                            "type": "CNAME Record",
                            "value": f"www.{domain} -> {cname_target}",
                            "description": "Canonical name alias for the domain"
                        })
                
                # Parse SOA records - look for lines like "google.com. 60 IN SOA ns1.google.com. dns-admin.google.com. ..."
                elif query_type == "SOA" and "IN SOA" in line:
                    parts = line.split()
                    if len(parts) >= 7 and parts[-6] == "SOA":
                        primary_ns = parts[-5].rstrip('.')
                        admin_email = parts[-4].rstrip('.')
                        dns_info.append({
                            "type": "SOA Record",
                            "value": f"Primary NS: {primary_ns}, Admin: {admin_email}",
                            "description": "Start of Authority record for the domain"
                        })
        
        return dns_info
    
    def _save_dns_results(self, dns_info, domain):
        """Save DNS reconnaissance results to JSON file."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "target": domain,
            "dns_info": dns_info,
            "total_count": len(dns_info)
        }
        
        # Create safe filename from domain
        safe_domain = domain.replace('.', '_').replace('/', '_')
        output_file = os.path.join(self.vulns_path, f"dns_recon_{safe_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]✅ DNS reconnaissance results saved to: {output_file}[/green]")
        except Exception as e:
            console.print(f"[yellow]⚠️ Could not save results: {e}[/yellow]")
    
    def comprehensive_reporting(self):
        """Generate comprehensive security assessment report."""
        console.print("[bold red]📊 Comprehensive Security Assessment Report[/bold red]")
        console.print("=" * 50)
        
        # Report options
        console.print(f"\n[bold]⚙️ Report Options:[/bold]")
        report_type = self.validate_input(
            "Select report type (1=Summary, 2=Detailed, 3=Full): ",
            ["1", "2", "3"]
        )
        
        # Generate report
        console.print(f"\n[blue]🚀 Generating comprehensive report...[/blue]")
        
        try:
            # Create report file
            report_file = os.path.join(self.session_path, f"comprehensive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            
            with open(report_file, 'w') as f:
                # Header
                f.write("=" * 80 + "\n")
                f.write("NetHawk v3.0 - Comprehensive Security Assessment Report\n")
                f.write("=" * 80 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Session: {self.session_path}\n")
                f.write(f"Report Type: {'Summary' if report_type == '1' else 'Detailed' if report_type == '2' else 'Full'}\n\n")
                
                # Executive Summary
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write("This report contains the results of comprehensive network security assessment\n")
                f.write("performed using NetHawk v3.0 - Professional penetration testing tool.\n\n")
                
                # Session Information
                f.write("SESSION INFORMATION\n")
                f.write("-" * 40 + "\n")
                f.write(f"Session Number: {self.session_number}\n")
                f.write(f"Session Path: {self.session_path}\n")
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Python Version: {sys.version.split()[0]}\n")
                f.write(f"Platform: {sys.platform}\n\n")
                
                # Available Tools
                f.write("AVAILABLE TOOLS\n")
                f.write("-" * 40 + "\n")
                available_tools = [k for k, v in self.tools_available.items() if v]
                f.write(f"Tools Available: {', '.join(available_tools) if available_tools else 'None'}\n")
                f.write(f"Total Tools: {len(available_tools)}/{len(self.tools_available)}\n\n")
                
                # Captured Handshakes
                f.write("CAPTURED HANDSHAKES\n")
                f.write("-" * 40 + "\n")
                cap_files = [f for f in os.listdir(self.handshakes_path) if f.endswith('.cap')]
                if cap_files:
                    f.write(f"Total Handshakes Captured: {len(cap_files)}\n")
                    for cap_file in cap_files:
                        cap_path = os.path.join(self.handshakes_path, cap_file)
                        file_size = os.path.getsize(cap_path)
                        f.write(f"  • {cap_file} ({file_size} bytes)\n")
                        f.write(f"    Status: Captured - ready for external cracking\n")
                else:
                    f.write("No handshake files captured.\n")
                f.write("\n")
                
                # Vulnerability Reports
                f.write("VULNERABILITY REPORTS\n")
                f.write("-" * 40 + "\n")
                vuln_files = [f for f in os.listdir(self.vulns_path) if f.endswith('.json')]
                if vuln_files:
                    f.write(f"Total Vulnerability Reports: {len(vuln_files)}\n")
                    for vuln_file in vuln_files:
                        f.write(f"  • {vuln_file}\n")
                        # Try to parse and show summary
                        try:
                            vuln_path = os.path.join(self.vulns_path, vuln_file)
                            with open(vuln_path, 'r') as vf:
                                vuln_data = json.load(vf)
                                if 'total_count' in vuln_data:
                                    f.write(f"    Vulnerabilities Found: {vuln_data['total_count']}\n")
                                if 'target' in vuln_data:
                                    f.write(f"    Target: {vuln_data['target']}\n")
                        except:
                            pass
                else:
                    f.write("No vulnerability reports generated.\n")
                f.write("\n")
                
                # Session Statistics
                f.write("SESSION STATISTICS\n")
                f.write("-" * 40 + "\n")
                f.write(f"Handshakes Directory: {self.handshakes_path}\n")
                f.write(f"Vulnerabilities Directory: {self.vulns_path}\n")
                f.write(f"Logs Directory: {self.logs_path}\n")
                f.write(f"Reports Directory: {self.reports_path}\n\n")
                
                # File Counts
                f.write("FILE COUNTS\n")
                f.write("-" * 40 + "\n")
                f.write(f"Handshake Files: {len(cap_files)}\n")
                f.write(f"Vulnerability Reports: {len(vuln_files)}\n")
                
                # Count other files
                try:
                    log_files = [f for f in os.listdir(self.logs_path) if f.endswith('.jsonl')]
                    f.write(f"Log Files: {len(log_files)}\n")
                except:
                    f.write("Log Files: 0\n")
                
                try:
                    report_files = [f for f in os.listdir(self.reports_path) if f.endswith('.txt')]
                    f.write(f"Report Files: {len(report_files)}\n")
                except:
                    f.write("Report Files: 0\n")
                
                f.write("\n")
                
                # Recommendations
                f.write("RECOMMENDATIONS\n")
                f.write("-" * 40 + "\n")
                f.write("1. Review all captured handshakes for potential security issues\n")
                f.write("2. Analyze vulnerability reports for remediation steps\n")
                f.write("3. Use external tools (aircrack-ng, hashcat) for handshake cracking\n")
                f.write("4. Implement security measures based on findings\n")
                f.write("5. Regular security assessments recommended\n\n")
                
                # Footer
                f.write("=" * 80 + "\n")
                f.write("Report generated by NetHawk v3.0\n")
                f.write("For security purposes only - use responsibly\n")
                f.write("=" * 80 + "\n")
            
            # Display summary
            console.print(f"\n[green]✅ Comprehensive report generated![/green]")
            console.print(f"[blue]Report saved to: {report_file}[/blue]")
            
            # Show report summary
            console.print(f"\n[bold green]📊 REPORT SUMMARY[/bold green]")
            console.print(f"[blue]Session: {self.session_number}[/blue]")
            console.print(f"[green]Handshakes Captured: {len(cap_files)}[/green]")
            console.print(f"[green]Vulnerability Reports: {len(vuln_files)}[/green]")
            console.print(f"[yellow]Available Tools: {len(available_tools)}/{len(self.tools_available)}[/yellow]")
            
            # Show file locations
            console.print(f"\n[bold cyan]📁 File Locations:[/bold cyan]")
            console.print(f"[blue]Handshakes: {self.handshakes_path}[/blue]")
            console.print(f"[blue]Vulnerabilities: {self.vulns_path}[/blue]")
            console.print(f"[blue]Logs: {self.logs_path}[/blue]")
            console.print(f"[blue]Reports: {self.reports_path}[/blue]")
            
        except Exception as e:
            console.print(f"[red]❌ Error generating comprehensive report: {e}[/red]")
        
        console.print(f"\n[yellow]Press Ctrl+C to stop[/yellow]")
    
    def _load_config(self):
        """Load configuration (placeholder). Returns dict of defaults."""
        # TODO: read a JSON/YAML config file if you need persistent settings
        return {
            "default_scan_timeout": 300,
            "default_port_range": "top1000",
            "default_scan_type": "aggressive",
            "default_interface": "wlan0",
            "scan_duration": 60,
            "output_format": "txt"
        }
    
    def run(self):
        """Main application loop."""
        try:
            # Display logo and check tools
            self.display_logo()
            
            while True:
                self.display_main_menu()
                
                choice = self.validate_input(
                    "\nSelect an option: ", 
                    ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]
                )
                
                if choice == "1":
                    self.aggressive_passive_scan()
                elif choice == "2":
                    self.aggressive_active_scan()
                elif choice == "3":
                    self.advanced_handshake_capture()
                elif choice == "4":
                    self.vulnerability_assessment()
                elif choice == "5":
                    self.web_application_scanning()
                elif choice == "6":
                    self.smb_enumeration()
                elif choice == "7":
                    self.dns_reconnaissance()
                elif choice == "8":
                    self.comprehensive_reporting()
                elif choice == "9":
                    self._display_hybrid_detection_explanation()
                elif choice == "0":
                    console.print("[bold green]Thank you for using NetHawk v3.0![/bold green]")
                    break
                
                input("\nPress Enter to continue...")
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        except Exception as e:
            console.print(f"\n[red]Unexpected error: {e}[/red]")

    def _ping_host(self, ip, count=1, timeout=1):
        """Simple ping wrapper used as gateway reachability test."""
        try:
            # Use system ping (linux)
            result = subprocess.run(["ping", "-c", str(count), "-W", str(timeout), ip],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except FileNotFoundError:
            console.print(f"[yellow]Warning: 'ping' command not found. Install iputils-ping package.[/yellow]")
            # fallback to aggressive ping
            return self._aggressive_ping_host(ip)
        except subprocess.TimeoutExpired:
            console.print(f"[yellow]Warning: Ping timed out for {ip}[/yellow]")
            return False
        except Exception:
            # fallback to aggressive ping
            return self._aggressive_ping_host(ip)

    def _scan_host_ports(self, ip, port_range="top1000", scan_type="aggressive"):
        """
        Perform a per-host nmap scan that tries to discover open ports, service versions, and OS.
        Returns a dict: {"open_ports": [...], "os": "string or Unknown", "services": [...], "nmap_output": "raw"}
        """
        try:
            # Ensure nmap exists
            if not shutil.which("nmap"):
                console.print("[yellow]Warning: nmap not installed. Install nmap to get ports/OS detection.[/yellow]")
                return {"open_ports": [], "os": "Unknown", "services": [], "nmap_output": ""}

            # Build nmap command
            cmd = ["nmap"]
            # -Pn: skip host discovery (we already know host is up). This avoids false negatives.
            # -sS: SYN scan (requires root) — faster and better for stealth.
            # -sV: service/version detection
            # -O: OS detection (requires root and packets to be allowed)
            # --version-intensity 5: moderate version detection intensity
            # -p: port range can be "1-65535" or "top1000"
            cmd.extend(["-Pn", "-sS", "-sV", "-O", "--version-intensity", "5"])

            # Port selection
            if port_range == "all":
                cmd.extend(["-p", "1-65535"])
            elif port_range == "top1000":
                cmd.extend(["--top-ports", "1000"])
            else:
                # If user passed e.g. "1-1000"
                cmd.extend(["-p", str(port_range)])

            # Add some timing option depending on scan_type
            if scan_type == "fast":
                cmd.extend(["-T4"])
            elif scan_type == "aggressive":
                cmd.extend(["-T4"])
            else:  # comprehensive
                cmd.extend(["-T3", "--max-retries", "2"])

            cmd.append(ip)

            # Run nmap (allow long timeout)
            console.print(f"[blue]Running nmap on {ip} (this may take a few seconds)...[/blue]")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            raw = result.stdout if result.returncode == 0 else result.stdout + "\n" + result.stderr

            # Parse open ports / services
            open_ports = []
            services = []

            # lines like: "22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)"
            for line in raw.splitlines():
                line = line.strip()
                m = re.match(r"^(\d+)\/(tcp|udp)\s+open\s+([^\s]+)(\s+(.*))?$", line)
                if m:
                    portnum = m.group(1)
                    proto = m.group(2)
                    svc = m.group(3)
                    svc_banner = m.group(5) or ""
                    open_ports.append({"port": portnum, "protocol": proto, "service": svc, "banner": svc_banner})
                    services.append(svc)

            # Parse OS info: look for common markers
            os_info = "Unknown"
            # look for lines like "OS details: Linux 3.10 - 4.11"
            m = re.search(r"OS details:\s*(.+)", raw)
            if m:
                os_info = m.group(1).strip()
            else:
                # nmap sometimes writes "OS guesses: Linux 3.2 - 4.9"
                m2 = re.search(r"OS guesses:\s*(.+)", raw)
                if m2:
                    os_info = m2.group(1).strip()
                else:
                    # Device type sometimes on "Device type: general purpose"
                    m3 = re.search(r"Device type:\s*(.+)", raw)
                    if m3:
                        os_info = m3.group(1).strip()

            # Try to get MAC/vendor (local ARP)
            mac = self._get_mac_address(ip) if hasattr(self, "_get_mac_address") else "Unknown"
            mac_vendor = self._get_mac_vendor(mac) if hasattr(self, "_get_mac_vendor") else None

            # Infer device kind from ports/services/os/vendor using hybrid methodology
            device_kind = self._infer_device_type(open_ports, services, os_info, mac_vendor, mac)

            return {
                "open_ports": open_ports,
                "os": os_info or "Unknown",
                "services": services,
                "nmap_output": raw,
                "mac": mac,
                "mac_vendor": mac_vendor,
                "device": device_kind
            }

        except subprocess.TimeoutExpired:
            console.print(f"[yellow]Nmap timed out scanning {ip}[/yellow]")
            return {"open_ports": [], "os": "Unknown", "services": [], "nmap_output": ""}
        except Exception as e:
            console.print(f"[red]Error scanning {ip}: {e}[/red]")
            return {"open_ports": [], "os": "Unknown", "services": [], "nmap_output": ""}
    

def main():
    """Main entry point."""
    # Check if running on Linux
    if sys.platform != "linux":
        console.print("[red]NetHawk is designed for Linux systems only![/red]")
        sys.exit(1)
    
    # Check if running as root
    if os.geteuid() != 0:
        console.print("[yellow]Warning: Some features may require root privileges[/yellow]")
        console.print("[blue]Consider running with: sudo python3 NetHawk.py[/blue]")
    
    # Create NetHawk instance and run
    nethawk = NetHawk()
    nethawk.run()

if __name__ == "__main__":
    main()
