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
            self.vulns_path
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
[bold]9.[/bold] Exit

[italic]Session: {session}[/italic]
[italic]Path: {path}[/italic]
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
        target = self._get_current_network()
        console.print(f"[blue]Debug: Detected target = '{target}'[/blue]")
        console.print(f"[blue]Debug: Target type = {type(target)}[/blue]")

        # Validate detected target
        valid_network = None
        if isinstance(target, str):
            try:
                # try to parse; don't enforce strict host/network alignment
                ipaddress.IPv4Network(target, strict=False)
                valid_network = target
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
        
        # Create network object with final validation
        try:
            network = ipaddress.IPv4Network(network_string, strict=False)
        except Exception as e:
            console.print(f"[red]Invalid network format: {e}[/red]")
            console.print(f"[red]Network string was: '{network_string}'[/red]")
            return
        
        try:
            console.print(f"[blue]AGGRESSIVE scanning network: {network_string}[/blue]")
            
            # Get scan options
            console.print("\n[bold]AGGRESSIVE Scan Options:[/bold]")
            port_range = Prompt.ask("Port range (e.g., 1-1000, top1000, all)", default="top1000")
            scan_type = Prompt.ask("Scan type (fast/aggressive/comprehensive)", default="aggressive")
            
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
                    console.print(f"  [green]IP Address:[/green] {host['ip']}")
                    console.print(f"  [green]Status:[/green] {host['status']}")
                    if host.get('mac') and host['mac'] != 'Unknown':
                        console.print(f"  [green]MAC Address:[/green] {host['mac']}")
                    if host.get('open_ports'):
                        console.print(f"  [green]Open Ports:[/green] {len(host['open_ports'])} ports")
                        for port in host['open_ports'][:5]:  # Show first 5 ports
                            console.print(f"    - Port {port['port']}/{port['protocol']}: {port['service']}")
                        if len(host['open_ports']) > 5:
                            console.print(f"    - ... and {len(host['open_ports'])-5} more ports")
                    else:
                        console.print(f"  [yellow]No open ports found[/yellow]")
            
            console.print(f"\n[bold green]✅ Active scan completed successfully![/bold green]")
            console.print(f"[blue]Results displayed above - no files saved[/blue]")
        else:
            console.print("[yellow]No active hosts found.[/yellow]")
            console.print("[blue]Try scanning a different network or check your network connection[/blue]")
                
        except Exception as e:
            console.print(f"[red]Invalid network format: {e}[/red]")
    
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
                        hosts.append({
                            "ip": str(ip),
                            "status": "up",
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
            cmd = ["nmap", "-sn", "-T4", str(network)]
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
                                hosts.append({
                                    "ip": ip,
                                    "status": "up",
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
                open_ports = self._scan_host_ports(host['ip'], port_range, scan_type)
                host['open_ports'] = open_ports
                
                if open_ports:
                    console.print(f"[green]✓ {host['ip']}: {len(open_ports)} open ports[/green]")
                    for port in open_ports[:5]:  # Show first 5 ports
                        console.print(f"[blue]  - Port {port['port']}: {port['service']}[/blue]")
                    if len(open_ports) > 5:
                        console.print(f"[blue]  - ... and {len(open_ports)-5} more ports[/blue]")
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
                    cmd = ["nmap", "-T4", "-F", "--top-ports", "1000", host["ip"]]
                elif scan_type == "aggressive":
                    cmd = ["nmap", "-T4", "-A", "-sV", "-sC", "--script", "vuln", host["ip"]]
                else:  # comprehensive
                    cmd = ["nmap", "-T4", "-A", "-sV", "-sC", "-O", "--script", "vuln,discovery", host["ip"]]
                
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
                        "port": parts[0].split('/')[0],
                        "protocol": parts[0].split('/')[1],
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "unknown"
                    }
                    open_ports.append(port_info)
        
        return open_ports
    
    def _display_aggressive_hosts_table(self, hosts):
        """Display discovered hosts in an enhanced table."""
        table = Table(title="AGGRESSIVE Scan - Discovered Hosts")
        table.add_column("IP Address", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Open Ports", style="red")
        table.add_column("OS", style="blue")
        
        for host in hosts:
            open_ports_str = ", ".join([p["port"] for p in host["open_ports"]]) if host["open_ports"] else "None"
            table.add_row(
                host["ip"],
                host["status"],
                host["mac"],
                open_ports_str,
                host.get("os", "Unknown")
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
        console.print("[bold red]Advanced Handshake Capture + Deauth[/bold red]")
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
        
        # Get target information
        bssid = Prompt.ask("Enter target BSSID (MAC address)")
        essid = Prompt.ask("Enter target ESSID (network name)")
        channel = Prompt.ask("Enter target channel", default="6")
        
        # Validate BSSID format
        if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid):
            console.print("[red]Invalid BSSID format! Use format: XX:XX:XX:XX:XX:XX[/red]")
            return
        
        console.print(f"[blue]Target: {essid} ({bssid}) on channel {channel}[/blue]")
        
        # Legal warning
        if not Confirm.ask("[bold red]WARNING: Only capture handshakes from networks you own or have permission to test! Continue?[/bold red]"):
            console.print("[yellow]Operation cancelled.[/yellow]")
            return
        
        # Set monitor mode
        monitor_iface = self._set_monitor_mode(iface)
        if not monitor_iface:
            return
        
        # Advanced capture options
        console.print("\n[bold]Advanced Capture Options:[/bold]")
        use_deauth = Confirm.ask("Use deauth attacks to force handshake?", default=True)
        deauth_count = IntPrompt.ask("Number of deauth packets", default=10) if use_deauth else 0
        
        # Start advanced handshake capture
        output_file = os.path.join(self.handshakes_path, f"{essid}_advanced_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        try:
            console.print(f"[blue]Starting advanced handshake capture...[/blue]")
            console.print("[yellow]Press Ctrl+C to stop[/yellow]")
            
            # Start airodump-ng
            cmd = ["airodump-ng", "-c", channel, "-w", output_file, "--bssid", bssid, monitor_iface]
            airodump_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Wait a bit for airodump to start
            time.sleep(5)
            
            # Start deauth attack if requested
            deauth_process = None
            if use_deauth:
                console.print(f"[red]Starting deauth attack with {deauth_count} packets...[/red]")
                deauth_cmd = ["aireplay-ng", "--deauth", str(deauth_count), "-a", bssid, monitor_iface]
                deauth_process = subprocess.Popen(deauth_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Show progress for handshake capture
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Capturing handshake...", total=30)
                
                for i in range(30):
                    progress.update(task, description=f"Capturing... {i+1}/30s")
                    time.sleep(1)
                
                progress.update(task, description="Capture complete!")
            
            # Stop processes
            airodump_process.terminate()
            airodump_process.wait()
            
            if deauth_process:
                deauth_process.terminate()
                deauth_process.wait()
            
            console.print(f"[green]✓ Advanced handshake capture completed![/green]")
            console.print(f"[blue]Handshake saved to: {output_file}*[/blue]")
            console.print("[yellow]Note: Use external tools like aircrack-ng to crack the handshake[/yellow]")
            
            # Show session storage message
            console.print(f"\n[bold green]📁 Scan Results Stored in Session Files:[/bold green]")
            console.print(f"[blue]Session Path: {self.session_path}[/blue]")
            console.print(f"[blue]Handshakes Directory: {self.handshakes_path}[/blue]")
            console.print(f"[yellow]Files created:[/yellow]")
            console.print(f"[blue]  - {os.path.basename(output_file)}.cap (Handshake file)[/blue]")
            console.print(f"[blue]  - {os.path.basename(output_file)}.csv (Capture data)[/blue]")
            console.print(f"[green]✓ All capture data is automatically saved to your session![/green]")
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Capture stopped by user.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during advanced capture: {e}[/red]")
        finally:
            # Restore managed mode
            self._restore_managed_mode(monitor_iface)
    
    def vulnerability_assessment(self):
        """Perform vulnerability assessment on discovered hosts."""
        console.print("[bold red]Vulnerability Assessment[/bold red]")
        console.print("=" * 50)
        
        # Check for vulnerability scanning tools
        if not self.tools_available.get("nmap", False):
            console.print("[red]nmap not found! Please install nmap.[/red]")
            return
        
        # Get target
        target = Prompt.ask("Enter target IP or network")
        
        console.print(f"[blue]Starting vulnerability assessment on {target}...[/blue]")
        
        try:
            # Run vulnerability scan with progress
            cmd = ["nmap", "-T4", "--script", "vuln", "-sV", target]
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Running vulnerability scan...", total=100)
                
                # Start the scan in background
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Show progress with longer timeout for vulnerability scans
                for i in range(600):  # 10 minutes max for vulnerability scans
                    progress.update(task, description=f"Scanning {target}... {i+1}/600s")
                    time.sleep(1)
                    
                    # Check if process finished
                    if process.poll() is not None:
                        progress.update(task, description="Scan completed!")
                        break
                
                # Get results
                stdout, stderr = process.communicate()
                result = type('obj', (object,), {'returncode': process.returncode, 'stdout': stdout, 'stderr': stderr})()
            
            if result.returncode == 0:
                # Parse vulnerabilities
                vulnerabilities = self._parse_vulnerabilities(result.stdout)
                
                if vulnerabilities:
                    console.print(f"\n[bold green]📊 VULNERABILITY ASSESSMENT RESULTS[/bold green]")
                    console.print(f"[blue]Target: {target}[/blue]")
                    console.print(f"[green]Vulnerabilities Found: {len(vulnerabilities)}[/green]")
                    console.print(f"[yellow]Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                    
                    console.print(f"\n[bold cyan]DETAILED VULNERABILITIES:[/bold cyan]")
                    for i, vuln in enumerate(vulnerabilities, 1):
                        console.print(f"\n[bold]Vulnerability {i}:[/bold]")
                        console.print(f"  [red]Title:[/red] {vuln['title']}")
                        console.print(f"  [yellow]Severity:[/yellow] {vuln['severity']}")
                        console.print(f"  [blue]Description:[/blue] {vuln['description'][:200]}...")
                    
                    console.print(f"\n[bold green]✅ Vulnerability assessment completed![/bold green]")
                    console.print(f"[blue]Results displayed above - no files saved[/blue]")
                else:
                    console.print("[yellow]No vulnerabilities found.[/yellow]")
                    console.print("[blue]Target appears to be secure or scan was inconclusive[/blue]")
            else:
                console.print(f"[red]Vulnerability scan failed: {result.stderr}[/red]")
                console.print(f"[blue]Partial output: {result.stdout[:500]}...[/blue]")
                
        except subprocess.TimeoutExpired:
            console.print("[yellow]Vulnerability scan timed out[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during vulnerability assessment: {e}[/red]")
    
    def _parse_vulnerabilities(self, nmap_output):
        """Parse nmap output to extract vulnerabilities."""
        vulnerabilities = []
        lines = nmap_output.split('\n')
        
        current_vuln = None
        for line in lines:
            if 'VULNERABLE:' in line:
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                current_vuln = {
                    "title": line.split('VULNERABLE:')[1].strip(),
                    "description": "",
                    "severity": "Unknown"
                }
            elif current_vuln and line.strip():
                current_vuln["description"] += line.strip() + " "
        
        if current_vuln:
            vulnerabilities.append(current_vuln)
        
        return vulnerabilities
    
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
        """Web application vulnerability scanning."""
        console.print("[bold red]Web Application Scanning[/bold red]")
        console.print("=" * 50)
        
        # Check for web scanning tools
        if not self.tools_available.get("nikto", False):
            console.print("[red]nikto not found! Please install nikto.[/red]")
            return
        
        # Get target URL with validation
        while True:
            target_url = Prompt.ask("Enter target URL (e.g., http://192.168.1.1)")
            if target_url.startswith(('http://', 'https://')):
                break
            else:
                console.print("[red]Please enter a valid URL starting with http:// or https://[/red]")
        
        console.print(f"[blue]Starting web application scan on {target_url}...[/blue]")
        
        try:
            # Run nikto scan with progress
            output_file = os.path.join(self.vulns_path, f"nikto_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            cmd = ["nikto", "-h", target_url, "-Format", "json", "-output", output_file]
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Scanning web application...", total=100)
                
                # Start nikto in background
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Show progress with longer timeout for web scans
                for i in range(600):  # 10 minutes max for web scans
                    progress.update(task, description=f"Scanning {target_url}... {i+1}/600s")
                    time.sleep(1)
                    
                    # Check if process finished
                    if process.poll() is not None:
                        progress.update(task, description="Web scan completed!")
                        break
                
                # Get results
                stdout, stderr = process.communicate()
                result = type('obj', (object,), {'returncode': process.returncode, 'stdout': stdout, 'stderr': stderr})()
            
            if result.returncode == 0:
                console.print(f"\n[bold green]📊 WEB APPLICATION SCAN RESULTS[/bold green]")
                console.print(f"[blue]Target: {target_url}[/blue]")
                console.print(f"[yellow]Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                
                # Show detailed results in terminal
                if result.stdout:
                    console.print(f"\n[bold cyan]SCAN RESULTS:[/bold cyan]")
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip():
                            console.print(f"[blue]{line}[/blue]")
                
                console.print(f"\n[bold green]✅ Web application scan completed![/bold green]")
                console.print(f"[blue]Results displayed above - no files saved[/blue]")
            else:
                console.print(f"[red]Web application scan failed: {result.stderr}[/red]")
                console.print(f"[blue]Partial output: {result.stdout[:500]}...[/blue]")
                
                # Show some results if available
                if result.stdout:
                    console.print(f"[yellow]Scan output:[/yellow]")
                    console.print(result.stdout[:500] + "..." if len(result.stdout) > 500 else result.stdout)
                
        except subprocess.TimeoutExpired:
            console.print("[yellow]Web application scan timed out[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during web application scanning: {e}[/red]")
    
    def smb_enumeration(self):
        """SMB/Windows enumeration."""
        console.print("[bold red]SMB/Windows Enumeration[/bold red]")
        console.print("=" * 50)
        
        # Check for SMB tools
        if not self.tools_available.get("enum4linux", False):
            console.print("[red]enum4linux not found! Please install enum4linux.[/red]")
            return
        
        # Get target with IP validation
        while True:
            target = Prompt.ask("Enter target IP")
            try:
                ipaddress.IPv4Address(target)
                break
            except ValueError:
                console.print("[red]Please enter a valid IP address[/red]")
        
        console.print(f"[blue]Starting SMB enumeration on {target}...[/blue]")
        
        try:
            # Run enum4linux with progress
            cmd = ["enum4linux", "-a", target]
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Enumerating SMB services...", total=100)
                
                # Start enum4linux in background
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Show progress with longer timeout for SMB scans
                for i in range(600):  # 10 minutes max for SMB scans
                    progress.update(task, description=f"Enumerating {target}... {i+1}/600s")
                    time.sleep(1)
                    
                    # Check if process finished
                    if process.poll() is not None:
                        progress.update(task, description="SMB enumeration completed!")
                        break
                
                # Get results
                stdout, stderr = process.communicate()
                result = type('obj', (object,), {'returncode': process.returncode, 'stdout': stdout, 'stderr': stderr})()
            
            if result.returncode == 0:
                console.print(f"\n[bold green]📊 SMB ENUMERATION RESULTS[/bold green]")
                console.print(f"[blue]Target: {target}[/blue]")
                console.print(f"[yellow]Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
                
                # Show detailed results in terminal
                if result.stdout:
                    console.print(f"\n[bold cyan]ENUMERATION RESULTS:[/bold cyan]")
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if line.strip():
                            console.print(f"[blue]{line}[/blue]")
                
                console.print(f"\n[bold green]✅ SMB enumeration completed![/bold green]")
                console.print(f"[blue]Results displayed above - no files saved[/blue]")
            else:
                console.print(f"[red]SMB enumeration failed: {result.stderr}[/red]")
                console.print(f"[blue]Partial output: {result.stdout[:500]}...[/blue]")
                
        except subprocess.TimeoutExpired:
            console.print("[yellow]SMB enumeration timed out[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during SMB enumeration: {e}[/red]")
    
    def dns_reconnaissance(self):
        """DNS reconnaissance."""
        console.print("[bold red]DNS Reconnaissance[/bold red]")
        console.print("=" * 50)
        
        # Check for DNS tools
        if not self.tools_available.get("dig", False):
            console.print("[red]dig not found! Please install dnsutils.[/red]")
            return
        
        # Get target domain with validation
        while True:
            domain = Prompt.ask("Enter target domain")
            if domain and '.' in domain and not domain.startswith('.'):
                break
            else:
                console.print("[red]Please enter a valid domain (e.g., example.com)[/red]")
        
        console.print(f"[blue]Starting DNS reconnaissance on {domain}...[/blue]")
        
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
                task = progress.add_task("Performing DNS reconnaissance...", total=3)
                
                # A records
                progress.update(task, description=f"Querying A records for {domain}...")
                result = subprocess.run(["dig", domain, "A"], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    dns_results["A_records"] = result.stdout
                progress.advance(task)
                
                # MX records
                progress.update(task, description=f"Querying MX records for {domain}...")
                result = subprocess.run(["dig", domain, "MX"], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    dns_results["MX_records"] = result.stdout
                progress.advance(task)
                
                # NS records
                progress.update(task, description=f"Querying NS records for {domain}...")
                result = subprocess.run(["dig", domain, "NS"], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    dns_results["NS_records"] = result.stdout
                progress.advance(task)
            
            console.print(f"\n[bold green]📊 DNS RECONNAISSANCE RESULTS[/bold green]")
            console.print(f"[blue]Target: {domain}[/blue]")
            console.print(f"[yellow]Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/yellow]")
            
            # Show results in terminal
            console.print(f"\n[bold cyan]DNS QUERY RESULTS:[/bold cyan]")
            for query_type, result in dns_results.items():
                if result:
                    console.print(f"\n[bold]{query_type}:[/bold]")
                    lines = result.split('\n')
                    for line in lines:
                        if line.strip():
                            console.print(f"[blue]  {line}[/blue]")
            
            console.print(f"\n[bold green]✅ DNS reconnaissance completed![/bold green]")
            console.print(f"[blue]Results displayed above - no files saved[/blue]")
            
        except Exception as e:
            console.print(f"[red]Error during DNS reconnaissance: {e}[/red]")
    
    def comprehensive_reporting(self):
        """Generate comprehensive security assessment report."""
        console.print("[bold red]Comprehensive Security Assessment Report[/bold red]")
        console.print("=" * 50)
        
        report_file = os.path.join(self.session_path, f"comprehensive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            with open(report_file, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("NetHawk v3.0 - Comprehensive Security Assessment Report\n")
                f.write("=" * 80 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Session: {self.session_path}\n\n")
                
                # Executive Summary
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write("This report contains the results of comprehensive network security assessment\n")
                f.write("performed using NetHawk v3.0 - AGGRESSIVE penetration testing tool.\n\n")
                
                # Session Summary
                f.write("SESSION SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write(f"Session Number: {self.session_number}\n")
                f.write(f"Session Path: {self.session_path}\n")
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Captured Handshakes
                f.write("CAPTURED HANDSHAKES\n")
                f.write("-" * 40 + "\n")
                cap_files = [f for f in os.listdir(self.handshakes_path) if f.endswith('.cap')]
                if cap_files:
                    for cap_file in cap_files:
                        cap_path = os.path.join(self.handshakes_path, cap_file)
                        file_size = os.path.getsize(cap_path)
                        f.write(f"File: {cap_file} ({file_size} bytes)\n")
                        f.write(f"  Status: Captured - ready for external cracking\n")
                        f.write("\n")
                else:
                    f.write("No handshake files captured.\n")
                f.write("\n")
                
                # Vulnerabilities
                f.write("DISCOVERED VULNERABILITIES\n")
                f.write("-" * 40 + "\n")
                vuln_files = [f for f in os.listdir(self.vulns_path) if f.endswith('.json')]
                if vuln_files:
                    for vuln_file in vuln_files:
                        f.write(f"Vulnerability Report: {vuln_file}\n")
                else:
                    f.write("No vulnerability reports generated.\n")
                f.write("\n")
                
                # System Information
                f.write("SYSTEM INFORMATION\n")
                f.write("-" * 40 + "\n")
                f.write(f"Python Version: {sys.version}\n")
                f.write(f"Platform: {sys.platform}\n")
                f.write(f"Working Directory: {os.getcwd()}\n")
                f.write(f"Available Tools: {', '.join([k for k, v in self.tools_available.items() if v])}\n")
            
            console.print(f"[green]✓ Comprehensive report generated: {report_file}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error generating comprehensive report: {e}[/red]")
    
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
                    ["1", "2", "3", "4", "5", "6", "7", "8", "9"]
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

    def _scan_host_ports(self, ip, port_range, scan_type):
        """Scan ports on a single host."""
        try:
            # Use nmap for port scanning
            if scan_type == "fast":
                cmd = ["nmap", "-T4", "-F", ip]
            elif scan_type == "aggressive":
                cmd = ["nmap", "-T4", "-A", ip]
            else:  # comprehensive
                cmd = ["nmap", "-T4", "-sS", "-sV", "-O", ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return self._parse_nmap_output(result.stdout)
            else:
                return []
                
        except Exception:
            return []
    
    def _parse_nmap_output(self, nmap_output):
        """Parse nmap output to extract open ports."""
        ports = []
        lines = nmap_output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0].split('/')
                    if len(port_info) == 2:
                        port = port_info[0]
                        protocol = port_info[1]
                        service = parts[2] if len(parts) > 2 else "unknown"
                        
                        ports.append({
                            "port": int(port),
                            "protocol": protocol,
                            "service": service,
                            "state": "open"
                        })
        
        return ports

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
