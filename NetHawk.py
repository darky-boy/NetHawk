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
        """Check if interface supports monitor mode."""
        try:
            # First check if interface exists and is wireless
            result = subprocess.run(["iw", iface, "info"], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return False
            
            # Check if it's a wireless interface
            if "type" not in result.stdout.lower():
                return False
            
            # Try to set monitor mode to test if it's supported
            test_result = subprocess.run(["iw", iface, "set", "type", "monitor"], 
                                       capture_output=True, text=True, timeout=5)
            
            if test_result.returncode == 0:
                # Restore to managed mode
                subprocess.run(["iw", iface, "set", "type", "managed"], 
                             capture_output=True, timeout=5)
                return True
            else:
                return False
                
        except Exception:
            # If we can't test, assume it might work and let airmon-ng handle it
            return True
    
    def _set_monitor_mode(self, iface):
        """Set interface to monitor mode."""
        try:
            console.print(f"[blue]Setting {iface} to monitor mode...[/blue]")
            
            # Stop conflicting processes
            subprocess.run(["airmon-ng", "check", "kill"], capture_output=True, timeout=10)
            
            # Set monitor mode
            result = subprocess.run(["airmon-ng", "start", iface], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                # Find the new monitor interface
                monitor_iface = iface + "mon"
                if os.path.exists(f'/sys/class/net/{monitor_iface}'):
                    console.print(f"[green]✓ Monitor mode enabled: {monitor_iface}[/green]")
                    return monitor_iface
                else:
                    console.print(f"[green]✓ Monitor mode enabled on {iface}[/green]")
                    return iface
            else:
                console.print(f"[red]Failed to set monitor mode: {result.stderr}[/red]")
                return None
                
        except Exception as e:
            console.print(f"[red]Error setting monitor mode: {e}[/red]")
            return None
    
    def _restore_managed_mode(self, iface):
        """Restore interface to managed mode."""
        try:
            console.print(f"[blue]Restoring {iface} to managed mode...[/blue]")
            subprocess.run(["airmon-ng", "stop", iface], capture_output=True, timeout=10)
            console.print(f"[green]✓ Interface restored to managed mode[/green]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not restore interface: {e}[/yellow]")
    
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
        
        # Check monitor mode support (but be flexible)
        if not self._check_monitor_mode_support(iface):
            console.print(f"[yellow]Warning: {iface} may not support monitor mode.[/yellow]")
            if not Confirm.ask("Continue anyway? (airmon-ng will try to enable monitor mode)"):
                return
        
        # Set monitor mode
        monitor_iface = self._set_monitor_mode(iface)
        if not monitor_iface:
            return
        
        # AGGRESSIVE scan options
        console.print("\n[bold]AGGRESSIVE Scan Options:[/bold]")
        duration = IntPrompt.ask("Scan duration (seconds)", default=60)
        channels = Prompt.ask("Channels to scan (e.g., 1,6,11 or all)", default="all")
        
        # Start AGGRESSIVE passive scan
        console.print(f"[blue]Starting AGGRESSIVE scan on {monitor_iface}...[/blue]")
        console.print(f"[yellow]Duration: {duration}s, Channels: {channels}[/yellow]")
        console.print("[yellow]Press Ctrl+C to stop scanning[/yellow]")
        
        try:
            # Use airodump-ng for AGGRESSIVE scanning
            output_file = os.path.join(self.logs_path, f"aggressive_passive_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            cmd = ["airodump-ng", "-w", output_file, "--output-format", "csv", "--manufacturer", "--uptime", "--wps"]
            
            if channels != "all":
                cmd.extend(["-c", channels])
            
            cmd.append(monitor_iface)
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Show progress bar for scan duration
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Scanning WiFi networks...", total=duration)
                
                for i in range(duration):
                    progress.update(task, description=f"Scanning... {i+1}/{duration}s")
                    time.sleep(1)
                
                progress.update(task, description="Scan complete!")
            
            process.terminate()
            process.wait()
            
            # Parse CSV results
            self._parse_aggressive_passive_results(output_file)
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan stopped by user.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during aggressive scan: {e}[/red]")
        finally:
            # Restore managed mode
            self._restore_managed_mode(monitor_iface)
    
    def _parse_aggressive_passive_results(self, output_file):
        """Parse airodump-ng CSV results with enhanced data."""
        csv_file = f"{output_file}-01.csv"
        if not os.path.exists(csv_file):
            console.print("[red]No CSV results found.[/red]")
            return
        
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
            
            # Display results
            if aps:
                self._display_aggressive_ap_table(aps)
            if clients:
                self._display_aggressive_client_table(clients)
            
            # Save to JSON
            self._save_aggressive_passive_results(aps, clients, output_file)
            
        except Exception as e:
            console.print(f"[red]Error parsing results: {e}[/red]")
    
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
    
    def _save_aggressive_passive_results(self, aps, clients, output_file):
        """Save aggressive passive scan results to JSON."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "scan_type": "aggressive_passive",
            "access_points": aps,
            "clients": clients,
            "summary": {
                "total_aps": len(aps),
                "total_clients": len(clients),
                "wps_enabled": len([ap for ap in aps if ap["WPS"] == "WPS"]),
                "hidden_networks": len([ap for ap in aps if ap["ESSID"] == "Hidden"])
            }
        }
        
        json_file = f"{output_file}.json"
        try:
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]✓ AGGRESSIVE results saved to: {json_file}[/green]")
        except Exception as e:
            console.print(f"[red]Error saving results: {e}[/red]")
    
    def aggressive_active_scan(self):
        """AGGRESSIVE active network scanning with port scanning and service detection."""
        console.print("[bold red]AGGRESSIVE Active Network Scan[/bold red]")
        console.print("=" * 50)
        
        # Get target network
        target = Prompt.ask("Enter target network (e.g., 192.168.1.0/24)")
        
        try:
            # Validate network
            network = ipaddress.IPv4Network(target, strict=False)
            console.print(f"[blue]AGGRESSIVE scanning network: {network}[/blue]")
            
            # AGGRESSIVE scan options
            console.print("\n[bold]AGGRESSIVE Scan Options:[/bold]")
            port_range = Prompt.ask("Port range (e.g., 1-1000, top1000, all)", default="top1000")
            scan_type = Prompt.ask("Scan type (fast/aggressive/comprehensive)", default="aggressive")
            
            # Perform AGGRESSIVE scan
            hosts = self._aggressive_host_discovery(network)
            
            if hosts:
                self._display_aggressive_hosts_table(hosts)
                
                # Port scan discovered hosts
                if Confirm.ask("Perform AGGRESSIVE port scanning on discovered hosts?"):
                    self._aggressive_port_scan(hosts, port_range, scan_type)
                
                self._save_aggressive_active_results(hosts, target)
            else:
                console.print("[yellow]No active hosts found.[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Invalid network format: {e}[/red]")
    
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
    
    def _save_aggressive_active_results(self, hosts, target):
        """Save aggressive active scan results to JSON."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "scan_type": "aggressive_active",
            "target_network": target,
            "hosts": hosts,
            "summary": {
                "total_hosts": len(hosts),
                "hosts_with_ports": len([h for h in hosts if h["open_ports"]])
            }
        }
        
        output_file = os.path.join(self.logs_path, f"aggressive_active_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]✓ AGGRESSIVE results saved to: {output_file}[/green]")
        except Exception as e:
            console.print(f"[red]Error saving results: {e}[/red]")
    
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
                
                # Show progress for up to 10 minutes
                for i in range(600):  # 10 minutes max
                    progress.update(task, description=f"Scanning {target}... {i+1}/600s")
                    time.sleep(1)
                    
                    # Check if process finished
                    if process.poll() is not None:
                        break
                
                # Get results
                stdout, stderr = process.communicate()
                result = type('obj', (object,), {'returncode': process.returncode, 'stdout': stdout, 'stderr': stderr})()
            
            if result.returncode == 0:
                # Parse vulnerabilities
                vulnerabilities = self._parse_vulnerabilities(result.stdout)
                
                if vulnerabilities:
                    self._display_vulnerabilities_table(vulnerabilities)
                    self._save_vulnerabilities(vulnerabilities, target)
                else:
                    console.print("[yellow]No vulnerabilities found.[/yellow]")
            else:
                console.print(f"[red]Vulnerability scan failed: {result.stderr}[/red]")
                
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
        
        # Get target URL
        target_url = Prompt.ask("Enter target URL (e.g., http://192.168.1.1)")
        
        console.print(f"[blue]Starting web application scan on {target_url}...[/blue]")
        
        try:
            # Run nikto scan
            cmd = ["nikto", "-h", target_url, "-Format", "json", "-output", os.path.join(self.vulns_path, f"nikto_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                console.print(f"[green]✓ Web application scan completed![/green]")
                console.print(f"[blue]Results saved to: {cmd[-1]}[/blue]")
            else:
                console.print(f"[red]Web application scan failed: {result.stderr}[/red]")
                
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
        
        # Get target
        target = Prompt.ask("Enter target IP")
        
        console.print(f"[blue]Starting SMB enumeration on {target}...[/blue]")
        
        try:
            # Run enum4linux
            cmd = ["enum4linux", "-a", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Save results
                output_file = os.path.join(self.logs_path, f"smb_enum_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
                
                console.print(f"[green]✓ SMB enumeration completed![/green]")
                console.print(f"[blue]Results saved to: {output_file}[/blue]")
            else:
                console.print(f"[red]SMB enumeration failed: {result.stderr}[/red]")
                
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
        
        # Get target domain
        domain = Prompt.ask("Enter target domain")
        
        console.print(f"[blue]Starting DNS reconnaissance on {domain}...[/blue]")
        
        try:
            # Run DNS queries
            dns_results = {}
            
            # A records
            result = subprocess.run(["dig", domain, "A"], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                dns_results["A_records"] = result.stdout
            
            # MX records
            result = subprocess.run(["dig", domain, "MX"], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                dns_results["MX_records"] = result.stdout
            
            # NS records
            result = subprocess.run(["dig", domain, "NS"], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                dns_results["NS_records"] = result.stdout
            
            # Save results
            output_file = os.path.join(self.logs_path, f"dns_recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(output_file, 'w') as f:
                json.dump(dns_results, f, indent=2)
            
            console.print(f"[green]✓ DNS reconnaissance completed![/green]")
            console.print(f"[blue]Results saved to: {output_file}[/blue]")
            
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
        """Load configuration from file."""
        try:
            if os.path.exists("config.json"):
                with open("config.json", 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        
        return {
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
