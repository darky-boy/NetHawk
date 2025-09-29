#!/usr/bin/env python3
"""
NetHawk - Professional Linux Network Security Tool
Robust, effective reconnaissance and penetration testing tool
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
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

# Initialize Rich console for colored output
console = Console()

class NetHawk:
    """Professional NetHawk application - Real reconnaissance capabilities."""
    
    def __init__(self):
        """Initialize NetHawk with robust session management."""
        self.config = self._load_config()
        self.session_number = self._get_next_session_number()
        self.session_path = os.path.abspath(f"sessions/session_{self.session_number}")
        self.handshakes_path = os.path.join(self.session_path, "handshakes")
        self.logs_path = os.path.join(self.session_path, "logs")
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
            self.logs_path
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
            "ping": "iputils-ping"
        }
        
        self.tools_available = {}
        missing_tools = []
        
        for tool, package in required_tools.items():
            if shutil.which(tool):
                self.tools_available[tool] = True
            else:
                self.tools_available[tool] = False
                missing_tools.append(f"{tool} (install: {package})")
        
        if missing_tools:
            console.print(f"[yellow]Missing tools: {', '.join(missing_tools)}[/yellow]")
            console.print("[blue]Some features may not work without these tools.[/blue]")
            console.print("[blue]Install with: sudo apt install aircrack-ng iw iproute2 nmap iputils-ping[/blue]")
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
        
        console.print(Panel(logo, title="[bold blue]NetHawk v2.0.0[/bold blue]", 
                           subtitle="[italic]Professional Linux Network Security Tool[/italic]"))
        console.print()
    
    def display_main_menu(self):
        """Display the main menu with options."""
        menu_text = """
[bold cyan]Main Menu[/bold cyan]

[bold]1.[/bold] Passive WiFi Scan
[bold]2.[/bold] Active Network Scan  
[bold]3.[/bold] Handshake Capture
[bold]4.[/bold] Reporting
[bold]5.[/bold] Exit

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
            result = subprocess.run(["iw", iface, "info"], capture_output=True, text=True, timeout=5)
            return "monitor" in result.stdout.lower()
        except Exception:
            return False
    
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
    
    def passive_scan(self):
        """Real passive WiFi scanning with proper CSV parsing."""
        console.print("[bold cyan]Passive WiFi Scan[/bold cyan]")
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
        
        # Check monitor mode support
        if not self._check_monitor_mode_support(iface):
            console.print(f"[red]{iface} does not support monitor mode.[/red]")
            return
        
        # Set monitor mode
        monitor_iface = self._set_monitor_mode(iface)
        if not monitor_iface:
            return
        
        # Start passive scan
        console.print(f"[blue]Starting passive scan on {monitor_iface}...[/blue]")
        console.print("[yellow]Press Ctrl+C to stop scanning[/yellow]")
        
        try:
            # Use airodump-ng for passive scanning
            output_file = os.path.join(self.logs_path, f"passive_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            cmd = ["airodump-ng", "-w", output_file, "--output-format", "csv", monitor_iface]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Let it run for a reasonable time
            time.sleep(15)
            process.terminate()
            process.wait()
            
            # Parse CSV results
            self._parse_passive_results(output_file)
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan stopped by user.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during passive scan: {e}[/red]")
        finally:
            # Restore managed mode
            self._restore_managed_mode(monitor_iface)
    
    def _parse_passive_results(self, output_file):
        """Parse airodump-ng CSV results and display them."""
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
                                "Auth": row[7]
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
                self._display_ap_table(aps)
            if clients:
                self._display_client_table(clients)
            
            # Save to JSON
            self._save_passive_results(aps, clients, output_file)
            
        except Exception as e:
            console.print(f"[red]Error parsing results: {e}[/red]")
    
    def _display_ap_table(self, aps):
        """Display access points in a table."""
        table = Table(title="Discovered Access Points")
        table.add_column("BSSID", style="cyan")
        table.add_column("ESSID", style="green")
        table.add_column("Channel", style="yellow")
        table.add_column("Power", style="red")
        table.add_column("Privacy", style="magenta")
        
        for ap in aps:
            table.add_row(
                ap["BSSID"],
                ap["ESSID"],
                ap["Channel"],
                ap["Power"],
                ap["Privacy"]
            )
        
        console.print(table)
    
    def _display_client_table(self, clients):
        """Display clients in a table."""
        table = Table(title="Discovered Clients")
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
    
    def _save_passive_results(self, aps, clients, output_file):
        """Save passive scan results to JSON."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "access_points": aps,
            "clients": clients,
            "summary": {
                "total_aps": len(aps),
                "total_clients": len(clients)
            }
        }
        
        json_file = f"{output_file}.json"
        try:
            with open(json_file, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]✓ Results saved to: {json_file}[/green]")
        except Exception as e:
            console.print(f"[red]Error saving results: {e}[/red]")
    
    def active_scan(self):
        """Real active network scanning with ARP sweep."""
        console.print("[bold cyan]Active Network Scan[/bold cyan]")
        console.print("=" * 50)
        
        # Get target network
        target = Prompt.ask("Enter target network (e.g., 192.168.1.0/24)")
        
        try:
            # Validate network
            network = ipaddress.IPv4Network(target, strict=False)
            console.print(f"[blue]Scanning network: {network}[/blue]")
            
            # Perform ARP sweep
            hosts = self._arp_sweep(network)
            
            if hosts:
                self._display_hosts_table(hosts)
                self._save_active_results(hosts, target)
            else:
                console.print("[yellow]No active hosts found.[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Invalid network format: {e}[/red]")
    
    def _arp_sweep(self, network):
        """Perform ARP sweep to discover active hosts."""
        hosts = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Scanning network...", total=len(list(network.hosts())))
            
            for ip in network.hosts():
                if self._ping_host(str(ip)):
                    hosts.append({
                        "ip": str(ip),
                        "status": "up",
                        "mac": self._get_mac_address(str(ip))
                    })
                progress.advance(task)
        
        return hosts
    
    def _ping_host(self, ip):
        """Ping a single host."""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                timeout=3
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _get_mac_address(self, ip):
        """Get MAC address using ARP table."""
        try:
            result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
        except Exception:
            pass
        return "Unknown"
    
    def _display_hosts_table(self, hosts):
        """Display discovered hosts in a table."""
        table = Table(title="Discovered Hosts")
        table.add_column("IP Address", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("MAC Address", style="yellow")
        
        for host in hosts:
            table.add_row(
                host["ip"],
                host["status"],
                host["mac"]
            )
        
        console.print(table)
    
    def _save_active_results(self, hosts, target):
        """Save active scan results to JSON."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "target_network": target,
            "hosts": hosts,
            "summary": {
                "total_hosts": len(hosts)
            }
        }
        
        output_file = os.path.join(self.logs_path, f"active_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            console.print(f"[green]✓ Results saved to: {output_file}[/green]")
        except Exception as e:
            console.print(f"[red]Error saving results: {e}[/red]")
    
    def handshake_capture(self):
        """Real WPA2/WPA3 handshake capture."""
        console.print("[bold cyan]Handshake Capture[/bold cyan]")
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
        
        # Start handshake capture
        output_file = os.path.join(self.handshakes_path, f"{essid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        try:
            console.print(f"[blue]Starting handshake capture...[/blue]")
            console.print("[yellow]Press Ctrl+C to stop[/yellow]")
            
            cmd = ["airodump-ng", "-c", channel, "-w", output_file, "--bssid", bssid, monitor_iface]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Let it run for a reasonable time
            time.sleep(30)
            process.terminate()
            process.wait()
            
            console.print(f"[green]✓ Handshake capture completed![/green]")
            console.print(f"[blue]Handshake saved to: {output_file}*[/blue]")
            console.print("[yellow]Note: Use external tools like aircrack-ng to crack the handshake[/yellow]")
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Capture stopped by user.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during handshake capture: {e}[/red]")
        finally:
            # Restore managed mode
            self._restore_managed_mode(monitor_iface)
    
    def generate_report(self):
        """Generate comprehensive report."""
        console.print("[bold cyan]Report Generation[/bold cyan]")
        console.print("=" * 50)
        
        report_file = os.path.join(self.session_path, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            with open(report_file, 'w') as f:
                f.write("=" * 60 + "\n")
                f.write("NetHawk Security Assessment Report\n")
                f.write("=" * 60 + "\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Session: {self.session_path}\n\n")
                
                # Session Summary
                f.write("SESSION SUMMARY\n")
                f.write("-" * 20 + "\n")
                f.write(f"Session Number: {self.session_number}\n")
                f.write(f"Session Path: {self.session_path}\n")
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Captured Handshakes
                f.write("CAPTURED HANDSHAKES\n")
                f.write("-" * 20 + "\n")
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
                
                # System Information
                f.write("SYSTEM INFORMATION\n")
                f.write("-" * 20 + "\n")
                f.write(f"Python Version: {sys.version}\n")
                f.write(f"Platform: {sys.platform}\n")
                f.write(f"Working Directory: {os.getcwd()}\n")
            
            console.print(f"[green]✓ Report generated: {report_file}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error generating report: {e}[/red]")
    
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
            "scan_duration": 30,
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
                    ["1", "2", "3", "4", "5"]
                )
                
                if choice == "1":
                    self.passive_scan()
                elif choice == "2":
                    self.active_scan()
                elif choice == "3":
                    self.handshake_capture()
                elif choice == "4":
                    self.generate_report()
                elif choice == "5":
                    console.print("[bold green]Thank you for using NetHawk![/bold green]")
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
