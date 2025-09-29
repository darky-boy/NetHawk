#!/usr/bin/env python3
"""
NetHawk - Linux Network Security Tool
A comprehensive terminal-based tool for network scanning, handshake capture, and analysis.

Author: DarCy
Version: 1.0.0
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
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich import print as rprint

# Initialize Rich console for colored output
console = Console()

class NetHawk:
    """Main NetHawk application class."""
    
    def __init__(self):
        """Initialize NetHawk with session management."""
        self.config = self._load_config()
        self.session_number = self._get_next_session_number()
        # Use absolute paths for Linux compatibility
        self.session_path = os.path.abspath(f"sessions/session_{self.session_number}")
        self.handshakes_path = os.path.join(self.session_path, "handshakes")
        self.crack_logs_path = os.path.join(self.session_path, "crack_logs")
        self.logs_path = os.path.join(self.session_path, "logs")
        self._create_session_directories()
    
    def _get_next_session_number(self):
        """Get the next available session number."""
        sessions_dir = "sessions"
        if not os.path.exists(sessions_dir):
            return 1
        
        existing_sessions = [d for d in os.listdir(sessions_dir) if d.startswith("session_")]
        if not existing_sessions:
            return 1
        
        # Extract session numbers and find the highest
        session_numbers = []
        for session in existing_sessions:
            try:
                num = int(session.split("_")[1])
                session_numbers.append(num)
            except (ValueError, IndexError):
                continue
        
        return max(session_numbers) + 1 if session_numbers else 1
    
    def _create_session_directories(self):
        """Create session directories if they don't exist."""
        directories = [
            self.session_path,
            self.handshakes_path,
            self.crack_logs_path,
            self.logs_path
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
                console.print(f"[green]Created directory: {directory}[/green]")
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to create directory {directory}: {e}")
    
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
        
        console.print(Panel(logo, title="[bold blue]NetHawk v1.0.0[/bold blue]", 
                           subtitle="[italic]Linux Network Security Tool[/italic]"))
        console.print()
    
    def display_main_menu(self):
        """Display the main menu with options."""
        menu_text = """
[bold cyan]Main Menu[/bold cyan]

[bold]1.[/bold] Passive Scan
[bold]2.[/bold] Active Scan  
[bold]3.[/bold] Deauth + Handshake Capture
[bold]4.[/bold] Cracking Handshakes
[bold]5.[/bold] Reporting
[bold]6.[/bold] Exit

[italic]Session: {session}[/italic]
[italic]Path: {path}[/italic]
        """.format(session=f"session_{self.session_number}", path=self.session_path)
        
        console.print(Panel(menu_text, title="[bold green]NetHawk Menu[/bold green]"))
    
    def validate_input(self, prompt, choices):
        """Validate user input against available choices."""
        while True:
            try:
                choice = Prompt.ask(prompt, choices=choices, default="1")
                return choice
            except KeyboardInterrupt:
                console.print("\n[yellow]Operation cancelled by user.[/yellow]")
                sys.exit(0)
            except Exception as e:
                console.print(f"[red]Invalid input: {e}[/red]")
                console.print("[red]Please enter a valid option.[/red]")
    
    def check_dependencies(self):
        """Check for required Linux tools and dependencies."""
        console.print("[yellow]Checking Linux dependencies...[/yellow]")
        
        required_tools = [
            "airodump-ng",
            "aireplay-ng", 
            "aircrack-ng",
            "hashcat",
            "hcxtools",
            "cap2hccapx",
            "iw",
            "ip"
        ]
        
        missing_tools = []
        for tool in required_tools:
            console.print(f"[blue]Checking {tool}...[/blue]")
            if not self._check_tool_exists(tool):
                missing_tools.append(tool)
        
        if missing_tools:
            console.print(f"[red]Missing tools: {', '.join(missing_tools)}[/red]")
            console.print("[yellow]Please install missing dependencies before continuing.[/yellow]")
            console.print("[blue]Install with: sudo apt install aircrack-ng hashcat hcxtools iw iproute2[/blue]")
            console.print("[blue]For cap2hccapx: sudo apt install hcxtools[/blue]")
            return False
        else:
            console.print("[green]All Linux dependencies found![/green]")
            return True
    
    def _check_tool_exists(self, tool):
        """Check if a Linux tool exists in PATH."""
        return shutil.which(tool) is not None
    
    # ----------------- Interface / Monitor Mode Helpers -----------------
    
    def get_wireless_interfaces(self):
        """Return a list of wireless interfaces using iw or nmcli fallback."""
        interfaces = []
        
        # Try iw first
        try:
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("Interface"):
                        interfaces.append(line.split()[1])
                if interfaces:
                    return interfaces
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Fallback to nmcli if iw fails
        try:
            console.print("[yellow]iw failed, trying nmcli fallback...[/yellow]")
            result = subprocess.run(["nmcli", "device"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "wifi" in line.lower() and "connected" in line.lower():
                        parts = line.split()
                        if len(parts) > 0:
                            interfaces.append(parts[0])
                if interfaces:
                    console.print("[green]Found interfaces using nmcli[/green]")
                    return interfaces
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        if not interfaces:
            console.print("[red]No wireless interfaces found using iw or nmcli[/red]")
            console.print("[yellow]Please ensure wireless drivers are installed[/yellow]")
        
        return interfaces

    def check_monitor_mode_capable(self, iface):
        """Check if the interface supports monitor mode."""
        try:
            result = subprocess.run(["iw", "list"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return False
            return "monitor" in result.stdout.lower()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def set_monitor_mode(self, iface):
        """Enable monitor mode on interface."""
        console.print(f"[yellow]Switching {iface} to monitor mode...[/yellow]")
        try:
            # Bring interface down
            subprocess.run(["ip", "link", "set", iface, "down"], check=True)
            # Set to monitor mode
            subprocess.run(["iw", iface, "set", "monitor", "none"], check=True)
            # Bring interface up
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)
            console.print(f"[green]{iface} is now in monitor mode[/green]")
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Failed to set monitor mode: {e}[/red]")
            raise

    def restore_interface_mode(self, iface):
        """Restore interface to managed mode."""
        console.print(f"[yellow]Restoring {iface} to managed mode...[/yellow]")
        try:
            # Bring interface down
            subprocess.run(["ip", "link", "set", iface, "down"], check=True)
            # Set to managed mode
            subprocess.run(["iw", iface, "set", "type", "managed"], check=True)
            # Bring interface up
            subprocess.run(["ip", "link", "set", iface, "up"], check=True)
            console.print(f"[green]{iface} restored to managed mode[/green]")
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Failed to restore managed mode: {e}[/red]")
            console.print("[yellow]You may need to manually restore the interface[/yellow]")
            raise

    # ----------------- Module Placeholders -----------------
    
    def passive_scan(self):
        """Passive Scan module: discover nearby APs and clients."""
        console.print("[bold cyan]Passive Scan Module[/bold cyan]")
        console.print("=" * 50)

        # Step 0: Check root
        if os.geteuid() != 0:
            console.print("[red]Passive Scan requires root privileges![/red]")
            console.print("[yellow]Please run NetHawk with sudo for wireless operations.[/yellow]")
            return

        # Step 1: Get wireless interfaces
        interfaces = self.get_wireless_interfaces()
        if not interfaces:
            console.print("[red]No wireless interfaces found![/red]")
            return

        console.print("[bold]Available Wireless Interfaces:[/bold]")
        for i, iface in enumerate(interfaces):
            console.print(f"{i+1}. {iface}")

        iface_choice = self.validate_input(
            "Select interface to use for passive scan: ", [str(i+1) for i in range(len(interfaces))]
        )
        iface = interfaces[int(iface_choice) - 1]

        # Step 2: Switch to monitor mode
        if not self.check_monitor_mode_capable(iface):
            console.print(f"[red]{iface} does not support monitor mode.[/red]")
            return
        try:
            self.set_monitor_mode(iface)
        except Exception as e:
            console.print(f"[red]Failed to set monitor mode: {e}[/red]")
            return

        # Step 3: Run airodump-ng to sniff nearby APs
        timestamp = int(time.time())
        capture_prefix = os.path.join(self.logs_path, f"passive_{timestamp}")
        console.print(f"[yellow]Starting passive scan on {iface}... Press Ctrl+C to stop[/yellow]")

        try:
            subprocess.run([
                "airodump-ng",
                "-w", capture_prefix,
                "--write-interval", "1",
                "--output-format", "csv",
                iface
            ])
        except KeyboardInterrupt:
            console.print("[yellow]Passive scan stopped by user.[/yellow]")
        except FileNotFoundError:
            console.print("[red]airodump-ng not found! Please install aircrack-ng.[/red]")
            self.restore_interface_mode(iface)
            return
        except Exception as e:
            console.print(f"[red]Error during passive scan: {e}[/red]")
            self.restore_interface_mode(iface)
            return

        # Step 4: Parse CSV file (latest capture)
        csv_file = f"{capture_prefix}-01.csv"
        if not os.path.exists(csv_file):
            console.print("[red]No CSV capture file generated. Scan failed.[/red]")
            self.restore_interface_mode(iface)
            return

        import csv
        ap_list = []
        client_list = []

        try:
            with open(csv_file, newline='', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                section = None
                for row in reader:
                    if not row:
                        continue
                    if "BSSID" in row[0]:
                        section = "AP"
                        next(reader)  # skip header
                        continue
                    if "Station MAC" in row[0]:
                        section = "CLIENT"
                        next(reader)
                        continue

                    if section == "AP":
                        # Expected CSV fields: BSSID, First time seen, Last time seen, channel, speed, privacy, cipher, auth, power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
                        bssid = row[0]
                        channel = row[3]
                        privacy = row[5]
                        power = row[8]
                        essid = row[13] if len(row) > 13 else ""
                        vendor = self._lookup_vendor(bssid)
                        ap_list.append({
                            "BSSID": bssid,
                            "ESSID": essid,
                            "Channel": channel,
                            "Privacy": privacy,
                            "Power": power,
                            "Vendor": vendor
                        })
                    elif section == "CLIENT":
                        # Expected CSV fields: Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
                        station = row[0]
                        power = row[3]
                        connected_bssid = row[5]
                        client_list.append({
                            "Station": station,
                            "Power": power,
                            "BSSID": connected_bssid,
                            "Vendor": self._lookup_vendor(station)
                        })
        except Exception as e:
            console.print(f"[red]Error parsing CSV: {e}[/red]")

        # Step 5: Save results to JSON
        results_file = os.path.join(self.logs_path, f"passive_scan_{timestamp}.json")
        try:
            with open(results_file, 'w') as f:
                json.dump({"APs": ap_list, "Clients": client_list}, f, indent=4)
            console.print(f"[green]✓ Passive scan results saved: {results_file}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to save JSON: {e}[/red]")

        # Step 6: Display tables
        if ap_list:
            table = Table(title="Detected Access Points")
            table.add_column("BSSID")
            table.add_column("ESSID")
            table.add_column("Channel")
            table.add_column("Privacy")
            table.add_column("Power")
            table.add_column("Vendor")
            for ap in ap_list:
                table.add_row(ap["BSSID"], ap["ESSID"], ap["Channel"], ap["Privacy"], ap["Power"], ap["Vendor"])
            console.print(table)

        if client_list:
            table = Table(title="Detected Clients")
            table.add_column("Station MAC")
            table.add_column("Power")
            table.add_column("Connected BSSID")
            table.add_column("Vendor")
            for c in client_list:
                table.add_row(c["Station"], c["Power"], c["BSSID"], c["Vendor"])
            console.print(table)

        # Step 7: Restore interface
        self.restore_interface_mode(iface)
        console.print("[green]✓ Passive scan complete[/green]")
    
    def active_scan(self):
        """Active Scan module: network discovery, port scanning, and service enumeration."""
        console.print("[bold cyan]Active Scan Module[/bold cyan]")
        console.print("=" * 50)

        # Step 1: Get target network
        target_network = Prompt.ask("Enter target network (e.g., 192.168.1.0/24 or single IP)", 
                                  default="192.168.1.0/24")
        
        try:
            # Validate network input
            if "/" in target_network:
                network = ipaddress.IPv4Network(target_network, strict=False)
                console.print(f"[blue]Scanning network: {network}[/blue]")
            else:
                # Single IP target
                ip = ipaddress.IPv4Address(target_network)
                console.print(f"[blue]Scanning single target: {ip}[/blue]")
                network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
        except Exception as e:
            console.print(f"[red]Invalid network format: {e}[/red]")
            return

        # Step 2: Choose scan type
        scan_type = Prompt.ask(
            "Choose scan type",
            choices=["ping_sweep", "port_scan", "service_scan", "comprehensive"],
            default="comprehensive"
        )

        timestamp = int(time.time())
        results = {
            "target_network": str(network),
            "scan_type": scan_type,
            "timestamp": timestamp,
            "hosts": [],
            "services": []
        }

        # Step 3: Execute scans based on type
        if scan_type in ["ping_sweep", "comprehensive"]:
            console.print("[yellow]Performing ping sweep...[/yellow]")
            hosts = self._ping_sweep(network)
            results["hosts"] = hosts
            
            if hosts:
                console.print(f"[green]✓ Found {len(hosts)} active hosts[/green]")
            else:
                console.print("[yellow]No active hosts found[/yellow]")

        if scan_type in ["port_scan", "comprehensive"]:
            if not results["hosts"]:
                # If no ping sweep, scan the network directly
                console.print("[yellow]Performing port scan on network...[/yellow]")
                for ip in network.hosts():
                    self._port_scan(str(ip), results)
            else:
                # Scan discovered hosts
                console.print("[yellow]Performing port scan on discovered hosts...[/yellow]")
                for host in results["hosts"]:
                    self._port_scan(host["ip"], results)

        if scan_type in ["service_scan", "comprehensive"]:
            console.print("[yellow]Performing service enumeration...[/yellow]")
            self._service_scan(results)

        # Step 4: Display results
        self._display_scan_results(results)

        # Step 5: Save results
        results_file = os.path.join(self.logs_path, f"active_scan_{timestamp}.json")
        try:
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=4)
            console.print(f"[green]✓ Active scan results saved: {results_file}[/green]")
        except Exception as e:
            console.print(f"[red]Failed to save results: {e}[/red]")

        console.print("[green]✓ Active scan completed![/green]")
    
    def deauth_handshake_capture(self):
        """Deauth + Handshake Capture module."""
        console.print("[bold cyan]Deauth + Handshake Capture Module[/bold cyan]")
        console.print("=" * 50)

        # Check if running as root
        if os.geteuid() != 0:
            console.print("[red]This module requires root privileges![/red]")
            console.print("[yellow]Please run NetHawk with sudo for wireless operations.[/yellow]")
            return

        # Step 1: List interfaces
        interfaces = self.get_wireless_interfaces()
        if not interfaces:
            console.print("[red]No wireless interfaces found![/red]")
            return
        
        console.print("[bold]Available Wireless Interfaces:[/bold]")
        for i, iface in enumerate(interfaces):
            console.print(f"{i+1}. {iface}")
        
        # Auto-suggest first capable interface
        suggested_iface = None
        for iface in interfaces:
            if self.check_monitor_mode_capable(iface):
                suggested_iface = iface
                console.print(f"[blue]Suggested: {iface} (supports monitor mode)[/blue]")
                break
        
        iface_choice = self.validate_input(
            "\nSelect interface to use: ", [str(i+1) for i in range(len(interfaces))]
        )
        iface = interfaces[int(iface_choice)-1]

        # Step 2: Check if interface supports monitor mode
        if not self.check_monitor_mode_capable(iface):
            console.print(f"[red]{iface} does not support monitor mode.[/red]")
            return

        # Step 3: Check for conflicting processes
        self._check_airmon_conflicts()

        # Step 4: Consent for deauth
        consent = Prompt.ask(
            "[bold red]WARNING: Deauth attack can disrupt networks! Type 'yes' to continue[/bold red]",
            choices=["yes", "no"], default="no"
        )
        if consent != "yes":
            console.print("[yellow]Operation aborted by user.[/yellow]")
            return

        # Step 5: Switch interface to monitor mode
        try:
            self.set_monitor_mode(iface)
        except Exception as e:
            console.print(f"[red]Failed to set monitor mode: {e}[/red]")
            return

        # Step 5: Ask for target AP BSSID and channel
        target_bssid = Prompt.ask("Enter target AP BSSID (e.g., 00:11:22:33:44:55)")
        if not self._validate_bssid(target_bssid):
            console.print("[red]Invalid BSSID format! Please use format: XX:XX:XX:XX:XX:XX[/red]")
            self.restore_interface_mode(iface)
            return
        
        target_channel = Prompt.ask("Enter target AP channel (e.g., 6)")
        try:
            channel = int(target_channel)
            if channel < 1 or channel > 14:
                console.print("[red]Invalid channel! Please use 1-14 for 2.4GHz[/red]")
                self.restore_interface_mode(iface)
                return
        except ValueError:
            console.print("[red]Invalid channel format! Please enter a number.[/red]")
            self.restore_interface_mode(iface)
            return

        # Step 6: Run airodump-ng to capture handshake
        output_file = os.path.join(self.handshakes_path, f"{target_bssid.replace(':','')}_{int(time.time())}.cap")
        console.print(f"[yellow]Starting handshake capture on {target_bssid}...[/yellow]")
        console.print("[blue]Press Ctrl+C to stop capture[/blue]")
        
        try:
            # Run airodump-ng without timeout for better handshake capture
            console.print("[blue]Running airodump-ng (no timeout - use Ctrl+C to stop)...[/blue]")
            result = subprocess.run([
                "airodump-ng",
                "-c", str(target_channel),
                "--bssid", target_bssid,
                "-w", output_file.replace(".cap", ""),  # airodump-ng adds -01.cap automatically
                iface
            ])  # No timeout - let user control when to stop
            
            if result.returncode == 0:
                console.print(f"[green]✓ Handshake capture finished! Saved to: {output_file}[/green]")
            else:
                console.print("[yellow]Handshake capture completed with warnings[/yellow]")
                
        except KeyboardInterrupt:
            console.print("[yellow]Handshake capture stopped by user.[/yellow]")
        except FileNotFoundError:
            console.print("[red]airodump-ng not found. Please install aircrack-ng package.[/red]")
            return
        except Exception as e:
            console.print(f"[red]Error during handshake capture: {e}[/red]")
            return

        # Step 7: Restore interface to managed mode
        try:
            self.restore_interface_mode(iface)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not restore interface: {e}[/yellow]")
            console.print("[yellow]You may need to manually restore the interface[/yellow]")
    
    def crack_handshakes(self):
        """Crack Handshakes module (aircrack-ng or hashcat)."""
        console.print("[bold cyan]Cracking Handshakes Module[/bold cyan]")
        console.print("=" * 50)

        # Step 1: List .cap files
        cap_files = [f for f in os.listdir(self.handshakes_path) if f.endswith(".cap")]
        if not cap_files:
            console.print(f"[red]No .cap files found in {self.handshakes_path}![/red]")
            console.print("[yellow]Run 'Deauth + Handshake Capture' first to capture handshakes.[/yellow]")
            return

        console.print("[bold]Available .cap files:[/bold]")
        for i, file in enumerate(cap_files):
            console.print(f"{i+1}. {file}")

        # Step 2: Select .cap file(s)
        selected_indices = Prompt.ask(
            "Enter file number(s) to crack (comma separated, e.g., 1,3)",
            default="1"
        )
        try:
            selected_files = [cap_files[int(idx.strip()) - 1] for idx in selected_indices.split(",")]
        except Exception:
            console.print("[red]Invalid selection[/red]")
            return

        # Step 3: Choose cracking tool
        default_tool = self.config.get("default_tool", "aircrack-ng")
        tool = Prompt.ask("Choose tool", choices=["aircrack-ng", "hashcat"], default=default_tool)

        # Step 4: Multi-wordlist support with auto-detection
        wordlist_choice = Prompt.ask(
            "Wordlist options", 
            choices=["single", "multiple", "auto-detect"], 
            default="single"
        )
        
        if wordlist_choice == "auto-detect":
            # Auto-detect available wordlists
            available_wordlists = self._get_available_wordlists()
            if not available_wordlists:
                console.print("[red]No wordlists found in common locations![/red]")
                return
            
            console.print("[bold]Available wordlists:[/bold]")
            for i, wl in enumerate(available_wordlists):
                console.print(f"{i+1}. {os.path.basename(wl)}")
            
            selected_indices = Prompt.ask(
                "Enter wordlist number(s) to use (comma separated, e.g., 1,3)",
                default="1"
            )
            try:
                selected_wordlists = [available_wordlists[int(idx.strip()) - 1] for idx in selected_indices.split(",")]
                wordlists = selected_wordlists
            except Exception:
                console.print("[red]Invalid selection[/red]")
                return
                
        elif wordlist_choice == "single":
            default_wordlist = self.config.get("default_wordlist", "/usr/share/wordlists/rockyou.txt")
            wordlist = Prompt.ask("Enter wordlist path", default=default_wordlist)
            if not os.path.isfile(wordlist):
                console.print(f"[red]Wordlist not found: {wordlist}[/red]")
                return
            wordlists = [wordlist]
        else:
            # Multiple wordlists
            wordlist_input = Prompt.ask("Enter wordlist paths (comma separated)", 
                                     default="/usr/share/wordlists/rockyou.txt,/usr/share/wordlists/fasttrack.txt")
            wordlists = [w.strip() for w in wordlist_input.split(",")]
            # Validate all wordlists
            valid_wordlists = []
            for wl in wordlists:
                if os.path.isfile(wl):
                    valid_wordlists.append(wl)
                else:
                    console.print(f"[yellow]Warning: {wl} not found, skipping[/yellow]")
            if not valid_wordlists:
                console.print("[red]No valid wordlists found![/red]")
                return
            wordlists = valid_wordlists

        # Step 5: Crack each selected .cap file
        for cap_file in selected_files:
            cap_path = os.path.join(self.handshakes_path, cap_file)
            console.print(f"\n[bold]Processing: {cap_file}[/bold]")
            
            # Get BSSID for aircrack-ng if needed
            bssid = ""
            if tool == "aircrack-ng":
                bssid = self._get_bssid_from_cap(cap_path)
                if bssid:
                    console.print(f"[blue]Detected BSSID: {bssid}[/blue]")
                else:
                    console.print("[yellow]Could not detect BSSID, using first available[/yellow]")

            # Try each wordlist
            for wordlist in wordlists:
                output_log = os.path.join(self.crack_logs_path, f"{cap_file}_{os.path.basename(wordlist)}_cracked.txt")
                console.print(f"[yellow]Cracking {cap_file} using {tool} with {os.path.basename(wordlist)}...[/yellow]")

                try:
                    if tool == "aircrack-ng":
                        cmd = ["aircrack-ng", "-w", wordlist]
                        if bssid:
                            cmd.extend(["-b", bssid])
                        cmd.append(cap_path)
                    else:  # hashcat
                        # Check if cap2hccapx exists
                        if not shutil.which("cap2hccapx"):
                            console.print("[red]cap2hccapx not found. Please install hcxtools.[/red]")
                            continue
                        
                        # Convert .cap to .hccapx using cap2hccapx
                        hccapx_path = cap_path.replace(".cap", ".hccapx")
                        console.print(f"[blue]Converting {cap_file} to .hccapx format...[/blue]")
                        try:
                            subprocess.run(["cap2hccapx", cap_path, hccapx_path], check=True)
                            console.print(f"[green]✓ Conversion successful: {hccapx_path}[/green]")
                        except subprocess.CalledProcessError:
                            console.print(f"[red]Failed to convert {cap_file} to .hccapx format[/red]")
                            continue
                        cmd = ["hashcat", "-m", "2500", hccapx_path, wordlist]

                    # Run cracking with live output and progress bar
                    console.print(f"[blue]Running: {' '.join(cmd)}[/blue]")
                    
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TimeElapsedColumn(),
                        console=console
                    ) as progress:
                        task = progress.add_task(f"Cracking with {os.path.basename(wordlist)}...", total=None)
                        
                        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        
                        with open(output_log, "w") as log_file:
                            for line in process.stdout:
                                print(line, end="")
                                log_file.write(line)
                                # Update progress description with current line
                                if "keys tested" in line.lower() or "progress" in line.lower():
                                    progress.update(task, description=f"Cracking... {line.strip()[:50]}")
                        
                        process.wait()
                    
                    # Check for password success using multiple methods
                    password_found = False
                    if process.returncode == 0:
                        password_found = True
                    elif self._check_password_found(output_log):
                        password_found = True
                    
                    if password_found:
                        console.print(f"[green]✓ Password found! Log saved to: {output_log}[/green]")
                        break  # Stop trying other wordlists if password found
                    else:
                        console.print(f"[yellow]No password found with {os.path.basename(wordlist)}[/yellow]")
                        if len(wordlists) > 1:
                            console.print("[blue]Trying next wordlist...[/blue]")

                except FileNotFoundError:
                    console.print(f"[red]{tool} not found. Please install it.[/red]")
                    break
                except subprocess.CalledProcessError as e:
                    console.print(f"[red]Error during cracking: {e}[/red]")
                except Exception as e:
                    console.print(f"[red]Unexpected error: {e}[/red]")
    
    def _get_bssid_from_cap(self, cap_path):
        """Extract BSSID from .cap file using airodump-ng."""
        try:
            # Use airodump-ng to analyze the .cap file
            result = subprocess.run(["airodump-ng", cap_path], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Parse output to find BSSID
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'BSSID' in line and 'ESSID' in line:
                        continue  # Skip header
                    if line.strip() and not line.startswith('Station') and ':' in line:
                        parts = line.split()
                        if len(parts) > 0 and ':' in parts[0] and len(parts[0]) == 17:  # Valid BSSID format
                            return parts[0]
        except Exception:
            pass
        return None
    
    def _validate_bssid(self, bssid):
        """Validate BSSID format (XX:XX:XX:XX:XX:XX)."""
        import re
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, bssid))
    
    def _check_airmon_conflicts(self):
        """Check for conflicting processes that might interfere with monitor mode."""
        try:
            result = subprocess.run(["airmon-ng", "check"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                console.print("[yellow]Conflicting processes detected:[/yellow]")
                console.print(result.stdout)
                kill_choice = Prompt.ask("Kill conflicting processes?", choices=["yes", "no"], default="yes")
                if kill_choice == "yes":
                    subprocess.run(["airmon-ng", "check", "kill"], check=True)
                    console.print("[green]✓ Conflicting processes killed[/green]")
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            pass  # airmon-ng not available or no conflicts
    
    def _check_password_found(self, output_log):
        """Check if password was found in the output log."""
        try:
            with open(output_log, 'r') as f:
                content = f.read().lower()
                # Look for common success indicators
                success_indicators = [
                    'key found',
                    'password found',
                    'key cracked',
                    'handshake cracked',
                    'fms attack',
                    'korek attack',
                    'passphrase',  # hashcat output
                    'wpa key',     # aircrack-ng output
                    'network key', # generic success
                    'found key'    # generic success
                ]
                return any(indicator in content for indicator in success_indicators)
        except Exception:
            return False
    
    def _get_available_wordlists(self):
        """Auto-detect available wordlists in common locations."""
        common_paths = [
            "/usr/share/wordlists",
            "/usr/share/wordlists/rockyou",
            "/usr/share/wordlists/fasttrack",
            "/usr/share/wordlists/metasploit",
            "/usr/share/wordlists/wifite"
        ]
        
        wordlists = []
        for path in common_paths:
            if os.path.exists(path):
                for file in os.listdir(path):
                    if file.endswith('.txt') and os.path.isfile(os.path.join(path, file)):
                        wordlists.append(os.path.join(path, file))
        return wordlists
    
    def _lookup_vendor(self, mac):
        """Lookup vendor from MAC address (OUI) using macvendors API fallback to 'Unknown'."""
        try:
            import requests
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
            if response.status_code == 200:
                return response.text.strip()
        except Exception:
            pass
        return "Unknown"
    
    def _ping_sweep(self, network):
        """Perform ping sweep to discover active hosts."""
        hosts = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Ping sweeping...", total=len(list(network.hosts())))
            
            for ip in network.hosts():
                if self._ping_host(str(ip)):
                    hosts.append({
                        "ip": str(ip),
                        "status": "up",
                        "response_time": "N/A"
                    })
                progress.advance(task)
        
        return hosts
    
    def _ping_host(self, ip):
        """Ping a single host to check if it's alive."""
        try:
            # Use system ping command for better reliability
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                timeout=3
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _port_scan(self, ip, results):
        """Scan common ports on a target host."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900, 8080]
        open_ports = []
        
        for port in common_ports:
            if self._scan_port(ip, port):
                open_ports.append(port)
        
        if open_ports:
            # Add to results
            for host in results["hosts"]:
                if host["ip"] == ip:
                    host["open_ports"] = open_ports
                    break
            else:
                # Host not in results, add it
                results["hosts"].append({
                    "ip": ip,
                    "status": "up",
                    "open_ports": open_ports
                })
    
    def _scan_port(self, ip, port):
        """Scan a single port on a host."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _service_scan(self, results):
        """Perform service enumeration on discovered hosts."""
        for host in results["hosts"]:
            if "open_ports" in host:
                for port in host["open_ports"]:
                    service_info = self._get_service_info(host["ip"], port)
                    if service_info:
                        results["services"].append({
                            "host": host["ip"],
                            "port": port,
                            "service": service_info["service"],
                            "version": service_info["version"],
                            "banner": service_info["banner"]
                        })
    
    def _get_service_info(self, ip, port):
        """Get service information for a specific port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Try to get banner
            banner = ""
            try:
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                pass
            
            sock.close()
            
            # Map common ports to services
            service_map = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
                443: "HTTPS", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
                3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"
            }
            
            service = service_map.get(port, "Unknown")
            version = "Unknown"
            
            # Try to extract version from banner
            if banner:
                if "SSH" in banner:
                    version = banner.split()[1] if len(banner.split()) > 1 else "Unknown"
                elif "HTTP" in banner:
                    version = banner.split()[1] if len(banner.split()) > 1 else "Unknown"
            
            return {
                "service": service,
                "version": version,
                "banner": banner
            }
        except Exception:
            return None
    
    def _display_scan_results(self, results):
        """Display scan results in rich tables."""
        if results["hosts"]:
            # Hosts table
            table = Table(title="Discovered Hosts")
            table.add_column("IP Address")
            table.add_column("Status")
            table.add_column("Open Ports")
            
            for host in results["hosts"]:
                ports = ", ".join(map(str, host.get("open_ports", [])))
                table.add_row(host["ip"], host["status"], ports)
            
            console.print(table)
        
        if results["services"]:
            # Services table
            table = Table(title="Discovered Services")
            table.add_column("Host")
            table.add_column("Port")
            table.add_column("Service")
            table.add_column("Version")
            table.add_column("Banner")
            
            for service in results["services"]:
                table.add_row(
                    service["host"],
                    str(service["port"]),
                    service["service"],
                    service["version"],
                    service["banner"][:50] + "..." if len(service["banner"]) > 50 else service["banner"]
                )
            
            console.print(table)
    
    def _load_config(self):
        """Load configuration from config.json or create default."""
        config_file = "config.json"
        default_config = {
            "default_wordlist": "/usr/share/wordlists/rockyou.txt",
            "default_tool": "aircrack-ng",
            "auto_suggest_interface": True,
            "session_retention_days": 90,
            "enable_progress_bars": True,
            "log_level": "INFO"
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                # Merge with defaults for any missing keys
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
            except Exception as e:
                console.print(f"[yellow]Warning: Could not load config: {e}[/yellow]")
                return default_config
        else:
            # Create default config file
            try:
                with open(config_file, 'w') as f:
                    json.dump(default_config, f, indent=4)
                console.print(f"[green]Created default config: {config_file}[/green]")
            except Exception as e:
                console.print(f"[yellow]Warning: Could not create config file: {e}[/yellow]")
            return default_config
    
    def _save_config(self):
        """Save current configuration to config.json."""
        try:
            with open("config.json", 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not save config: {e}[/yellow]")
    
    def generate_report(self):
        """Comprehensive reporting module."""
        console.print("[bold cyan]Reporting Module[/bold cyan]")
        console.print("=" * 50)
        
        # Generate timestamped report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.session_path, f"NetHawk_Report_{timestamp}.txt")
        
        console.print("[yellow]Generating comprehensive report...[/yellow]")
        
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
                
                # Passive Scan Results
                f.write("PASSIVE SCAN RESULTS\n")
                f.write("-" * 20 + "\n")
                passive_scan_files = [f for f in os.listdir(self.logs_path) if f.startswith('passive_scan_') and f.endswith('.json')]
                if passive_scan_files:
                    for scan_file in passive_scan_files:
                        scan_path = os.path.join(self.logs_path, scan_file)
                        try:
                            with open(scan_path, 'r') as scan_f:
                                scan_data = json.load(scan_f)
                                f.write(f"Scan: {scan_file}\n")
                                f.write(f"  Access Points: {len(scan_data.get('APs', []))}\n")
                                f.write(f"  Clients: {len(scan_data.get('Clients', []))}\n")
                                
                                # Show top APs by power
                                aps = scan_data.get('APs', [])
                                if aps:
                                    f.write("  Top APs by signal strength:\n")
                                    sorted_aps = sorted(aps, key=lambda x: int(x.get('Power', -100)), reverse=True)[:5]
                                    for ap in sorted_aps:
                                        f.write(f"    {ap.get('BSSID', 'N/A')} - {ap.get('ESSID', 'Hidden')} - {ap.get('Power', 'N/A')} dBm\n")
                                f.write("\n")
                        except Exception:
                            f.write(f"  Error reading {scan_file}\n")
                else:
                    f.write("No passive scan results found.\n")
                f.write("\n")
                
                # Active Scan Results
                f.write("ACTIVE SCAN RESULTS\n")
                f.write("-" * 20 + "\n")
                active_scan_files = [f for f in os.listdir(self.logs_path) if f.startswith('active_scan_') and f.endswith('.json')]
                if active_scan_files:
                    for scan_file in active_scan_files:
                        scan_path = os.path.join(self.logs_path, scan_file)
                        try:
                            with open(scan_path, 'r') as scan_f:
                                scan_data = json.load(scan_f)
                                f.write(f"Scan: {scan_file}\n")
                                f.write(f"  Target Network: {scan_data.get('target_network', 'N/A')}\n")
                                f.write(f"  Scan Type: {scan_data.get('scan_type', 'N/A')}\n")
                                f.write(f"  Hosts Found: {len(scan_data.get('hosts', []))}\n")
                                f.write(f"  Services Found: {len(scan_data.get('services', []))}\n")
                                
                                # Show discovered hosts
                                hosts = scan_data.get('hosts', [])
                                if hosts:
                                    f.write("  Discovered Hosts:\n")
                                    for host in hosts:
                                        ports = ", ".join(map(str, host.get('open_ports', [])))
                                        f.write(f"    {host.get('ip', 'N/A')} - Ports: {ports}\n")
                                
                                # Show discovered services
                                services = scan_data.get('services', [])
                                if services:
                                    f.write("  Discovered Services:\n")
                                    for service in services[:10]:  # Limit to first 10
                                        f.write(f"    {service.get('host', 'N/A')}:{service.get('port', 'N/A')} - {service.get('service', 'N/A')}\n")
                                f.write("\n")
                        except Exception:
                            f.write(f"  Error reading {scan_file}\n")
                else:
                    f.write("No active scan results found.\n")
                f.write("\n")
                
                # Captured Handshakes
                f.write("CAPTURED HANDSHAKES\n")
                f.write("-" * 20 + "\n")
                cap_files = [f for f in os.listdir(self.handshakes_path) if f.endswith('.cap')]
                if cap_files:
                    for cap_file in cap_files:
                        cap_path = os.path.join(self.handshakes_path, cap_file)
                        file_size = os.path.getsize(cap_path)
                        f.write(f"File: {cap_file} ({file_size} bytes)\n")
                        
                        # Try to extract BSSID from cap file
                        bssid = self._get_bssid_from_cap(cap_path)
                        if bssid:
                            f.write(f"  BSSID: {bssid}\n")
                        
                        # Check if this handshake was cracked
                        crack_logs = [f for f in os.listdir(self.crack_logs_path) if cap_file.replace('.cap', '') in f]
                        if crack_logs:
                            f.write(f"  Cracking attempts: {len(crack_logs)}\n")
                            for log in crack_logs:
                                log_path = os.path.join(self.crack_logs_path, log)
                                if self._check_password_found(log_path):
                                    f.write(f"  Status: PASSWORD FOUND in {log}\n")
                                else:
                                    f.write(f"  Status: No password found in {log}\n")
                        else:
                            f.write("  Status: No cracking attempts\n")
                        f.write("\n")
                else:
                    f.write("No handshake files captured.\n")
                f.write("\n")
                
                # Cracking Results
                f.write("CRACKING RESULTS\n")
                f.write("-" * 20 + "\n")
                crack_logs = [f for f in os.listdir(self.crack_logs_path) if f.endswith('.txt')]
                if crack_logs:
                    for log_file in crack_logs:
                        log_path = os.path.join(self.crack_logs_path, log_file)
                        f.write(f"Log: {log_file}\n")
                        # Check if password was found
                        if self._check_password_found(log_path):
                            f.write("Status: PASSWORD FOUND!\n")
                        else:
                            f.write("Status: No password found\n")
                        f.write("\n")
                else:
                    f.write("No cracking attempts recorded.\n")
                f.write("\n")
                
                # System Information
                f.write("SYSTEM INFORMATION\n")
                f.write("-" * 20 + "\n")
                try:
                    import platform
                    f.write(f"OS: {platform.system()} {platform.release()}\n")
                    f.write(f"Python: {platform.python_version()}\n")
                    f.write(f"Architecture: {platform.machine()}\n")
                except Exception:
                    f.write("System information unavailable.\n")
                f.write("\n")
                
                # Recommendations
                f.write("RECOMMENDATIONS\n")
                f.write("-" * 20 + "\n")
                f.write("1. Review captured handshakes for security assessment\n")
                f.write("2. Analyze cracking results for password strength\n")
                f.write("3. Document findings for security report\n")
                f.write("4. Consider additional security measures\n")
                f.write("\n")
                
                f.write("=" * 60 + "\n")
                f.write("End of Report\n")
                f.write("=" * 60 + "\n")
            
            console.print(f"[green]✓ Report generated: {report_file}[/green]")
            
            # Auto-prune old sessions (>90 days)
            self._prune_old_sessions()
            
        except Exception as e:
            console.print(f"[red]Error generating report: {e}[/red]")
    
    def _prune_old_sessions(self):
        """Remove sessions older than 90 days."""
        console.print("[yellow]Checking for old sessions to prune...[/yellow]")
        
        try:
            sessions_dir = "sessions"
            if not os.path.exists(sessions_dir):
                return
            
            current_time = time.time()
            retention_days = self.config.get("session_retention_days", 90)
            cutoff_time = current_time - (retention_days * 24 * 60 * 60)
            
            for session_dir in os.listdir(sessions_dir):
                if session_dir.startswith("session_"):
                    session_path = os.path.join(sessions_dir, session_dir)
                    if os.path.isdir(session_path):
                        session_time = os.path.getmtime(session_path)
                        if session_time < cutoff_time:
                            console.print(f"[blue]Removing old session: {session_dir}[/blue]")
                            import shutil
                            shutil.rmtree(session_path)
                            console.print(f"[green]✓ Removed: {session_dir}[/green]")
            
            console.print("[green]✓ Session pruning completed[/green]")
            
        except Exception as e:
            console.print(f"[yellow]Warning: Could not prune old sessions: {e}[/yellow]")
    
    # ----------------- Main Loop -----------------
    
    def run(self):
        """Main application loop."""
        try:
            self.display_logo()
            if not self.check_dependencies():
                console.print("[red]Dependency check failed. Please install required tools.[/red]")
                return
            
            while True:
                console.clear()
                self.display_logo()
                self.display_main_menu()
                
                choice = self.validate_input(
                    "\n[bold]Select an option (1-6):[/bold] ",
                    ["1","2","3","4","5","6"]
                )
                
                if choice == "1":
                    self.passive_scan()
                elif choice == "2":
                    self.active_scan()
                elif choice == "3":
                    self.deauth_handshake_capture()
                elif choice == "4":
                    self.crack_handshakes()
                elif choice == "5":
                    self.generate_report()
                elif choice == "6":
                    console.print("[bold green]Thank you for using NetHawk![/bold green]")
                    break
                
                input("\nPress Enter to continue...")
        
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        except Exception as e:
            console.print(f"[red]An error occurred: {e}[/red]")
            console.print("[red]Please check your system and try again.[/red]")

def main():
    """Main entry point for NetHawk."""
    # Check if running on Linux
    if sys.platform != "linux":
        console.print("[red]NetHawk is designed for Linux systems only.[/red]")
        console.print("[yellow]This tool requires Linux-specific wireless tools and kernel modules.[/yellow]")
        console.print(f"[blue]Current platform: {sys.platform}[/blue]")
        console.print("[yellow]Please run on a Linux system for full functionality.[/yellow]")
        sys.exit(1)
    
    # Check for root privileges
    is_root = os.geteuid() == 0
    
    if not is_root:
        console.print("[yellow]NetHawk is running without root privileges.[/yellow]")
        console.print("[blue]Some modules (Deauth + Handshake Capture, Active Scan) require root.[/blue]")
        console.print("[blue]Reporting and Cracking modules can run without root.[/blue]")
        console.print("[yellow]For full functionality, run with: sudo python3 NetHawk.py[/yellow]")
        
        # Ask user if they want to continue
        continue_choice = Prompt.ask("Continue with limited functionality?", choices=["yes", "no"], default="yes")
        if continue_choice != "yes":
            sys.exit(0)
    
    # Initialize and run NetHawk
    app = NetHawk()
    app.run()

if __name__ == "__main__":
    main()

