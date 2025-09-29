#!/usr/bin/env python3
"""
NetHawk - Simple Linux Network Security Tool
Simplified version: Capture and Store only
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
    """Simplified NetHawk application - Capture and Store only."""
    
    def __init__(self):
        """Initialize NetHawk with session management."""
        self.config = self._load_config()
        self.session_number = self._get_next_session_number()
        # Use absolute paths for Linux compatibility
        self.session_path = os.path.abspath(f"sessions/session_{self.session_number}")
        self.handshakes_path = os.path.join(self.session_path, "handshakes")
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
                           subtitle="[italic]Simple Linux Network Security Tool[/italic]"))
        console.print()
    
    def display_main_menu(self):
        """Display the main menu with options."""
        menu_text = """
[bold cyan]Main Menu[/bold cyan]

[bold]1.[/bold] Passive Scan
[bold]2.[/bold] Active Scan  
[bold]3.[/bold] Deauth + Handshake Capture
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
    
    def check_dependencies(self):
        """Check for required Linux tools and dependencies."""
        console.print("[yellow]Checking Linux dependencies...[/yellow]")
        
        required_tools = [
            "airodump-ng",
            "aireplay-ng", 
            "aircrack-ng",
            "iw",
            "ip"
        ]
        
        missing_tools = []
        for tool in required_tools:
            console.print(f"[blue]Checking {tool}...[/blue]")
            if not self._check_tool_exists(tool):
                missing_tools.append(tool)
        
        if missing_tools:
            console.print(f"[yellow]Missing tools: {', '.join(missing_tools)}[/yellow]")
            console.print("[blue]Some features may not work without these tools.[/blue]")
            console.print("[blue]Install with: sudo apt install aircrack-ng iw iproute2[/blue]")
            console.print("[green]Continuing anyway...[/green]")
            return True  # Continue anyway instead of blocking
        else:
            console.print("[green]All Linux dependencies found![/green]")
            return True
    
    def _check_tool_exists(self, tool):
        """Check if a Linux tool exists in PATH."""
        return shutil.which(tool) is not None
    
    def passive_scan(self):
        """Passive wireless scanning module."""
        console.print("[bold cyan]Passive Wireless Scan[/bold cyan]")
        console.print("=" * 50)
        
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
        
        # Start passive scan
        console.print(f"[blue]Starting passive scan on {iface}...[/blue]")
        console.print("[yellow]Press Ctrl+C to stop scanning[/yellow]")
        
        try:
            # Use airodump-ng for passive scanning
            output_file = os.path.join(self.logs_path, f"passive_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            cmd = ["airodump-ng", "-w", output_file, iface]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Monitor for a few seconds to capture data
            time.sleep(10)
            process.terminate()
            process.wait()
            
            console.print(f"[green]✓ Passive scan completed![/green]")
            console.print(f"[blue]Results saved to: {output_file}*[/blue]")
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan stopped by user.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during passive scan: {e}[/red]")
    
    def active_scan(self):
        """Active network scanning module."""
        console.print("[bold cyan]Active Network Scan[/bold cyan]")
        console.print("=" * 50)
        
        # Get target network
        target = Prompt.ask("Enter target network (e.g., 192.168.1.0/24)")
        
        console.print(f"[blue]Scanning network: {target}[/blue]")
        
        try:
            # Use nmap for active scanning
            cmd = ["nmap", "-sn", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                console.print("[green]✓ Active scan completed![/green]")
                console.print(f"[blue]Results:[/blue]")
                console.print(result.stdout)
            else:
                console.print(f"[red]Scan failed: {result.stderr}[/red]")
                
        except subprocess.TimeoutExpired:
            console.print("[yellow]Scan timed out[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during active scan: {e}[/red]")
    
    def deauth_handshake_capture(self):
        """Deauth attack and handshake capture module."""
        console.print("[bold cyan]Deauth + Handshake Capture[/bold cyan]")
        console.print("=" * 50)
        
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
        
        # Get target network info
        bssid = Prompt.ask("Enter target BSSID (MAC address)")
        essid = Prompt.ask("Enter target ESSID (network name)")
        channel = Prompt.ask("Enter target channel", default="6")
        
        console.print(f"[blue]Target: {essid} ({bssid}) on channel {channel}[/blue]")
        
        # Start handshake capture
        output_file = os.path.join(self.handshakes_path, f"{essid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        try:
            # Start airodump-ng to capture handshakes
            cmd = ["airodump-ng", "-c", channel, "-w", output_file, "--bssid", bssid, iface]
            console.print(f"[blue]Starting handshake capture...[/blue]")
            console.print("[yellow]Press Ctrl+C to stop[/yellow]")
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Let it run for a while
            time.sleep(30)
            process.terminate()
            process.wait()
            
            console.print(f"[green]✓ Handshake capture completed![/green]")
            console.print(f"[blue]Handshake saved to: {output_file}*[/blue]")
            console.print("[yellow]Note: Use external tools like aircrack-ng or hashcat to crack the handshake[/yellow]")
            
        except KeyboardInterrupt:
            console.print("\n[yellow]Capture stopped by user.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error during handshake capture: {e}[/red]")
    
    def generate_report(self):
        """Generate a simple report."""
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
    
    def _get_wireless_interfaces(self):
        """Get available wireless interfaces."""
        interfaces = []
        try:
            # Use iw to list wireless interfaces
            result = subprocess.run(["iw", "dev"], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Interface' in line:
                        iface = line.split()[-1]
                        interfaces.append(iface)
        except Exception:
            # Fallback to common interface names
            common_interfaces = ['wlan0', 'wlan1', 'wlp2s0', 'wlp3s0']
            for iface in common_interfaces:
                if os.path.exists(f'/sys/class/net/{iface}'):
                    interfaces.append(iface)
        
        return interfaces
    
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
            # Check dependencies (non-blocking)
            self.check_dependencies()
            
            while True:
                self.display_logo()
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
                    self.deauth_handshake_capture()
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
