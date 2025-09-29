#!/usr/bin/env python3
"""
NetHawk Professional CLI Interface
Designed to work like nmap, metasploit, and other professional tools
"""

import argparse
import sys
import os
from pathlib import Path
from typing import Optional, List
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich import print as rprint

# Import NetHawk modules
from nethawk.session import SessionManager
from nethawk.util.logger import get_logger
from nethawk.util.toolcheck import check_dependencies
from nethawk.modules import passive, active, capture, crack, report

console = Console()

class NetHawkProfessional:
    """Professional NetHawk CLI interface."""
    
    def __init__(self):
        self.session_manager = SessionManager()
        self.current_session = None
        self.logger = get_logger(__name__)
        
    def display_banner(self):
        """Display professional NetHawk banner."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  ███╗   ██╗███████╗████████╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
║  ████╗  ██║██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║    ██║██║ ██╔╝
║  ██╔██╗ ██║█████╗     ██║   ███████║███████║██║ █╗ ██║█████╔╝ 
║  ██║╚██╗██║██╔══╝     ██║   ██╔══██║██╔══██║██║███╗██║██╔═██╗ 
║  ██║ ╚████║███████╗   ██║   ██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
║  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
║                                                              ║
║              Professional Linux Reconnaissance Toolkit        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner, style="bold blue"))
        console.print("[bold green]🦅 NetHawk v2.0 - Professional Edition[/bold green]")
        console.print("[yellow]Use 'nethawk --help' for usage information[/yellow]\n")
    
    def check_environment(self) -> bool:
        """Check if environment is properly set up."""
        console.print("[blue]🔍 Checking environment...[/blue]")
        
        # Check dependencies
        if not check_dependencies():
            console.print("[red]❌ Missing required dependencies[/red]")
            console.print("[yellow]Run: ./install.sh to install dependencies[/yellow]")
            return False
        
        # Check root privileges
        if os.geteuid() != 0:
            console.print("[yellow]⚠️  Running without root privileges[/yellow]")
            console.print("[blue]Some features may be limited[/blue]")
        
        console.print("[green]✅ Environment check passed[/green]")
        return True
    
    def create_session(self, session_name: Optional[str] = None) -> str:
        """Create a new session."""
        if session_name:
            session_path = self.session_manager.create_session(session_name)
        else:
            session_path = self.session_manager.create_session()
        
        self.current_session = session_path
        console.print(f"[green]✅ Session created: {session_path.name}[/green]")
        return str(session_path)
    
    def list_sessions(self):
        """List available sessions."""
        sessions = self.session_manager.list_sessions()
        
        if not sessions:
            console.print("[yellow]No sessions found[/yellow]")
            return
        
        table = Table(title="Available Sessions")
        table.add_column("Session ID", style="cyan")
        table.add_column("Created", style="green")
        table.add_column("Status", style="yellow")
        
        for session in sessions:
            table.add_row(
                session.name,
                session.stat().st_mtime.strftime("%Y-%m-%d %H:%M:%S"),
                "Active" if session == self.current_session else "Inactive"
            )
        
        console.print(table)
    
    def run_passive_scan(self, interface: str = "wlan0", duration: int = 60):
        """Run passive wireless scan."""
        console.print(f"[blue]🔍 Starting passive scan on {interface}...[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            
            try:
                passive.run_passive_scan(self.current_session, interface, duration)
                progress.update(task, description="[green]Scan completed[/green]")
            except Exception as e:
                console.print(f"[red]❌ Scan failed: {e}[/red]")
    
    def run_active_scan(self, target: str, interface: str = "eth0"):
        """Run active network scan."""
        console.print(f"[blue]🎯 Starting active scan of {target}...[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            
            try:
                active.run_active_scan(target, self.current_session, interface)
                progress.update(task, description="[green]Scan completed[/green]")
            except Exception as e:
                console.print(f"[red]❌ Scan failed: {e}[/red]")
    
    def capture_handshake(self, ssid: str, bssid: str, interface: str = "wlan0"):
        """Capture WPA handshake."""
        console.print(f"[blue]📡 Capturing handshake for {ssid}...[/blue]")
        
        if not Confirm.ask("This will perform deauthentication attacks. Continue?"):
            console.print("[yellow]Operation cancelled[/yellow]")
            return
        
        try:
            capture.run_handshake_capture(ssid, bssid, self.current_session, interface)
            console.print("[green]✅ Handshake capture completed[/green]")
        except Exception as e:
            console.print(f"[red]❌ Capture failed: {e}[/red]")
    
    def crack_handshake(self, cap_file: str, wordlist: str = "/usr/share/wordlists/rockyou.txt"):
        """Crack captured handshake."""
        console.print(f"[blue]🔓 Cracking handshake from {cap_file}...[/blue]")
        
        try:
            result = crack.crack_handshake(cap_file, wordlist, self.current_session)
            if result:
                console.print(f"[green]✅ Password found: {result}[/green]")
            else:
                console.print("[yellow]❌ Password not found in wordlist[/yellow]")
        except Exception as e:
            console.print(f"[red]❌ Cracking failed: {e}[/red]")
    
    def generate_report(self, output_format: str = "html"):
        """Generate professional report."""
        console.print(f"[blue]📊 Generating {output_format.upper()} report...[/blue]")
        
        try:
            report.generate_report(self.current_session, output_format)
            console.print("[green]✅ Report generated successfully[/green]")
        except Exception as e:
            console.print(f"[red]❌ Report generation failed: {e}[/red]")
    
    def interactive_mode(self):
        """Interactive mode like metasploit."""
        self.display_banner()
        
        if not self.check_environment():
            return
        
        # Create default session
        self.create_session()
        
        while True:
            try:
                console.print("\n[bold cyan]NetHawk[/bold cyan] > ", end="")
                command = input().strip().split()
                
                if not command:
                    continue
                
                cmd = command[0].lower()
                args = command[1:]
                
                if cmd in ['exit', 'quit', 'q']:
                    console.print("[yellow]Goodbye![/yellow]")
                    break
                elif cmd == 'help':
                    self.show_help()
                elif cmd == 'sessions':
                    self.list_sessions()
                elif cmd == 'passive':
                    interface = args[0] if args else "wlan0"
                    self.run_passive_scan(interface)
                elif cmd == 'active':
                    if not args:
                        target = Prompt.ask("Enter target network")
                    else:
                        target = args[0]
                    self.run_active_scan(target)
                elif cmd == 'capture':
                    if len(args) < 2:
                        console.print("[red]Usage: capture <SSID> <BSSID> [interface][/red]")
                        continue
                    interface = args[2] if len(args) > 2 else "wlan0"
                    self.capture_handshake(args[0], args[1], interface)
                elif cmd == 'crack':
                    if not args:
                        console.print("[red]Usage: crack <cap_file> [wordlist][/red]")
                        continue
                    wordlist = args[1] if len(args) > 1 else "/usr/share/wordlists/rockyou.txt"
                    self.crack_handshake(args[0], wordlist)
                elif cmd == 'report':
                    format_type = args[0] if args else "html"
                    self.generate_report(format_type)
                else:
                    console.print(f"[red]Unknown command: {cmd}[/red]")
                    console.print("[yellow]Type 'help' for available commands[/yellow]")
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]Use 'exit' to quit[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
    
    def show_help(self):
        """Show help information."""
        help_text = """
[bold cyan]NetHawk Professional Commands:[/bold cyan]

[bold green]Session Management:[/bold green]
  sessions                    List all sessions
  help                       Show this help

[bold green]Reconnaissance:[/bold green]
  passive [interface]         Passive wireless scan
  active <target>            Active network scan

[bold green]Handshake Operations:[/bold green]
  capture <SSID> <BSSID>     Capture WPA handshake
  crack <cap_file>           Crack captured handshake

[bold green]Reporting:[/bold green]
  report [format]            Generate report (html/pdf)

[bold green]System:[/bold green]
  exit/quit/q                Exit NetHawk

[bold yellow]Examples:[/bold yellow]
  passive wlan0              # Scan on wlan0
  active 192.168.1.0/24      # Scan network
  capture MyWiFi aa:bb:cc:dd:ee:ff  # Capture handshake
  crack handshake.cap        # Crack handshake
  report html                # Generate HTML report
        """
        console.print(Panel(help_text, title="NetHawk Help", border_style="blue"))

def main():
    """Main entry point for professional CLI."""
    parser = argparse.ArgumentParser(
        description="NetHawk - Professional Linux Reconnaissance Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nethawk                           # Interactive mode
  nethawk --passive wlan0          # Passive scan
  nethawk --active 192.168.1.0/24  # Active scan
  nethawk --capture MyWiFi aa:bb:cc:dd:ee:ff  # Capture handshake
  nethawk --crack handshake.cap    # Crack handshake
  nethawk --report                 # Generate report
        """
    )
    
    parser.add_argument('--version', action='version', version='NetHawk 2.0')
    parser.add_argument('--session', help='Use specific session')
    parser.add_argument('--interface', default='wlan0', help='Network interface')
    parser.add_argument('--output', help='Output file')
    
    # Command options
    parser.add_argument('--passive', action='store_true', help='Run passive scan')
    parser.add_argument('--active', help='Run active scan on target')
    parser.add_argument('--capture', nargs=2, metavar=('SSID', 'BSSID'), help='Capture handshake')
    parser.add_argument('--crack', help='Crack handshake file')
    parser.add_argument('--report', action='store_true', help='Generate report')
    
    args = parser.parse_args()
    
    # Create NetHawk instance
    nethawk = NetHawkProfessional()
    
    # If no specific command, run interactive mode
    if not any([args.passive, args.active, args.capture, args.crack, args.report]):
        nethawk.interactive_mode()
        return
    
    # Check environment
    if not nethawk.check_environment():
        sys.exit(1)
    
    # Create session
    nethawk.create_session(args.session)
    
    # Execute commands
    try:
        if args.passive:
            nethawk.run_passive_scan(args.interface)
        elif args.active:
            nethawk.run_active_scan(args.active, args.interface)
        elif args.capture:
            nethawk.capture_handshake(args.capture[0], args.capture[1], args.interface)
        elif args.crack:
            nethawk.crack_handshake(args.crack)
        elif args.report:
            nethawk.generate_report()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
