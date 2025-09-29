"""
NetHawk CLI Interface
Auto-generated skeleton - main menu and argument parsing with safety controls
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import print as rprint

from nethawk.session import SessionManager
# Lazy imports to avoid circular dependencies
def _get_logger():
    """Get logger instance lazily to avoid circular imports."""
    try:
        from nethawk.util.logger import get_logger
        return get_logger(__name__)
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from nethawk.util.logger import get_logger
        return get_logger(__name__)

def _check_dependencies():
    """Check dependencies lazily to avoid circular imports."""
    try:
        from nethawk.util.toolcheck import check_dependencies
        return check_dependencies()
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from nethawk.util.toolcheck import check_dependencies
        return check_dependencies()

console = Console()
logger = _get_logger()

class NetHawkCLI:
    """Main CLI interface for NetHawk toolkit."""
    
    def __init__(self, lab_only: bool = False, auto_yes: bool = False, session_id: Optional[str] = None):
        self.lab_only = lab_only
        self.auto_yes = auto_yes
        self.session_manager = SessionManager()
        self.current_session = session_id or self.session_manager.create_session()
        
    def display_banner(self) -> None:
        """Display NetHawk banner with legal notice."""
        banner = """
    ███╗   ██╗████████╗██╗  ██╗ █████╗ ██╗  ██╗ █████╗ ██╗  ██╗
    ████╗  ██║╚══██╔══╝██║ ██╔╝██╔══██╗██║ ██╔╝██╔══██╗██║ ██╔╝
    ██╔██╗ ██║   ██║   █████╔╝ ███████║█████╔╝ ███████║█████╔╝ 
    ██║╚██╗██║   ██║   ██╔═██╗ ██╔══██║██╔═██╗ ██╔══██║██╔═██╗ 
    ██║ ╚████║   ██║   ██║  ██╗██║  ██║██║  ██╗██║  ██║██║  ██╗
    ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
        """
        
        legal_notice = """
[bold red]LEGAL NOTICE:[/bold red] NetHawk is for authorized testing and lab environments only.
Unauthorized use on networks you do not own is illegal and unethical.
Always ensure you have explicit written permission before testing.
        """
        
        console.print(Panel(banner, title="[bold blue]NetHawk v1.0.0[/bold blue]", 
                           subtitle="[italic]Linux Reconnaissance Toolkit[/italic]"))
        console.print(Panel(legal_notice, title="[bold red]⚠️  LEGAL WARNING ⚠️[/bold red]"))
        console.print()
    
    def check_consent(self, operation: str) -> bool:
        """Check user consent for potentially dangerous operations."""
        if self.auto_yes:
            return True
            
        if not self.lab_only:
            console.print(f"[red]Operation '{operation}' requires --lab-only flag for safety.[/red]")
            return False
            
        consent = Prompt.ask(
            f"[bold red]CONSENT REQUIRED:[/bold red] Type 'I CONSENT' to proceed with {operation}",
            default=""
        )
        return consent == "I CONSENT"
    
    def display_main_menu(self) -> None:
        """Display the main menu."""
        menu_text = f"""
[bold cyan]Main Menu[/bold cyan]

[bold]1.[/bold] Passive Scan
[bold]2.[/bold] Active Scan  
[bold]3.[/bold] Capture Handshake
[bold]4.[/bold] Crack Handshake
[bold]5.[/bold] Generate Report
[bold]6.[/bold] Exit

[italic]Session: {self.current_session}[/italic]
[italic]Lab Mode: {'Enabled' if self.lab_only else 'Disabled'}[/italic]
        """
        
        console.print(Panel(menu_text, title="[bold green]NetHawk Menu[/bold green]"))
    
    def run(self) -> None:
        """Main CLI loop."""
        try:
            self.display_banner()
            
            # Check dependencies
            if not _check_dependencies():
                console.print("[red]Missing required dependencies. Please install them first.[/red]")
                sys.exit(1)
            
            while True:
                console.clear()
                self.display_banner()
                self.display_main_menu()
                
                choice = Prompt.ask(
                    "\n[bold]Select an option (1-6):[/bold] ",
                    choices=["1", "2", "3", "4", "5", "6"],
                    default="6"
                )
                
                if choice == "1":
                    self._run_passive_scan()
                elif choice == "2":
                    self._run_active_scan()
                elif choice == "3":
                    self._run_capture()
                elif choice == "4":
                    self._run_crack()
                elif choice == "5":
                    self._run_report()
                elif choice == "6":
                    console.print("[bold green]Thank you for using NetHawk![/bold green]")
                    break
                
                input("\nPress Enter to continue...")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        except Exception as e:
            logger.error(f"CLI error: {e}")
            console.print(f"[red]An error occurred: {e}[/red]")
    
    def _run_passive_scan(self) -> None:
        """Run passive scan module."""
        console.print("[bold cyan]Starting Passive Scan...[/bold cyan]")
        try:
            from nethawk.modules.passive import run_passive_scan
            run_passive_scan(self.current_session)
        except ImportError as e:
            console.print(f"[red]Failed to import passive module: {e}[/red]")
            console.print("[yellow]Passive scanning not yet fully implemented[/yellow]")
    
    def _run_active_scan(self) -> None:
        """Run active scan module."""
        console.print("[bold cyan]Starting Active Scan...[/bold cyan]")
        try:
            from nethawk.modules.active import run_active_scan
            # Get target from user input
            target = Prompt.ask("Enter target network (e.g., 192.168.1.0/24)", default="192.168.1.0/24")
            run_active_scan(target, self.current_session)
        except ImportError as e:
            console.print(f"[red]Failed to import active module: {e}[/red]")
            console.print("[yellow]Active scanning not yet fully implemented[/yellow]")
    
    def _run_capture(self) -> None:
        """Run handshake capture module."""
        if not self.check_consent("handshake capture"):
            console.print("[yellow]Operation cancelled.[/yellow]")
            return
        console.print("[bold cyan]Starting Handshake Capture...[/bold cyan]")
        try:
            from nethawk.modules.capture import run_handshake_capture
            # Get target details from user
            target_ssid = Prompt.ask("Enter target SSID")
            target_bssid = Prompt.ask("Enter target BSSID (e.g., 00:11:22:33:44:55)")
            channel = int(Prompt.ask("Enter target channel", default="6"))
            run_handshake_capture(target_ssid, target_bssid, channel, session_path=self.current_session)
        except ImportError as e:
            console.print(f"[red]Failed to import capture module: {e}[/red]")
            console.print("[yellow]Handshake capture not yet fully implemented[/yellow]")
    
    def _run_crack(self) -> None:
        """Run handshake cracking module."""
        if not self.check_consent("handshake cracking"):
            console.print("[yellow]Operation cancelled.[/yellow]")
            return
        console.print("[bold cyan]Starting Handshake Cracking...[/bold cyan]")
        try:
            from nethawk.modules.crack import crack_handshake
            # Get input from user
            cap_file = Prompt.ask("Enter path to .cap file")
            wordlist = Prompt.ask("Enter path to wordlist", default="/usr/share/wordlists/rockyou.txt")
            crack_handshake(cap_file, wordlist, session_path=str(self.current_session))
        except ImportError as e:
            console.print(f"[red]Failed to import crack module: {e}[/red]")
            console.print("[yellow]Handshake cracking not yet fully implemented[/yellow]")
    
    def _run_report(self) -> None:
        """Run report generation module."""
        console.print("[bold cyan]Generating Report...[/bold cyan]")
        try:
            from nethawk.modules.report import generate_report
            generate_report(self.current_session)
        except ImportError as e:
            console.print(f"[red]Failed to import report module: {e}[/red]")
            console.print("[yellow]Report generation not yet fully implemented[/yellow]")

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="NetHawk - Linux reconnaissance toolkit for ethical pentesting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m nethawk                    # Safe mode (passive scans only)
  python -m nethawk --lab-only         # Enable lab features with consent prompts
  python -m nethawk --lab-only --yes   # Enable all features (automated consent)
  python -m nethawk --session test123  # Use specific session ID
        """
    )
    
    parser.add_argument(
        "--lab-only",
        action="store_true",
        help="Enable lab-only features (handshake capture, cracking)"
    )
    
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Automatically consent to all operations (requires --lab-only)"
    )
    
    parser.add_argument(
        "--session",
        type=str,
        help="Use specific session ID instead of auto-generating"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="NetHawk 1.0.0"
    )
    
    return parser.parse_args()

def main() -> None:
    """Main entry point."""
    args = parse_args()
    
    if args.yes and not args.lab_only:
        console.print("[red]Error: --yes flag requires --lab-only flag[/red]")
        sys.exit(1)
    
    cli = NetHawkCLI(
        lab_only=args.lab_only,
        auto_yes=args.yes,
        session_id=args.session
    )
    
    cli.run()
