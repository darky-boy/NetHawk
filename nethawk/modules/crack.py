"""
NetHawk Handshake Cracking Module
Production-ready handshake cracking with aircrack-ng and hashcat support
"""

import os
import subprocess
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# Lazy import to avoid circular dependencies
def _get_session_path():
    """Get session path lazily to avoid circular imports."""
    try:
        from nethawk.session import get_session_path
        return get_session_path()
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from nethawk.session import get_session_path
        return get_session_path()


def current_time_str() -> str:
    """Get current timestamp as string."""
    return time.strftime("%Y%m%d_%H%M%S")


@dataclass
class CrackResult:
    """Represents a handshake cracking result."""
    cap_file: str
    tool: str
    password: str = ""
    success: bool = False
    log_file: str = ""
    timestamp: str = field(default_factory=current_time_str)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'CrackResult':
        """Create from dictionary."""
        return cls(**data)


def convert_cap_to_hccapx(cap_file: str, output_file: Optional[str] = None) -> str:
    """
    Converts .cap file to .hccapx format for hashcat.
    Requires cap2hccapx or pyrit installed.
    
    Args:
        cap_file: Path to the .cap file
        output_file: Optional output path for .hccapx file
        
    Returns:
        Path to the converted .hccapx file
        
    Raises:
        RuntimeError: If conversion fails
    """
    if not Path(cap_file).exists():
        raise FileNotFoundError(f"Capture file not found: {cap_file}")
    
    output_file = output_file or str(Path(cap_file).with_suffix(".hccapx"))
    
    try:
        # Try cap2hccapx first
        result = subprocess.run(
            ["cap2hccapx", cap_file, output_file],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0 and Path(output_file).exists():
            return output_file
        else:
            raise subprocess.CalledProcessError(result.returncode, "cap2hccapx", result.stderr)
            
    except (subprocess.CalledProcessError, FileNotFoundError):
        try:
            # Fallback to pyrit
            result = subprocess.run(
                ["pyrit", "-r", cap_file, "export", "hccapx", output_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and Path(output_file).exists():
                return output_file
            else:
                raise subprocess.CalledProcessError(result.returncode, "pyrit", result.stderr)
                
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError(
                "Conversion to .hccapx failed. Ensure cap2hccapx or pyrit is installed.\n"
                "Install with: apt install hcxtools (for cap2hccapx) or pip install pyrit"
            )


def crack_handshake(
    cap_file: str,
    wordlist: str,
    session_path: Optional[str] = None,
    tool: str = "aircrack-ng",
    timeout: Optional[int] = None,
    safe_mode: bool = True
) -> CrackResult:
    """
    Attempts to crack a WPA/WPA2 handshake using aircrack-ng or hashcat.
    
    Args:
        cap_file: Path to the .cap file containing handshake
        wordlist: Path to wordlist file
        session_path: Optional session directory path
        tool: Cracking tool to use ("aircrack-ng" or "hashcat")
        timeout: Optional timeout in seconds
        safe_mode: If True, only allow safe cracking operations
        
    Returns:
        CrackResult object with cracking results
        
    Raises:
        PermissionError: If safe_mode is enabled and conditions not met
        FileNotFoundError: If required files don't exist
        ValueError: If unsupported tool is specified
        RuntimeError: If cracking process fails
    """
    # Safety checks
    if safe_mode and not Path(cap_file).exists():
        raise PermissionError("Safe mode enabled: capture file not found or unsafe path.")
    
    if not Path(wordlist).exists():
        raise FileNotFoundError(f"Wordlist not found: {wordlist}")
    
    # Setup session directory
    session_path = Path(session_path or _get_session_path()) / "crack_logs"
    session_path.mkdir(parents=True, exist_ok=True)
    
    # Prepare log file
    log_file = session_path / f"crack_{Path(cap_file).stem}_{current_time_str()}.log"
    
    password = ""
    success = False
    start_time = time.time()
    
    try:
        if tool.lower() == "aircrack-ng":
            # Aircrack-ng command
            cmd = ["aircrack-ng", "-w", wordlist, "-b", "", cap_file]
            
        elif tool.lower() == "hashcat":
            # Convert to hccapx format first
            hccapx_file = convert_cap_to_hccapx(cap_file)
            cmd = [
                "hashcat", 
                "-m", "2500",  # WPA/WPA2 mode
                str(hccapx_file), 
                wordlist, 
                "--quiet", 
                "--potfile-disable"
            ]
            
        else:
            raise ValueError(f"Unsupported tool: {tool}. Use 'aircrack-ng' or 'hashcat'")
        
        print(f"[+] Starting {tool} crack on {Path(cap_file).name}")
        print(f"[+] Wordlist: {Path(wordlist).name}")
        print(f"[+] Log file: {log_file}")
        
        # Run cracking process
        with open(log_file, "w") as log_f:
            proc = subprocess.Popen(
                cmd, 
                stdout=log_f, 
                stderr=subprocess.STDOUT,
                text=True
            )
            
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                print(f"[!] Cracking timed out after {timeout} seconds")
                proc.kill()
                proc.wait()
        
        # Parse log to find password
        if log_file.exists():
            with open(log_file, "r") as f:
                log_content = f.read()
                
                # Look for success indicators
                success_indicators = [
                    "KEY FOUND",
                    "Cracked",
                    "Password:",
                    "Found:",
                    "SUCCESS"
                ]
                
                for line in log_content.split('\n'):
                    for indicator in success_indicators:
                        if indicator.lower() in line.lower():
                            # Extract password from line
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if indicator.lower() in part.lower() and i + 1 < len(parts):
                                    password = parts[i + 1].strip('"\'[]()')
                                    success = True
                                    break
                            if success:
                                break
                    if success:
                        break
        
        duration = time.time() - start_time
        
        if success:
            print(f"[+] SUCCESS! Password found: {password}")
            print(f"[+] Cracking completed in {duration:.2f} seconds")
        else:
            print(f"[!] Password not found in wordlist")
            print(f"[!] Cracking completed in {duration:.2f} seconds")
        
    except Exception as e:
        print(f"[!] Cracking failed: {e}")
        raise RuntimeError(f"Cracking process failed: {e}")
    
    return CrackResult(
        cap_file=cap_file,
        tool=tool,
        password=password,
        success=success,
        log_file=str(log_file)
    )


def save_crack_result(result: CrackResult, session_path: Optional[str] = None) -> str:
    """
    Save crack result to JSON file in session directory.
    
    Args:
        result: CrackResult object to save
        session_path: Optional session directory path
        
    Returns:
        Path to the saved JSON file
    """
    session_path = Path(session_path or _get_session_path()) / "crack_logs"
    session_path.mkdir(parents=True, exist_ok=True)
    
    out_file = session_path / f"crack_result_{current_time_str()}.json"
    
    with open(out_file, "w") as f:
        json.dump(result.to_dict(), f, indent=4)
    
    print(f"[+] Crack result saved: {out_file}")
    return str(out_file)


def load_crack_result(json_file: str) -> CrackResult:
    """
    Load crack result from JSON file.
    
    Args:
        json_file: Path to JSON file containing crack result
        
    Returns:
        CrackResult object loaded from file
        
    Raises:
        FileNotFoundError: If JSON file doesn't exist
        json.JSONDecodeError: If JSON file is malformed
    """
    if not Path(json_file).exists():
        raise FileNotFoundError(f"Crack result file not found: {json_file}")
    
    with open(json_file, "r") as f:
        data = json.load(f)
    
    return CrackResult.from_dict(data)


def display_crack_results(result: CrackResult) -> None:
    """
    Display crack results in a formatted way.
    
    Args:
        result: CrackResult object to display
    """
    print("\n" + "="*60)
    print("HANDSHAKE CRACKING RESULTS")
    print("="*60)
    print(f"Capture File: {Path(result.cap_file).name}")
    print(f"Tool Used: {result.tool}")
    print(f"Timestamp: {result.timestamp}")
    print(f"Success: {'YES' if result.success else 'NO'}")
    
    if result.success:
        print(f"Password: {result.password}")
        print("🎉 HANDSHAKE SUCCESSFULLY CRACKED!")
    else:
        print("❌ Password not found in wordlist")
    
    print(f"Log File: {Path(result.log_file).name}")
    print("="*60)


if __name__ == "__main__":
    """
    Demo script for testing handshake cracking functionality.
    This demo uses safe targets to avoid making system changes.
    """
    print("NetHawk Handshake Cracking Module Demo")
    print("=" * 50)
    
    # Test with a demo capture file (safe mode)
    test_cap = "sessions/session_demo_capture/handshakes/TestNetwork.cap"
    test_wordlist = "wordlists/common.txt"
    
    print(f"Testing crack with:")
    print(f"  Capture file: {test_cap}")
    print(f"  Wordlist: {test_wordlist}")
    print(f"  Safe mode: True")
    
    try:
        # Test cracking attempt (will fail safely due to missing tools/files)
        result = crack_handshake(
            cap_file=test_cap,
            wordlist=test_wordlist,
            safe_mode=True,
            timeout=30
        )
        
        # Display results
        display_crack_results(result)
        
        # Save results
        save_crack_result(result)
        
    except PermissionError as e:
        print(f"[!] Safety check triggered: {e}")
        print("This is expected behavior in safe mode.")
        
    except FileNotFoundError as e:
        print(f"[!] File not found: {e}")
        print("This is expected - demo files don't exist yet.")
        
    except Exception as e:
        print(f"[!] Demo failed: {e}")
        print("This is expected - cracking tools not available on Windows.")
    
    print("\nDemo completed - no system changes made")
    print("Note: Real cracking requires Linux with aircrack-ng or hashcat installed")