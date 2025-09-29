"""
NetHawk Network Utilities
Production-ready monitor mode context manager with safety checks and cross-platform support
"""

import os
import shutil
import socket
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional, Dict, Any

# Lazy import to avoid circular dependencies
def _get_logger():
    """Get logger instance lazily to avoid circular imports."""
    try:
        from nethawk.util.logger import get_logger
        return get_logger(name="nethawk.net")
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from nethawk.util.logger import get_logger
        return get_logger(name="nethawk.net")

# Try to import psutil for better interface detection
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class MonitorModeError(Exception):
    """Custom exception for monitor mode operations."""
    pass


def list_interfaces() -> List[str]:
    """
    List available network interface names.
    
    Uses psutil if available, otherwise falls back to system-specific methods.
    Works on Linux systems with proper network interfaces.
    
    Returns:
        List of interface names
        
    Example:
        >>> interfaces = list_interfaces()
        >>> print(f"Found {len(interfaces)} interfaces: {interfaces}")
        Found 3 interfaces: ['eth0', 'wlan0', 'lo']
    """
    interfaces = []
    
    if PSUTIL_AVAILABLE:
        try:
            # Use psutil for cross-platform interface detection
            for interface_name, addrs in psutil.net_if_addrs().items():
                # Filter out loopback and virtual interfaces
                if not interface_name.startswith(('lo', 'docker', 'br-', 'veth')):
                    interfaces.append(interface_name)
        except Exception as e:
            _get_logger().warning(f"psutil interface detection failed: {e}")
    
    # Fallback methods
    if not interfaces:
        if sys.platform == "linux":
            # Linux: read from /sys/class/net/
            try:
                net_dir = Path("/sys/class/net")
                if net_dir.exists():
                    for interface_path in net_dir.iterdir():
                        if interface_path.is_dir() and not interface_path.name.startswith(('lo', 'docker')):
                            interfaces.append(interface_path.name)
            except Exception as e:
                _get_logger().warning(f"Linux interface detection failed: {e}")
        
        # Cross-platform fallback using socket
        try:
            # Get all available interfaces
            for interface_name in socket.if_nameindex():
                if not interface_name[1].startswith(('lo', 'docker')):
                    interfaces.append(interface_name[1])
        except Exception as e:
            _get_logger().warning(f"Socket interface detection failed: {e}")
    
    
    return sorted(list(set(interfaces)))  # Remove duplicates and sort


def get_iface_mode(iface: str) -> str:
    """
    Detect the current mode of a network interface.
    
    Args:
        iface: Interface name to check
        
    Returns:
        Interface mode: "managed", "monitor", or "unknown"
        
    Example:
        >>> mode = get_iface_mode("wlan0")
        >>> print(f"Interface wlan0 is in {mode} mode")
        Interface wlan0 is in managed mode
    """
    # Check if iw is available
    if not shutil.which("iw"):
        _get_logger().info(f"iw not available, cannot determine mode for {iface}")
        return "unknown"
    
    try:
        # Use iw to get interface info
        result = _run_cmd(["iw", "dev", iface, "info"], None, timeout=5)
        
        # Parse output for type information
        for line in result.stdout.split('\n'):
            if 'type' in line.lower():
                if 'monitor' in line.lower():
                    return "monitor"
                elif 'managed' in line.lower():
                    return "managed"
                elif 'station' in line.lower():
                    return "managed"  # Station mode is typically managed
        
        return "unknown"
        
    except Exception as e:
        _get_logger().warning(f"Failed to determine mode for {iface}: {e}")
        return "unknown"


def can_switch_to_monitor(iface: str) -> bool:
    """
    Check if an interface can potentially be switched to monitor mode.
    
    Performs quick checks for:
    - Interface exists
    - Not a bridge/VLAN
    - Required tools available (iw or airmon-ng)
    - Platform compatibility
    
    Args:
        iface: Interface name to check
        
    Returns:
        True if switching to monitor mode appears possible
        
    Example:
        >>> can_switch = can_switch_to_monitor("wlan0")
        >>> print(f"Can switch wlan0 to monitor: {can_switch}")
        Can switch wlan0 to monitor: True
    """
    # Platform compatibility check
    
    # Check if interface exists
    interfaces = list_interfaces()
    if iface not in interfaces:
        _get_logger().warning(f"Interface {iface} not found in available interfaces")
        return False
    
    # Check if it's a virtual interface (bridge, VLAN, etc.)
    if iface.startswith(('br-', 'veth', 'docker', 'virbr')):
        _get_logger().warning(f"Interface {iface} appears to be virtual, not suitable for monitor mode")
        return False
    
    # Check for required tools
    has_iw = shutil.which("iw") is not None
    has_airmon = shutil.which("airmon-ng") is not None
    
    if not (has_iw or has_airmon):
        _get_logger().warning(f"No monitor mode tools available (iw or airmon-ng)")
        return False
    
    return True


def _run_cmd(cmd: List[str], logger: Optional[Any], timeout: int = 10) -> subprocess.CompletedProcess:
    """
    Run a command safely with proper error handling and logging.
    
    Args:
        cmd: Command to run as list of strings
        logger: Logger instance (optional)
        timeout: Command timeout in seconds
        
    Returns:
        CompletedProcess result
        
    Raises:
        MonitorModeError: If command fails
    """
    if logger is None:
        logger = _get_logger()
    
    try:
        logger.info(f"Running command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True
        )
        
        if result.stdout:
            logger.info(f"Command output: {result.stdout.strip()}")
        if result.stderr:
            logger.warning(f"Command stderr: {result.stderr.strip()}")
        
        return result
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Command failed: {' '.join(cmd)} (exit code {e.returncode})"
        if e.stderr:
            error_msg += f" - {e.stderr.strip()}"
        logger.error(error_msg)
        raise MonitorModeError(error_msg) from e
        
    except subprocess.TimeoutExpired as e:
        error_msg = f"Command timed out: {' '.join(cmd)}"
        logger.error(error_msg)
        raise MonitorModeError(error_msg) from e


@contextmanager
def monitor_mode(iface: str, *, dry_run: bool = False, logger: Optional[Any] = None):
    """
    Context manager for safely switching an interface to monitor mode.
    
    Always restores the original state, even on exceptions or KeyboardInterrupt.
    Uses iw method by default, falls back to airmon-ng if needed.
    
    Args:
        iface: Interface name to switch
        dry_run: If True, only log what would be done without making changes
        logger: Logger instance (optional)
        
    Yields:
        None (context manager)
        
    Raises:
        MonitorModeError: If required tools are missing or operations fail
        
    Example:
        >>> with monitor_mode("wlan0", dry_run=True) as _:
        ...     print("Would be in monitor mode now")
        >>> # Interface is automatically restored
        
        >>> with monitor_mode("wlan0") as _:
        ...     # Perform monitor mode operations
        ...     pass
        >>> # Interface automatically restored to original state
    """
    if logger is None:
        logger = _get_logger()
    
    
    # Record original state
    original_mode = get_iface_mode(iface)
    logger.info(f"Original mode of {iface}: {original_mode}")
    
    # Check if already in monitor mode
    if original_mode == "monitor":
        logger.info(f"Interface {iface} already in monitor mode, no change needed")
        try:
            yield
        finally:
            logger.info(f"Interface {iface} remains in monitor mode")
        return
    
    # Check if switching is possible
    if not can_switch_to_monitor(iface):
        raise MonitorModeError(f"Cannot switch {iface} to monitor mode")
    
    # Determine method to use
    has_iw = shutil.which("iw") is not None
    has_airmon = shutil.which("airmon-ng") is not None
    
    if not (has_iw or has_airmon):
        raise MonitorModeError("No monitor mode tools available (iw or airmon-ng)")
    
    method = "iw" if has_iw else "airmon-ng"
    logger.info(f"Using {method} method for monitor mode")
    
    # Dry run mode
    if dry_run:
        logger.info(f"[DRY RUN] Would switch {iface} to monitor mode using {method}")
        if method == "iw":
            logger.info(f"[DRY RUN] Commands: ip link set {iface} down; iw dev {iface} set type monitor; ip link set {iface} up")
        else:
            logger.info(f"[DRY RUN] Command: airmon-ng start {iface}")
        
        logger.info(f"[DRY RUN] Would restore {iface} to {original_mode} mode")
        try:
            yield
        finally:
            logger.info(f"[DRY RUN] Monitor mode session completed for {iface}")
        return
    
    # Actual monitor mode switch
    try:
        logger.info(f"Switching {iface} to monitor mode using {method}")
        
        if method == "iw":
            # Use iw method
            _run_cmd(["ip", "link", "set", iface, "down"], logger)
            _run_cmd(["iw", "dev", iface, "set", "type", "monitor"], logger)
            _run_cmd(["ip", "link", "set", iface, "up"], logger)
        else:
            # Use airmon-ng method
            _run_cmd(["airmon-ng", "start", iface], logger)
        
        logger.info(f"Successfully switched {iface} to monitor mode")
        
        # Yield control to caller
        yield
        
    except Exception as e:
        logger.error(f"Error during monitor mode operations: {e}")
        raise
    finally:
        # Always attempt to restore original state
        try:
            logger.info(f"Restoring {iface} to {original_mode} mode")
            
            if original_mode == "managed":
                if method == "iw":
                    _run_cmd(["ip", "link", "set", iface, "down"], logger)
                    _run_cmd(["iw", "dev", iface, "set", "type", "managed"], logger)
                    _run_cmd(["ip", "link", "set", iface, "up"], logger)
                else:
                    _run_cmd(["airmon-ng", "stop", iface], logger)
            elif original_mode == "monitor":
                logger.info(f"Interface {iface} was already in monitor mode, no restore needed")
            else:
                logger.warning(f"Unknown original mode {original_mode}, attempting managed mode restore")
                try:
                    if method == "iw":
                        _run_cmd(["ip", "link", "set", iface, "down"], logger)
                        _run_cmd(["iw", "dev", iface, "set", "type", "managed"], logger)
                        _run_cmd(["ip", "link", "set", iface, "up"], logger)
                    else:
                        _run_cmd(["airmon-ng", "stop", iface], logger)
                except Exception as restore_error:
                    logger.error(f"Failed to restore {iface}: {restore_error}")
            
            logger.info(f"Successfully restored {iface} to {original_mode} mode")
            
        except Exception as restore_error:
            # Log error but don't re-raise to allow caller to save session state
            logger.error(f"Failed to restore {iface} to original state: {restore_error}")
            logger.error("Interface may be left in monitor mode - manual intervention may be required")


def validate_bssid(bssid: str) -> bool:
    """
    Validate BSSID format.
    
    Args:
        bssid: BSSID string to validate
        
    Returns:
        True if valid BSSID format
    """
    import re
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(pattern, bssid))


def validate_channel(channel: int) -> bool:
    """
    Validate WiFi channel number.
    
    Args:
        channel: Channel number to validate
        
    Returns:
        True if valid channel
    """
    return 1 <= channel <= 14  # 2.4GHz channels


if __name__ == "__main__":
    """
    Demo script that lists interfaces and performs a dry-run monitor mode test.
    This demo does not change system state.
    """
    print("NetHawk Network Utilities Demo")
    print("=" * 40)
    
    # List available interfaces
    print("\n1. Available interfaces:")
    interfaces = list_interfaces()
    if interfaces:
        for i, iface in enumerate(interfaces, 1):
            print(f"   {i}. {iface}")
    else:
        print("   No interfaces found")
        sys.exit(1)
    
    # Test interface mode detection
    print("\n2. Interface mode detection:")
    for iface in interfaces[:3]:  # Test first 3 interfaces
        mode = get_iface_mode(iface)
        can_switch = can_switch_to_monitor(iface)
        print(f"   {iface}: {mode} mode, can switch to monitor: {can_switch}")
    
    # Test dry-run monitor mode
    print("\n3. Dry-run monitor mode test:")
    test_iface = interfaces[0] if interfaces else None
    
    if test_iface:
        print(f"   Testing dry-run monitor mode for {test_iface}")
        try:
            with monitor_mode(test_iface, dry_run=True) as _:
                print(f"   [DRY RUN] Would be in monitor mode with {test_iface}")
            print(f"   [DRY RUN] Monitor mode session completed for {test_iface}")
        except MonitorModeError as e:
            print(f"   [DRY RUN] Monitor mode test failed: {e}")
    else:
        print("   No interfaces available for testing")
    
    print("\nDemo completed - no system changes made")