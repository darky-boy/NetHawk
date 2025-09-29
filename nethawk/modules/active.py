"""
NetHawk Active Scan Module
Production-ready active scanning with network discovery and port scanning
"""

import json
import socket
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
import ipaddress
import threading
import concurrent.futures
import sys

# Lazy import to avoid circular dependencies
def _get_logger():
    """Get logger instance lazily to avoid circular imports."""
    try:
        from nethawk.util.logger import get_logger
        return get_logger(name="nethawk.active")
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from nethawk.util.logger import get_logger
        return get_logger(name="nethawk.active")

# Try to import scapy for advanced ARP scanning
try:
    from scapy.layers.l2 import arping
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


@dataclass
class HostInfo:
    """Represents a discovered host during active scan."""
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    alive: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HostInfo':
        """Create from dictionary."""
        return cls(**data)


@dataclass
class PortInfo:
    """Represents a scanned port result."""
    port: int
    protocol: str = "tcp"
    state: str = "closed"  # open/closed/filtered
    service: Optional[str] = None
    banner: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PortInfo':
        """Create from dictionary."""
        return cls(**data)


@dataclass
class ActiveScanResult:
    """Container for active scan results."""
    hosts: List[HostInfo]
    ports: Dict[str, List[PortInfo]]  # keyed by IP
    scan_duration: float
    timestamp: float
    target: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'hosts': [host.to_dict() for host in self.hosts],
            'ports': {ip: [port.to_dict() for port in ports] for ip, ports in self.ports.items()},
            'scan_duration': self.scan_duration,
            'timestamp': self.timestamp,
            'target': self.target
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ActiveScanResult':
        """Create from dictionary."""
        return cls(
            hosts=[HostInfo.from_dict(host) for host in data['hosts']],
            ports={ip: [PortInfo.from_dict(port) for port in ports] for ip, ports in data['ports'].items()},
            scan_duration=data['scan_duration'],
            timestamp=data['timestamp'],
            target=data['target']
        )


def _is_safe_target(target: str) -> bool:
    """
    Check if target is safe for scanning (local/lab networks only).
    
    Args:
        target: Target IP or subnet to check
        
    Returns:
        True if target appears to be safe for scanning
    """
    try:
        # Parse target as network
        network = ipaddress.ip_network(target, strict=False)
        
        # Check for private/local networks
        if network.is_private:
            return True
        
        # Check for localhost
        if network.is_loopback:
            return True
        
        # Check for link-local
        if network.is_link_local:
            return True
        
        # Check for common lab ranges
        lab_ranges = [
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("127.0.0.0/8")
        ]
        
        for lab_range in lab_ranges:
            if network.subnet_of(lab_range):
                return True
        
        return False
        
    except Exception:
        # If we can't parse it, assume it's unsafe
        return False


def _lookup_vendor(mac_address: str) -> Optional[str]:
    """
    Lookup vendor information for MAC address.
    
    Args:
        mac_address: MAC address to lookup
        
    Returns:
        Vendor name or None if not found
    """
    # TODO: Implement real vendor lookup using macvendors.com API or local OUI database
    # - Use macvendors.com API for online lookup
    # - Cache results to avoid repeated API calls
    # - Handle API failures gracefully
    # - Consider local OUI database for offline operation
    
    # Placeholder implementation
    if not mac_address:
        return None
    
    oui_prefix = mac_address[:8].upper().replace(':', '')
    
    # Simple OUI lookup (expand this with real database)
    oui_database = {
        '001122': 'Test Vendor',
        'AABBCC': 'Example Corp',
        'DEADBE': 'Demo Company',
        '000000': 'Unknown'
    }
    
    return oui_database.get(oui_prefix, None)


def arp_sweep(subnet: str, timeout: float = 2.0, logger: Optional[Any] = None) -> List[HostInfo]:
    """
    Perform ARP sweep to discover hosts on a subnet.
    
    Args:
        subnet: Subnet to scan (e.g., "192.168.1.0/24")
        timeout: Timeout for each ARP request
        logger: Logger instance (optional)
        
    Returns:
        List of discovered hosts
        
    Example:
        >>> hosts = arp_sweep("192.168.1.0/24", timeout=1.0)
        >>> print(f"Found {len(hosts)} hosts")
    """
    if logger is None:
        logger = _get_logger()
    
    logger.info(f"Starting ARP sweep on {subnet}")
    
    hosts = []
    
    # Try scapy first (most accurate)
    if SCAPY_AVAILABLE:
        try:
            logger.info("Using scapy for ARP sweep")
            result = arping(subnet, timeout=timeout, verbose=False)
            
            for sent, received in result[0]:
                if received:
                    host = HostInfo(
                        ip=received.psrc,
                        mac=received.hwsrc,
                        vendor=_lookup_vendor(received.hwsrc),
                        alive=True
                    )
                    hosts.append(host)
                    logger.info(f"Found host: {host.ip} ({host.mac})")
            
            logger.info(f"Scapy ARP sweep completed, found {len(hosts)} hosts")
            return hosts
            
        except Exception as e:
            logger.warning(f"Scapy ARP sweep failed: {e}, falling back to nmap")
    
    # Fallback to nmap
    if _check_nmap_available():
        try:
            logger.info("Using nmap for ARP sweep")
            cmd = ["nmap", "-sn", "-T4", "--max-retries", "1", subnet]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse nmap output for hosts
                for line in result.stdout.split('\n'):
                    if 'Nmap scan report for' in line:
                        # Extract IP from line like "Nmap scan report for 192.168.1.1"
                        parts = line.split()
                        if len(parts) >= 5:
                            ip = parts[4]
                            host = HostInfo(ip=ip, alive=True)
                            hosts.append(host)
                            logger.info(f"Found host: {host.ip}")
            
            logger.info(f"Nmap ARP sweep completed, found {len(hosts)} hosts")
            return hosts
            
        except Exception as e:
            logger.warning(f"Nmap ARP sweep failed: {e}, falling back to ping sweep")
    
    # Last resort: ping sweep
    logger.info("Using ping sweep as fallback")
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        for ip in network.hosts():
            if _ping_host(str(ip), timeout=timeout):
                host = HostInfo(ip=str(ip), alive=True)
                hosts.append(host)
                logger.info(f"Found host: {host.ip}")
    except Exception as e:
        logger.error(f"Ping sweep failed: {e}")
    
    logger.info(f"ARP sweep completed, found {len(hosts)} hosts")
    return hosts


def _check_nmap_available() -> bool:
    """Check if nmap is available on the system."""
    import shutil
    return shutil.which("nmap") is not None


def _ping_host(ip: str, timeout: float = 1.0) -> bool:
    """
    Ping a single host to check if it's alive.
    
    Args:
        ip: IP address to ping
        timeout: Ping timeout in seconds
        
    Returns:
        True if host is alive
    """
    try:
        # Use system ping command
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 1
        )
        
        return result.returncode == 0
        
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
    except Exception:
        return False


def port_scan(host: str, ports: List[int], timeout: float = 1.0, banner: bool = False, logger: Optional[Any] = None) -> List[PortInfo]:
    """
    Scan ports on a host using TCP connect scan.
    
    Args:
        host: Host IP to scan
        ports: List of ports to scan
        timeout: Connection timeout per port
        banner: Whether to attempt banner grabbing
        logger: Logger instance (optional)
        
    Returns:
        List of port scan results
        
    Example:
        >>> ports = port_scan("192.168.1.1", [22, 80, 443], timeout=0.5)
        >>> print(f"Scanned {len(ports)} ports")
    """
    if logger is None:
        logger = _get_logger()
    
    logger.info(f"Scanning {len(ports)} ports on {host}")
    
    results = []
    
    def scan_port(port: int) -> PortInfo:
        """Scan a single port."""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Attempt connection
            result = sock.connect_ex((host, port))
            
            if result == 0:
                # Port is open
                service = _get_service_name(port)
                banner_text = None
                
                if banner:
                    try:
                        # Try to read banner
                        sock.settimeout(0.5)
                        banner_text = sock.recv(512).decode('utf-8', errors='ignore').strip()
                    except Exception:
                        pass
                
                port_info = PortInfo(
                    port=port,
                    protocol="tcp",
                    state="open",
                    service=service,
                    banner=banner_text
                )
                
                logger.info(f"Port {port}/tcp open ({service})")
                return port_info
            else:
                # Port is closed
                return PortInfo(port=port, protocol="tcp", state="closed")
                
        except socket.timeout:
            return PortInfo(port=port, protocol="tcp", state="filtered")
        except Exception as e:
            logger.warning(f"Error scanning port {port}: {e}")
            return PortInfo(port=port, protocol="tcp", state="error")
        finally:
            try:
                sock.close()
            except Exception:
                pass
    
    # Scan ports concurrently for better performance
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(scan_port, port): port for port in ports}
        
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logger.warning(f"Port {port} scan failed: {e}")
                results.append(PortInfo(port=port, protocol="tcp", state="error"))
    
    # Sort results by port number
    results.sort(key=lambda x: x.port)
    
    open_ports = [p for p in results if p.state == "open"]
    logger.info(f"Port scan completed: {len(open_ports)}/{len(ports)} ports open")
    
    return results


def _get_service_name(port: int) -> Optional[str]:
    """
    Get service name for common ports.
    
    Args:
        port: Port number
        
    Returns:
        Service name or None
    """
    # Common port mappings
    service_map = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        993: "imaps",
        995: "pop3s",
        1433: "mssql",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        8080: "http-proxy",
        8443: "https-alt"
    }
    
    return service_map.get(port, None)


def run_active_scan(
    target: str,
    session_path: Path,
    ports: Optional[List[int]] = None,
    safe_mode: bool = True,
    logger: Optional[Any] = None
) -> Path:
    """
    Run active scan on target network or host.
    
    Args:
        target: Target IP or subnet to scan
        ports: List of ports to scan (default: common ports)
        session_path: Path to session directory for saving results
        safe_mode: If True, only allow safe targets (local/lab networks)
        logger: Logger instance (optional)
        
    Returns:
        Path to the generated results file
        
    Raises:
        ValueError: If target is not safe and safe_mode is True
        
    Example:
        >>> results_path = run_active_scan("192.168.1.0/24", session_path=Path("sessions/session_001"))
        >>> print(f"Results saved to: {results_path}")
    """
    if logger is None:
        logger = _get_logger()
    
    logger.info(f"Starting active scan on {target}")
    logger.info(f"Safe mode: {safe_mode}")
    
    # Validate target safety
    if safe_mode and not _is_safe_target(target):
        raise ValueError(f"Target {target} is not safe for scanning. Use safe_mode=False to override.")
    
    # Set default ports if not provided
    if ports is None:
        ports = [22, 80, 443, 139, 445, 8080, 3306, 1433, 3389, 5432]
    
    start_time = time.time()
    
    # Determine if target is a single host or subnet
    try:
        network = ipaddress.ip_network(target, strict=False)
        is_subnet = network.num_addresses > 1
    except Exception:
        # Assume single host
        is_subnet = False
    
    # Discover hosts
    if is_subnet:
        logger.info(f"Scanning subnet: {target}")
        hosts = arp_sweep(target, timeout=2.0, logger=logger)
    else:
        logger.info(f"Scanning single host: {target}")
        # Single host - just ping to check if alive
        if _ping_host(target, timeout=2.0):
            hosts = [HostInfo(ip=target, alive=True)]
        else:
            logger.warning(f"Host {target} appears to be down")
            hosts = [HostInfo(ip=target, alive=False)]
    
    # Scan ports on each host
    port_results = {}
    for host in hosts:
        if host.alive:
            logger.info(f"Scanning ports on {host.ip}")
            port_results[host.ip] = port_scan(host.ip, ports, timeout=1.0, banner=True, logger=logger)
        else:
            port_results[host.ip] = []
    
    # Create results
    scan_duration = time.time() - start_time
    results = ActiveScanResult(
        hosts=hosts,
        ports=port_results,
        scan_duration=scan_duration,
        timestamp=start_time,
        target=target
    )
    
    # Save results
    results_file = session_path / "active.json"
    with open(results_file, 'w') as f:
        json.dump(results.to_dict(), f, indent=2)
    
    # Log completion event
    alive_hosts = [h for h in hosts if h.alive]
    total_ports = sum(len(ports) for ports in port_results.values())
    open_ports = sum(len([p for p in ports if p.state == "open"]) for ports in port_results.values())
    
    logger.info(f"Active scan completed in {scan_duration:.2f} seconds")
    logger.info(f"Found {len(alive_hosts)} alive hosts, {open_ports}/{total_ports} ports open")
    logger.info(f"Results saved to: {results_file}")
    
    return results_file


def sample_subnet_scan() -> ActiveScanResult:
    """
    Generate sample scan results for testing purposes.
    
    Returns:
        Sample ActiveScanResult for testing
    """
    hosts = [
        HostInfo(ip="192.168.1.1", mac="00:11:22:33:44:55", vendor="Router Corp", alive=True),
        HostInfo(ip="192.168.1.100", mac="aa:bb:cc:dd:ee:ff", vendor="Laptop Inc", alive=True),
        HostInfo(ip="192.168.1.200", mac="77:88:99:aa:bb:cc", vendor="Server Co", alive=True)
    ]
    
    ports = {
        "192.168.1.1": [
            PortInfo(port=22, state="open", service="ssh"),
            PortInfo(port=80, state="open", service="http"),
            PortInfo(port=443, state="open", service="https")
        ],
        "192.168.1.100": [
            PortInfo(port=22, state="open", service="ssh"),
            PortInfo(port=80, state="closed", service=None),
            PortInfo(port=443, state="closed", service=None)
        ],
        "192.168.1.200": [
            PortInfo(port=22, state="open", service="ssh"),
            PortInfo(port=80, state="open", service="http"),
            PortInfo(port=443, state="open", service="https"),
            PortInfo(port=3306, state="open", service="mysql")
        ]
    }
    
    return ActiveScanResult(
        hosts=hosts,
        ports=ports,
        scan_duration=15.5,
        timestamp=time.time(),
        target="192.168.1.0/24"
    )


def display_scan_results(results: ActiveScanResult, logger: Optional[Any] = None) -> None:
    """
    Display scan results in a formatted table.
    
    Args:
        results: ActiveScanResult to display
        logger: Logger instance (optional)
    """
    if logger is None:
        logger = _get_logger()
    
    try:
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        
        # Display Hosts
        if results.hosts:
            table = Table(title="Discovered Hosts")
            table.add_column("IP Address")
            table.add_column("MAC Address")
            table.add_column("Vendor")
            table.add_column("Status")
            
            for host in results.hosts:
                table.add_row(
                    host.ip,
                    host.mac or "Unknown",
                    host.vendor or "Unknown",
                    "Alive" if host.alive else "Down"
                )
            
            console.print(table)
        
        # Display Ports
        if results.ports:
            for ip, ports in results.ports.items():
                if ports:
                    table = Table(title=f"Open Ports on {ip}")
                    table.add_column("Port")
                    table.add_column("Protocol")
                    table.add_column("State")
                    table.add_column("Service")
                    table.add_column("Banner")
                    
                    for port in ports:
                        if port.state == "open":
                            banner = port.banner[:50] + "..." if port.banner and len(port.banner) > 50 else port.banner
                            table.add_row(
                                str(port.port),
                                port.protocol,
                                port.state,
                                port.service or "Unknown",
                                banner or "None"
                            )
                    
                    console.print(table)
    
    except ImportError:
        # Fallback to simple text output if Rich is not available
        logger.info("Rich not available, using simple text output")
        
        print("\n=== Discovered Hosts ===")
        for host in results.hosts:
            print(f"IP: {host.ip}, MAC: {host.mac or 'Unknown'}, Vendor: {host.vendor or 'Unknown'}")
        
        print("\n=== Open Ports ===")
        for ip, ports in results.ports.items():
            open_ports = [p for p in ports if p.state == "open"]
            if open_ports:
                print(f"\n{ip}:")
                for port in open_ports:
                    print(f"  {port.port}/{port.protocol} - {port.service or 'Unknown'}")


if __name__ == "__main__":
    """
    Demo script for testing active scan functionality.
    This demo uses safe targets to avoid making system changes.
    """
    try:
        from nethawk.session import create_session
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from nethawk.session import create_session
    
    print("NetHawk Active Scan Module Demo")
    print("=" * 40)
    
    # Create a test session
    session_path = create_session("demo_active")
    print(f"Created test session: {session_path}")
    
    # Test sample scan results
    print("\nTesting sample scan results...")
    sample_results = sample_subnet_scan()
    print(f"Sample scan: {len(sample_results.hosts)} hosts, {sum(len(ports) for ports in sample_results.ports.values())} ports")
    
    # Test safe active scan
    print("\nTesting safe active scan on localhost...")
    try:
        results_path = run_active_scan(
            target="127.0.0.1/32",
            ports=[22, 80],
            session_path=session_path,
            safe_mode=True
        )
        
        print(f"Active scan completed, results saved to: {results_path}")
        
        # Display results
        with open(results_path, 'r') as f:
            results_data = json.load(f)
        
        print(f"Scan results:")
        print(f"  - Hosts found: {len(results_data['hosts'])}")
        print(f"  - Scan duration: {results_data['scan_duration']:.2f} seconds")
        print(f"  - Target: {results_data['target']}")
        
    except Exception as e:
        print(f"Active scan failed: {e}")
    
    print("\nDemo completed - no system changes made")