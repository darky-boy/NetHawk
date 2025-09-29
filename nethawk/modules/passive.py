"""
NetHawk Passive Scan Module
Production-ready passive scanning with airodump-ng CSV parsing and non-destructive operation
"""

import csv
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
import subprocess
import threading
import signal
import sys

# Lazy import to avoid circular dependencies
def _get_logger():
    """Get logger instance lazily to avoid circular imports."""
    try:
        from nethawk.util.logger import get_logger
        return get_logger(name="nethawk.passive")
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from nethawk.util.logger import get_logger
        return get_logger(name="nethawk.passive")


@dataclass
class AccessPoint:
    """Represents a wireless access point discovered during passive scan."""
    bssid: str
    channel: Optional[int] = None
    pwr: Optional[int] = None
    beacons: Optional[int] = None
    essid: Optional[str] = None
    vendor: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AccessPoint':
        """Create from dictionary."""
        return cls(**data)


@dataclass
class Station:
    """Represents a wireless station (client) discovered during passive scan."""
    station_mac: str
    associated_bssid: Optional[str] = None
    probing: Optional[List[str]] = None
    last_seen: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Station':
        """Create from dictionary."""
        return cls(**data)


@dataclass
class PassiveScanResults:
    """Container for passive scan results."""
    access_points: List[AccessPoint]
    stations: List[Station]
    scan_duration: float
    timestamp: float
    interface: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'access_points': [ap.to_dict() for ap in self.access_points],
            'stations': [st.to_dict() for st in self.stations],
            'scan_duration': self.scan_duration,
            'timestamp': self.timestamp,
            'interface': self.interface
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PassiveScanResults':
        """Create from dictionary."""
        return cls(
            access_points=[AccessPoint.from_dict(ap) for ap in data['access_points']],
            stations=[Station.from_dict(st) for st in data['stations']],
            scan_duration=data['scan_duration'],
            timestamp=data['timestamp'],
            interface=data['interface']
        )


def parse_airodump_csv(csv_path: Path) -> PassiveScanResults:
    """
    Parse airodump-ng CSV output file.
    
    Args:
        csv_path: Path to the CSV file to parse
        
    Returns:
        PassiveScanResults containing parsed data
        
    Raises:
        FileNotFoundError: If CSV file doesn't exist
        ValueError: If CSV format is invalid
        
    Example:
        >>> results = parse_airodump_csv(Path("scan.csv"))
        >>> print(f"Found {len(results.access_points)} access points")
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")
    
    access_points = []
    stations = []
    
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read the file content
            content = f.read()
            
            # Split into sections (APs and Stations)
            sections = content.split('\n\n')
            
            # Parse Access Points section
            if len(sections) > 0:
                ap_section = sections[0].strip()
                if ap_section:
                    ap_reader = csv.DictReader(ap_section.split('\n'))
                    for row in ap_reader:
                        if row.get('BSSID'):  # Skip empty rows
                            ap = AccessPoint(
                                bssid=row.get('BSSID', '').strip(),
                                channel=_parse_int(row.get('channel', '')),
                                pwr=_parse_int(row.get('PWR', '')),
                                beacons=_parse_int(row.get('beacons', '')),
                                essid=row.get('ESSID', '').strip() or None,
                                vendor=None  # Will be filled by vendor lookup
                            )
                            access_points.append(ap)
            
            # Parse Stations section
            if len(sections) > 1:
                station_section = sections[1].strip()
                if station_section:
                    station_reader = csv.DictReader(station_section.split('\n'))
                    for row in station_reader:
                        if row.get('Station MAC'):  # Skip empty rows
                            station = Station(
                                station_mac=row.get('Station MAC', '').strip(),
                                associated_bssid=row.get('BSSID', '').strip() or None,
                                probing=_parse_probing_list(row.get('Probes', '')),
                                last_seen=_parse_int(row.get('Last seen', ''))
                            )
                            stations.append(station)
    
    except Exception as e:
        raise ValueError(f"Failed to parse CSV file: {e}")
    
    return PassiveScanResults(
        access_points=access_points,
        stations=stations,
        scan_duration=0.0,  # Will be set by caller
        timestamp=time.time(),
        interface="unknown"  # Will be set by caller
    )


def _parse_int(value: str) -> Optional[int]:
    """Parse integer value from string, return None if invalid."""
    if not value or value.strip() == '':
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _parse_probing_list(value: str) -> Optional[List[str]]:
    """Parse probing list from string."""
    if not value or value.strip() == '':
        return None
    # Split by comma and clean up
    probes = [p.strip() for p in value.split(',') if p.strip()]
    return probes if probes else None


def _lookup_vendor(mac_address: str) -> Optional[str]:
    """
    Lookup vendor information for MAC address.
    
    Args:
        mac_address: MAC address to lookup
        
    Returns:
        Vendor name or None if not found
        
    TODO: Implement real vendor lookup using macvendors.com API or local OUI database
    """
    # TODO: Implement vendor lookup
    # - Use macvendors.com API for online lookup
    # - Cache results to avoid repeated API calls
    # - Handle API failures gracefully
    # - Consider local OUI database for offline operation
    
    # Placeholder implementation
    oui_prefix = mac_address[:8].upper().replace(':', '')
    
    # Simple OUI lookup (expand this with real database)
    oui_database = {
        '001122': 'Test Vendor',
        'AABBCC': 'Example Corp',
        'DEADBE': 'Demo Company'
    }
    
    return oui_database.get(oui_prefix, None)


def _run_airodump_scan(interface: str, output_dir: Path, duration: int = 60, logger=None) -> Path:
    """
    Run airodump-ng scan and return path to CSV file.
    
    Args:
        interface: Network interface to use
        output_dir: Directory to save output files
        duration: Scan duration in seconds
        logger: Logger instance
        
    Returns:
        Path to the generated CSV file
        
    Raises:
        RuntimeError: If airodump-ng fails or is not available
    """
    if logger is None:
        logger = _get_logger()
    
    # Check if airodump-ng is available
    if not _check_airodump_available():
        raise RuntimeError("airodump-ng not available - install aircrack-ng package")
    
    # Prepare output files
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_file = output_dir / f"airodump_{int(time.time())}.csv"
    
    # Build airodump-ng command
    cmd = [
        "airodump-ng",
        "-w", str(csv_file.with_suffix('')),  # Remove .csv extension for airodump
        "-o", "csv",  # Output format
        "--write-interval", "1",  # Write every second
        interface
    ]
    
    logger.info(f"Starting airodump-ng scan on {interface} for {duration} seconds")
    logger.info(f"Output will be saved to: {csv_file}")
    
    try:
        # Run airodump-ng with timeout
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
            logger.info(f"Scan duration ({duration}s) completed, stopping airodump-ng")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.warning("airodump-ng did not stop gracefully, forcing kill")
                process.kill()
        
        # Check if CSV file was created
        if not csv_file.exists():
            raise RuntimeError(f"airodump-ng did not create output file: {csv_file}")
        
        logger.info(f"airodump-ng scan completed, output saved to: {csv_file}")
        return csv_file
        
    except Exception as e:
        logger.error(f"airodump-ng scan failed: {e}")
        raise RuntimeError(f"airodump-ng scan failed: {e}")


def _check_airodump_available() -> bool:
    """Check if airodump-ng is available on the system."""
    import shutil
    return shutil.which("airodump-ng") is not None


def run_passive_scan(
    session_path: Path,
    interface: str = "wlan0",
    duration: int = 60,
    dry_run: bool = True,
    logger: Optional[Any] = None
) -> PassiveScanResults:
    """
    Run passive wireless scan to discover access points and stations.
    
    Args:
        session_path: Path to session directory for saving results
        interface: Network interface to use for scanning
        duration: Scan duration in seconds
        dry_run: If True, only simulate the scan without actually running airodump-ng
        logger: Logger instance (optional)
        
    Returns:
        PassiveScanResults containing discovered access points and stations
        
    Example:
        >>> results = run_passive_scan(Path("sessions/session_001"), "wlan0", dry_run=True)
        >>> print(f"Found {len(results.access_points)} access points")
    """
    if logger is None:
        logger = _get_logger()
    
    logger.info(f"Starting passive scan on interface {interface}")
    logger.info(f"Duration: {duration} seconds, Dry run: {dry_run}")
    
    start_time = time.time()
    
    if dry_run:
        # Simulate scan results for testing
        logger.info("[DRY RUN] Simulating passive scan - no actual network capture")
        
        # Create simulated results
        simulated_aps = [
            AccessPoint(
                bssid="00:11:22:33:44:55",
                channel=6,
                pwr=-45,
                beacons=150,
                essid="TestNetwork",
                vendor="Netgear"
            ),
            AccessPoint(
                bssid="aa:bb:cc:dd:ee:ff",
                channel=11,
                pwr=-60,
                beacons=75,
                essid="HiddenNetwork",
                vendor="Linksys"
            )
        ]
        
        simulated_stations = [
            Station(
                station_mac="11:22:33:44:55:66",
                associated_bssid="00:11:22:33:44:55",
                probing=None,
                last_seen=30
            ),
            Station(
                station_mac="77:88:99:aa:bb:cc",
                associated_bssid=None,
                probing=["TestNetwork", "OtherNetwork"],
                last_seen=45
            )
        ]
        
        results = PassiveScanResults(
            access_points=simulated_aps,
            stations=simulated_stations,
            scan_duration=duration,
            timestamp=start_time,
            interface=interface
        )
        
    else:
        # Real scan using airodump-ng
        logger.info("Performing real passive scan - this will capture network traffic")
        
        # Use monitor mode context manager
        try:
            from nethawk.util.net import monitor_mode
            
            with monitor_mode(interface, dry_run=False, logger=logger):
                # Run airodump-ng scan
                csv_file = _run_airodump_scan(interface, session_path / "logs", duration, logger)
                
                # Parse results
                results = parse_airodump_csv(csv_file)
                results.scan_duration = time.time() - start_time
                results.interface = interface
                
                # Perform vendor lookups
                for ap in results.access_points:
                    if ap.bssid:
                        ap.vendor = _lookup_vendor(ap.bssid)
                
        except Exception as e:
            logger.error(f"Passive scan failed: {e}")
            # Return empty results on failure
            results = PassiveScanResults(
                access_points=[],
                stations=[],
                scan_duration=time.time() - start_time,
                timestamp=start_time,
                interface=interface
            )
    
    # Save results to session directory
    results_file = session_path / "passive.json"
    with open(results_file, 'w') as f:
        json.dump(results.to_dict(), f, indent=2)
    
    logger.info(f"Passive scan completed in {results.scan_duration:.2f} seconds")
    logger.info(f"Found {len(results.access_points)} access points and {len(results.stations)} stations")
    logger.info(f"Results saved to: {results_file}")
    
    return results


def display_scan_results(results: PassiveScanResults, logger: Optional[Any] = None) -> None:
    """
    Display scan results in a formatted table.
    
    Args:
        results: PassiveScanResults to display
        logger: Logger instance (optional)
    """
    if logger is None:
        logger = _get_logger()
    
    try:
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        
        # Display Access Points
        if results.access_points:
            table = Table(title="Discovered Access Points")
            table.add_column("BSSID")
            table.add_column("ESSID")
            table.add_column("Channel")
            table.add_column("Power")
            table.add_column("Beacons")
            table.add_column("Vendor")
            
            for ap in results.access_points:
                table.add_row(
                    ap.bssid,
                    ap.essid or "Hidden",
                    str(ap.channel) if ap.channel else "Unknown",
                    str(ap.pwr) if ap.pwr else "Unknown",
                    str(ap.beacons) if ap.beacons else "Unknown",
                    ap.vendor or "Unknown"
                )
            
            console.print(table)
        
        # Display Stations
        if results.stations:
            table = Table(title="Discovered Stations")
            table.add_column("Station MAC")
            table.add_column("Associated BSSID")
            table.add_column("Probing")
            table.add_column("Last Seen")
            
            for station in results.stations:
                probing_str = ", ".join(station.probing) if station.probing else "None"
                table.add_row(
                    station.station_mac,
                    station.associated_bssid or "None",
                    probing_str,
                    str(station.last_seen) if station.last_seen else "Unknown"
                )
            
            console.print(table)
    
    except ImportError:
        # Fallback to simple text output if Rich is not available
        logger.info("Rich not available, using simple text output")
        
        print("\n=== Access Points ===")
        for ap in results.access_points:
            print(f"BSSID: {ap.bssid}, ESSID: {ap.essid or 'Hidden'}, Channel: {ap.channel}, Power: {ap.pwr}")
        
        print("\n=== Stations ===")
        for station in results.stations:
            print(f"Station: {station.station_mac}, Associated: {station.associated_bssid or 'None'}")


if __name__ == "__main__":
    """
    Demo script for testing passive scan functionality.
    This demo uses dry_run=True to avoid making system changes.
    """
    try:
        from nethawk.session import create_session
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from nethawk.session import create_session
    
    print("NetHawk Passive Scan Module Demo")
    print("=" * 40)
    
    # Create a test session
    session_path = create_session("passive_demo")
    print(f"Created test session: {session_path}")
    
    # Test CSV parsing with a sample file (if it exists)
    sample_csv = Path("sample_airodump.csv")
    if sample_csv.exists():
        print(f"\nTesting CSV parsing with {sample_csv}")
        try:
            results = parse_airodump_csv(sample_csv)
            print(f"Parsed {len(results.access_points)} access points and {len(results.stations)} stations")
        except Exception as e:
            print(f"CSV parsing failed: {e}")
    else:
        print("\nNo sample CSV file found, skipping parser test")
    
    # Test dry-run passive scan
    print("\nTesting dry-run passive scan...")
    try:
        results = run_passive_scan(
            session_path=session_path,
            interface="wlan0",
            duration=30,
            dry_run=True
        )
        
        print(f"Dry-run scan completed:")
        print(f"  - Found {len(results.access_points)} access points")
        print(f"  - Found {len(results.stations)} stations")
        print(f"  - Scan duration: {results.scan_duration:.2f} seconds")
        
        # Display results
        display_scan_results(results)
        
    except Exception as e:
        print(f"Dry-run scan failed: {e}")
    
    print("\nDemo completed - no system changes made")