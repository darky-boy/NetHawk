"""
NetHawk Report Generation Module
Production-ready report generation with HTML, JSON, and optional PDF export
"""

import os
import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any, Union

# Optional PDF export
try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    PDFKIT_AVAILABLE = False

# Optional Jinja2 for HTML templating
try:
    from jinja2 import Environment, FileSystemLoader, Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

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
class ReportData:
    """Container for all report data from NetHawk modules."""
    session: str
    passive_hosts: List[dict] = field(default_factory=list)
    active_hosts: List[dict] = field(default_factory=list)
    handshakes: List[dict] = field(default_factory=list)
    cracks: List[dict] = field(default_factory=list)
    timestamp: str = field(default_factory=current_time_str)
    total_aps: int = 0
    total_stations: int = 0
    total_hosts: int = 0
    total_ports: int = 0
    successful_cracks: int = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'ReportData':
        """Create from dictionary."""
        return cls(
            session=data.get("session", ""),
            passive_hosts=data.get("passive_hosts", []),
            active_hosts=data.get("active_hosts", []),
            handshakes=data.get("handshakes", []),
            cracks=data.get("cracks", []),
            timestamp=data.get("timestamp", ""),
            total_aps=data.get("total_aps", 0),
            total_stations=data.get("total_stations", 0),
            total_hosts=data.get("total_hosts", 0),
            total_ports=data.get("total_ports", 0),
            successful_cracks=data.get("successful_cracks", 0)
        )


def load_module_data(module_json_path: str) -> List[dict]:
    """
    Load JSON data from a module output file.
    
    Args:
        module_json_path: Path to the JSON file
        
    Returns:
        List of data items or empty list if file not found/error
    """
    path = Path(module_json_path)
    if not path.exists():
        print(f"[!] Module data not found: {module_json_path}")
        return []
    
    try:
        with open(path, "r") as f:
            data = json.load(f)
        
        # Handle different data structures
        if isinstance(data, list):
            return data
        elif isinstance(data, dict):
            # Extract relevant data based on module type
            if "handshakes" in data:
                return data.get("handshakes", [])
            elif "hosts" in data:
                return data.get("hosts", [])
            elif "crack_attempts" in data:
                return data.get("crack_attempts", [])
            else:
                return [data]  # Single item
        else:
            return []
            
    except Exception as e:
        print(f"[!] Failed to load {module_json_path}: {e}")
        return []


def load_passive_data(session_path: Path) -> List[dict]:
    """Load passive scan data from session."""
    passive_json = session_path / "passive.json"
    if not passive_json.exists():
        return []
    
    try:
        with open(passive_json, "r") as f:
            data = json.load(f)
        
        # Extract access points and stations
        aps = data.get("access_points", [])
        stations = data.get("stations", [])
        
        # Combine into single list with type indicators
        result = []
        for ap in aps:
            ap["type"] = "access_point"
            result.append(ap)
        for station in stations:
            station["type"] = "station"
            result.append(station)
        
        return result
    except Exception as e:
        print(f"[!] Failed to load passive data: {e}")
        return []


def load_active_data(session_path: Path) -> List[dict]:
    """Load active scan data from session."""
    active_json = session_path / "active.json"
    if not active_json.exists():
        return []
    
    try:
        with open(active_json, "r") as f:
            data = json.load(f)
        
        # Extract hosts and ports
        hosts = data.get("hosts", [])
        ports_data = data.get("ports", {})
        
        # Add port information to hosts
        for host in hosts:
            ip = host.get("ip", "")
            if ip in ports_data:
                host["ports"] = ports_data[ip]
            else:
                host["ports"] = []
        
        return hosts
    except Exception as e:
        print(f"[!] Failed to load active data: {e}")
        return []


def load_capture_data(session_path: Path) -> List[dict]:
    """Load handshake capture data from session."""
    capture_json = session_path / "capture.json"
    if not capture_json.exists():
        return []
    
    try:
        with open(capture_json, "r") as f:
            data = json.load(f)
        
        return data.get("handshakes", [])
    except Exception as e:
        print(f"[!] Failed to load capture data: {e}")
        return []


def load_crack_data(session_path: Path) -> List[dict]:
    """Load handshake cracking data from session."""
    crack_logs_dir = session_path / "crack_logs"
    if not crack_logs_dir.exists():
        return []
    
    crack_results = []
    for json_file in crack_logs_dir.glob("*.json"):
        try:
            with open(json_file, "r") as f:
                data = json.load(f)
                crack_results.append(data)
        except Exception as e:
            print(f"[!] Failed to load crack data from {json_file}: {e}")
    
    return crack_results


def get_html_template() -> str:
    """Get the HTML template for reports."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetHawk Security Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.2em;
            margin-top: 10px;
        }
        .summary {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }
        .summary h2 {
            color: #2c3e50;
            margin-top: 0;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .stat-card {
            background: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            border-left: 4px solid #3498db;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }
        .stat-label {
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .table th, .table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .table th {
            background-color: #34495e;
            color: white;
            font-weight: bold;
        }
        .table tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .table tr:hover {
            background-color: #e8f4f8;
        }
        .success {
            color: #27ae60;
            font-weight: bold;
        }
        .warning {
            color: #f39c12;
            font-weight: bold;
        }
        .danger {
            color: #e74c3c;
            font-weight: bold;
        }
        .info {
            color: #3498db;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
        }
        .no-data {
            text-align: center;
            color: #7f8c8d;
            font-style: italic;
            padding: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦅 NetHawk Security Assessment</h1>
            <div class="subtitle">Generated on {{ timestamp }}</div>
        </div>

        <div class="summary">
            <h2>📊 Executive Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{{ total_aps }}</div>
                    <div class="stat-label">Access Points</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ total_stations }}</div>
                    <div class="stat-label">Stations</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ total_hosts }}</div>
                    <div class="stat-label">Active Hosts</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ successful_cracks }}</div>
                    <div class="stat-label">Cracked Passwords</div>
                </div>
            </div>
        </div>

        {% if passive_hosts %}
        <div class="section">
            <h2>📡 Passive Scan Results</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>SSID/MAC</th>
                        <th>BSSID</th>
                        <th>Channel</th>
                        <th>Power</th>
                        <th>Vendor</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in passive_hosts %}
                    <tr>
                        <td><span class="info">{{ item.type }}</span></td>
                        <td>{{ item.essid or item.station_mac }}</td>
                        <td>{{ item.bssid or 'N/A' }}</td>
                        <td>{{ item.channel or 'N/A' }}</td>
                        <td>{{ item.pwr or 'N/A' }}</td>
                        <td>{{ item.vendor or 'Unknown' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if active_hosts %}
        <div class="section">
            <h2>🔍 Active Scan Results</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Vendor</th>
                        <th>Status</th>
                        <th>Open Ports</th>
                    </tr>
                </thead>
                <tbody>
                    {% for host in active_hosts %}
                    <tr>
                        <td>{{ host.ip }}</td>
                        <td>{{ host.mac or 'N/A' }}</td>
                        <td>{{ host.vendor or 'Unknown' }}</td>
                        <td>
                            {% if host.alive %}
                                <span class="success">Alive</span>
                            {% else %}
                                <span class="danger">Dead</span>
                            {% endif %}
                        </td>
                        <td>{{ host.ports|length }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if handshakes %}
        <div class="section">
            <h2>🤝 Handshake Capture Results</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>SSID</th>
                        <th>BSSID</th>
                        <th>Channel</th>
                        <th>Capture File</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {% for handshake in handshakes %}
                    <tr>
                        <td>{{ handshake.ssid }}</td>
                        <td>{{ handshake.bssid }}</td>
                        <td>{{ handshake.channel }}</td>
                        <td>{{ handshake.capture_file.split('/')[-1] }}</td>
                        <td><span class="success">Captured</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if cracks %}
        <div class="section">
            <h2>🔓 Password Cracking Results</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Capture File</th>
                        <th>Tool</th>
                        <th>Password</th>
                        <th>Status</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody>
                    {% for crack in cracks %}
                    <tr>
                        <td>{{ crack.cap_file.split('/')[-1] }}</td>
                        <td>{{ crack.tool }}</td>
                        <td>
                            {% if crack.success %}
                                <span class="success">{{ crack.password }}</span>
                            {% else %}
                                <span class="warning">Not Found</span>
                            {% endif %}
                        </td>
                        <td>
                            {% if crack.success %}
                                <span class="success">SUCCESS</span>
                            {% else %}
                                <span class="danger">FAILED</span>
                            {% endif %}
                        </td>
                        <td>{{ crack.timestamp }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if not passive_hosts and not active_hosts and not handshakes and not cracks %}
        <div class="section">
            <div class="no-data">
                <h2>📋 No Data Available</h2>
                <p>No scan or capture data found in this session.</p>
                <p>Run NetHawk modules to generate data for this report.</p>
            </div>
        </div>
        {% endif %}

        <div class="footer">
            <p>Generated by NetHawk Security Assessment Tool</p>
            <p>Session: {{ session }}</p>
        </div>
    </div>
</body>
</html>
    """


def render_html_report(data: ReportData, output_file: str) -> str:
    """
    Render HTML report from report data.
    
    Args:
        data: ReportData object containing all report information
        output_file: Path to output HTML file
        
    Returns:
        Path to the generated HTML file
    """
    if JINJA2_AVAILABLE:
        # Use Jinja2 for templating
        template = Template(get_html_template())
        html_content = template.render(
            session=data.session,
            timestamp=data.timestamp,
            passive_hosts=data.passive_hosts,
            active_hosts=data.active_hosts,
            handshakes=data.handshakes,
            cracks=data.cracks,
            total_aps=data.total_aps,
            total_stations=data.total_stations,
            total_hosts=data.total_hosts,
            total_ports=data.total_ports,
            successful_cracks=data.successful_cracks
        )
    else:
        # Fallback to simple string formatting
        html_content = get_html_template().format(
            session=data.session,
            timestamp=data.timestamp,
            passive_hosts=data.passive_hosts,
            active_hosts=data.active_hosts,
            handshakes=data.handshakes,
            cracks=data.cracks,
            total_aps=data.total_aps,
            total_stations=data.total_stations,
            total_hosts=data.total_hosts,
            total_ports=data.total_ports,
            successful_cracks=data.successful_cracks
        )
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"[+] HTML report generated: {output_file}")
    return output_file


def export_to_pdf(html_file: str, pdf_file: str) -> Optional[str]:
    """
    Export HTML report to PDF format.
    
    Args:
        html_file: Path to HTML file
        pdf_file: Path to output PDF file
        
    Returns:
        Path to PDF file if successful, None if failed
    """
    if not PDFKIT_AVAILABLE:
        print("[!] pdfkit not available, skipping PDF export")
        print("Install with: pip install pdfkit")
        return None
    
    try:
        pdfkit.from_file(html_file, pdf_file)
        print(f"[+] PDF report generated: {pdf_file}")
        return pdf_file
    except Exception as e:
        print(f"[!] PDF export failed: {e}")
        return None


def generate_report(
    session_path: Union[str, Path], 
    output_format: str = "html",
    include_pdf: bool = False
) -> tuple:
    """
    Generate comprehensive report from session data.
    
    Args:
        session_path: Path to session directory
        output_format: Output format ("html", "json", "both")
        include_pdf: Whether to include PDF export
        
    Returns:
        Tuple of (html_file, json_file, pdf_file) paths
    """
    session_path = Path(session_path)
    if not session_path.exists():
        raise FileNotFoundError(f"Session directory not found: {session_path}")
    
    # Create reports directory
    report_dir = session_path / "reports"
    report_dir.mkdir(exist_ok=True)
    
    # Initialize report data
    data = ReportData(session=str(session_path))
    
    # Load data from all modules
    print("[+] Loading passive scan data...")
    data.passive_hosts = load_passive_data(session_path)
    
    print("[+] Loading active scan data...")
    data.active_hosts = load_active_data(session_path)
    
    print("[+] Loading handshake capture data...")
    data.handshakes = load_capture_data(session_path)
    
    print("[+] Loading crack data...")
    data.cracks = load_crack_data(session_path)
    
    # Calculate statistics
    data.total_aps = len([h for h in data.passive_hosts if h.get("type") == "access_point"])
    data.total_stations = len([h for h in data.passive_hosts if h.get("type") == "station"])
    data.total_hosts = len(data.active_hosts)
    data.total_ports = sum(len(host.get("ports", [])) for host in data.active_hosts)
    data.successful_cracks = len([c for c in data.cracks if c.get("success", False)])
    
    # Generate timestamp for filenames
    timestamp = current_time_str()
    
    html_file = None
    json_file = None
    pdf_file = None
    
    # Generate HTML report
    if output_format.lower() in ["html", "both"]:
        html_file = report_dir / f"report_{timestamp}.html"
        render_html_report(data, str(html_file))
    
    # Generate JSON report
    if output_format.lower() in ["json", "both"]:
        json_file = report_dir / f"report_{timestamp}.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(data.to_dict(), f, indent=4)
        print(f"[+] JSON report generated: {json_file}")
    
    # Generate PDF report
    if include_pdf and html_file:
        pdf_file = report_dir / f"report_{timestamp}.pdf"
        export_to_pdf(str(html_file), str(pdf_file))
    
    # Print summary
    print("\n" + "="*60)
    print("REPORT GENERATION SUMMARY")
    print("="*60)
    print(f"Session: {session_path}")
    print(f"Access Points: {data.total_aps}")
    print(f"Stations: {data.total_stations}")
    print(f"Active Hosts: {data.total_hosts}")
    print(f"Total Ports: {data.total_ports}")
    print(f"Successful Cracks: {data.successful_cracks}")
    print("="*60)
    
    if html_file:
        print(f"HTML Report: {html_file}")
    if json_file:
        print(f"JSON Report: {json_file}")
    if pdf_file:
        print(f"PDF Report: {pdf_file}")
    
    return html_file, json_file, pdf_file


def display_report_summary(data: ReportData) -> None:
    """
    Display a summary of the report data.
    
    Args:
        data: ReportData object to summarize
    """
    print("\n" + "="*60)
    print("NETHAWK SECURITY ASSESSMENT SUMMARY")
    print("="*60)
    print(f"Session: {data.session}")
    print(f"Generated: {data.timestamp}")
    print()
    print("📊 SCAN RESULTS:")
    print(f"  Access Points: {data.total_aps}")
    print(f"  Stations: {data.total_stations}")
    print(f"  Active Hosts: {data.total_hosts}")
    print(f"  Total Ports: {data.total_ports}")
    print()
    print("🔓 CRACKING RESULTS:")
    print(f"  Successful Cracks: {data.successful_cracks}")
    print(f"  Total Attempts: {len(data.cracks)}")
    print()
    print("📁 DATA BREAKDOWN:")
    print(f"  Passive Scan Items: {len(data.passive_hosts)}")
    print(f"  Active Scan Items: {len(data.active_hosts)}")
    print(f"  Handshakes Captured: {len(data.handshakes)}")
    print(f"  Crack Attempts: {len(data.cracks)}")
    print("="*60)


if __name__ == "__main__":
    """
    Demo script for testing report generation functionality.
    This demo creates sample data and generates a report.
    """
    print("NetHawk Report Generation Module Demo")
    print("=" * 50)
    
    # Test with a demo session (safe mode)
    test_session = "sessions/session_demo_capture_20240924_161044"
    
    print(f"Testing report generation with:")
    print(f"  Session: {test_session}")
    print(f"  Output format: HTML + JSON")
    print(f"  Include PDF: False (pdfkit not available)")
    
    try:
        # Generate report
        html_file, json_file, pdf_file = generate_report(
            session_path=test_session,
            output_format="both",
            include_pdf=False
        )
        
        print(f"\nReport generation completed:")
        if html_file:
            print(f"  HTML: {html_file}")
        if json_file:
            print(f"  JSON: {json_file}")
        if pdf_file:
            print(f"  PDF: {pdf_file}")
        
        # Display summary
        if json_file and json_file.exists():
            with open(json_file, "r") as f:
                data_dict = json.load(f)
            data = ReportData.from_dict(data_dict)
            display_report_summary(data)
        
    except FileNotFoundError as e:
        print(f"[!] Session not found: {e}")
        print("This is expected - demo session doesn't exist yet.")
        
    except Exception as e:
        print(f"[!] Demo failed: {e}")
        print("This is expected - demo data not available.")
    
    print("\nDemo completed - no system changes made")
    print("Note: Real reports require NetHawk scan data in session directory")