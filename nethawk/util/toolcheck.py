"""
NetHawk Tool Checking Utilities
Auto-generated skeleton - checks PATH for required executables
"""

import shutil
from pathlib import Path
from typing import List, Dict, Optional

# Lazy import to avoid circular dependencies
def _get_logger():
    """Get logger instance lazily to avoid circular imports."""
    try:
        from nethawk.util.logger import get_logger
        return get_logger(__name__)
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from nethawk.util.logger import get_logger
        return get_logger(__name__)

logger = _get_logger()

# Required tools for different operations
REQUIRED_TOOLS = {
    "core": ["python3", "ping"],
    "wireless": ["iw", "ip"],
    "airodump": ["airodump-ng", "aireplay-ng", "aircrack-ng"],
    "cracking": ["hashcat", "cap2hccapx"],
    "scanning": ["nmap"]  # Optional but recommended
}

def check_tool_exists(tool_name: str) -> bool:
    """
    Check if a tool exists in PATH.
    
    Args:
        tool_name: Name of the tool to check
        
    Returns:
        True if tool exists, False otherwise
    """
    return shutil.which(tool_name) is not None

def check_tool_group(tool_group: str) -> Dict[str, bool]:
    """
    Check all tools in a specific group.
    
    Args:
        tool_group: Name of the tool group to check
        
    Returns:
        Dictionary mapping tool names to availability
    """
    if tool_group not in REQUIRED_TOOLS:
        logger.warning(f"Unknown tool group: {tool_group}")
        return {}
    
    results = {}
    for tool in REQUIRED_TOOLS[tool_group]:
        results[tool] = check_tool_exists(tool)
    
    return results

def check_dependencies() -> bool:
    """
    Check all required dependencies.
    
    Returns:
        True if all core dependencies are available
    """
    missing_tools = []
    
    # Check core tools (required)
    core_results = check_tool_group("core")
    for tool, available in core_results.items():
        if not available:
            missing_tools.append(tool)
    
    # Check wireless tools (required for wireless operations)
    wireless_results = check_tool_group("wireless")
    for tool, available in wireless_results.items():
        if not available:
            missing_tools.append(tool)
    
    if missing_tools:
        logger.error(f"Missing required tools: {', '.join(missing_tools)}")
        return False
    
    # Check optional tools and warn
    optional_groups = ["airodump", "cracking", "scanning"]
    for group in optional_groups:
        group_results = check_tool_group(group)
        missing_optional = [tool for tool, available in group_results.items() if not available]
        if missing_optional:
            logger.warning(f"Missing optional tools for {group}: {', '.join(missing_optional)}")
    
    return True

def get_tool_path(tool_name: str) -> Optional[str]:
    """
    Get the full path to a tool.
    
    Args:
        tool_name: Name of the tool
        
    Returns:
        Full path to tool or None if not found
    """
    return shutil.which(tool_name)

def get_installation_commands() -> Dict[str, str]:
    """
    Get installation commands for missing tools.
    
    Returns:
        Dictionary mapping tool groups to installation commands
    """
    return {
        "core": "sudo apt update && sudo apt install python3 iputils-ping",
        "wireless": "sudo apt install iw iproute2",
        "airodump": "sudo apt install aircrack-ng",
        "cracking": "sudo apt install hashcat hcxtools",
        "scanning": "sudo apt install nmap"
    }
