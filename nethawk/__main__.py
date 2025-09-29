#!/usr/bin/env python3
"""
NetHawk - Professional Linux Reconnaissance Toolkit
Main entry point for the application
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import professional CLI
from nethawk.cli_professional import main

if __name__ == "__main__":
    main()
