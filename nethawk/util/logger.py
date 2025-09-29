"""
NetHawk Logging Utilities
Production-ready structured, thread-safe logger with Rich console output and JSONL file logging
"""

import json
import os
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Union

from rich.console import Console
from rich.text import Text

console = Console()


class NethawkLogger:
    """
    Thread-safe logger that provides both console output via Rich and JSONL file logging.
    
    Features:
    - Thread-safe logging with locks
    - Rich console output with colors
    - JSONL file logging for audit trails
    - Configurable verbosity and output options
    - Atomic writes with fsync support
    """
    
    def __init__(
        self, 
        session_path: Optional[Path] = None, 
        name: str = "nethawk",
        debug: bool = False,
        to_stdout: bool = True
    ):
        """
        Initialize NethawkLogger.
        
        Args:
            session_path: Path to session directory. If None, uses ~/.nethawk/logs/
            name: Logger name for identification
            debug: Enable debug verbosity
            to_stdout: Enable console output (disable for tests)
        """
        self.name = name
        self.debug = debug
        self.to_stdout = to_stdout
        self._lock = threading.Lock()
        
        # Determine log file path
        if session_path:
            if isinstance(session_path, str):
                session_path = Path(session_path)
            self.log_file = session_path / "logs" / f"{name}.jsonl"
        else:
            home_dir = Path.home()
            log_dir = home_dir / ".nethawk" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            self.log_file = log_dir / f"{name}.jsonl"
        
        # Ensure log directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
    
    def _log(self, level: str, message: str, event: Optional[str] = None, **meta: Any) -> None:
        """
        Internal logging method that handles both console and file output.
        
        Args:
            level: Log level (info, warning, error, event)
            message: Log message
            event: Optional event name for structured logging
            **meta: Additional metadata
        """
        timestamp = datetime.now().isoformat()
        
        # Prepare log entry
        log_entry = {
            "ts": timestamp,
            "level": level,
            "message": message,
            "logger": self.name
        }
        
        if event:
            log_entry["event"] = event
        
        if meta:
            # Convert non-serializable values to strings
            serializable_meta = {}
            for key, value in meta.items():
                try:
                    json.dumps(value)  # Test if serializable
                    serializable_meta[key] = value
                except (TypeError, ValueError):
                    serializable_meta[key] = str(value)
            log_entry["meta"] = serializable_meta
        
        # Thread-safe file writing
        with self._lock:
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(log_entry) + '\n')
                    f.flush()  # Ensure immediate write
                    os.fsync(f.fileno())  # Force filesystem sync
            except Exception as e:
                # Fallback to stderr if file writing fails
                print(f"Logger error: {e}", file=sys.stderr)
        
        # Console output with Rich
        if self.to_stdout:
            self._console_output(level, message, event, **meta)
    
    def _console_output(self, level: str, message: str, event: Optional[str] = None, **meta: Any) -> None:
        """Output formatted message to console using Rich."""
        # Create colored text based on level
        if level == "error":
            text = Text(message, style="bold red")
        elif level == "warning":
            text = Text(message, style="bold yellow")
        elif level == "info":
            text = Text(message, style="green")
        elif level == "event":
            text = Text(message, style="bold blue")
        else:
            text = Text(message)
        
        # Add event info if present
        if event:
            event_text = Text(f" [{event}]", style="dim")
            text.append(event_text)
        
        # Add metadata if present and in debug mode
        if self.debug and meta:
            meta_text = Text(f" {meta}", style="dim")
            text.append(meta_text)
        
        console.print(text)
    
    def info(self, message: str, **meta: Any) -> None:
        """
        Log an info message.
        
        Args:
            message: Log message
            **meta: Additional metadata
        """
        self._log("info", message, **meta)
    
    def warning(self, message: str, **meta: Any) -> None:
        """
        Log a warning message.
        
        Args:
            message: Log message
            **meta: Additional metadata
        """
        self._log("warning", message, **meta)
    
    def error(self, message: str, **meta: Any) -> None:
        """
        Log an error message.
        
        Args:
            message: Log message
            **meta: Additional metadata
        """
        self._log("error", message, **meta)
    
    def event(self, event_name: str, message: str, **meta: Any) -> None:
        """
        Log a structured event.
        
        Args:
            event_name: Name of the event
            message: Event description
            **meta: Additional metadata
        """
        self._log("event", message, event=event_name, **meta)
    
    def flush(self) -> None:
        """
        Force flush of log file.
        
        This method ensures all pending writes are committed to disk.
        Useful for testing and ensuring log integrity.
        """
        with self._lock:
            try:
                with open(self.log_file, 'a', encoding='utf-8') as f:
                    f.flush()
                    os.fsync(f.fileno())
            except Exception:
                pass  # Ignore flush errors


def get_logger(
    session_path: Optional[Path] = None, 
    name: str = "nethawk",
    debug: bool = False,
    to_stdout: bool = True
) -> NethawkLogger:
    """
    Get a NethawkLogger instance.
    
    Args:
        session_path: Path to session directory. If None, uses ~/.nethawk/logs/
        name: Logger name for identification
        debug: Enable debug verbosity
        to_stdout: Enable console output (disable for tests)
        
    Returns:
        NethawkLogger instance
        
    Example:
        >>> logger = get_logger(session_path=Path("sessions/session_001"), name="test")
        >>> logger.info("Test message", user="admin", action="login")
        >>> logger.event("security", "User authentication failed", user="hacker", ip="192.168.1.100")
    """
    return NethawkLogger(session_path, name, debug, to_stdout)


# Convenience functions for backward compatibility
def log_operation(operation: str, details: Dict[str, Any], session_path: Path) -> None:
    """
    Log a specific operation with structured data.
    
    Args:
        operation: Name of the operation
        details: Additional details to log
        session_path: Path to session directory
    """
    logger = get_logger(session_path, "nethawk.operations")
    logger.event("operation", f"Operation: {operation}", **details)


def log_security_event(event_type: str, details: Dict[str, Any], session_path: Path) -> None:
    """
    Log security-related events.
    
    Args:
        event_type: Type of security event
        details: Event details
        session_path: Path to session directory
    """
    logger = get_logger(session_path, "nethawk.security")
    logger.event("security", f"Security Event: {event_type}", event_type=event_type, **details)


# TODO: Implement log rotation
# TODO: Add encryption support for sensitive log data
# TODO: Add log compression for old files
# TODO: Add structured querying capabilities for log analysis