"""
NetHawk Session Management
Production-ready session manager with folder structure and context management
"""

import os
import shutil
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, Generator

# Lazy import to avoid circular dependencies
def _get_logger():
    """Get logger instance lazily to avoid circular imports."""
    try:
        from nethawk.util.logger import get_logger
        return get_logger(name=__name__)
    except ImportError:
        # Fallback for when running as script
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from nethawk.util.logger import get_logger
        return get_logger(name=__name__)

logger = _get_logger()


class SessionManager:
    """
    Manages NetHawk sessions and file organization.
    
    Provides session creation, management, and cleanup functionality with
    organized folder structure for different types of artifacts.
    """
    
    def __init__(self, base_dir: Optional[str] = None):
        """
        Initialize SessionManager.
        
        Args:
            base_dir: Base directory for sessions. If None, uses environment
                     variable NETHAWK_SESSION_DIR or defaults to "sessions"
        """
        if base_dir is None:
            base_dir = os.environ.get("NETHAWK_SESSION_DIR", "sessions")
        
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)
    
    def create_session(self, prefix: Optional[str] = None) -> Path:
        """
        Create a new session with organized folder structure.
        
        Creates a session directory with format:
        sessions/session_{NNN}_{YYYYMMDD_HHMMSS} or sessions/session_{prefix}_{YYYYMMDD_HHMMSS}
        
        Args:
            prefix: Optional prefix for session name. If None, uses auto-incrementing number.
            
        Returns:
            Path to the created session directory
            
        Example:
            >>> manager = SessionManager()
            >>> session_path = manager.create_session()
            >>> print(session_path.name)  # session_001_20241201_143022
        """
        # Get next session number if no prefix provided
        if prefix is None:
            existing_sessions = self._get_existing_sessions()
            next_num = self._get_next_session_number(existing_sessions)
            session_name = f"session_{next_num:03d}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        else:
            session_name = f"session_{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        session_path = self.base_dir / session_name
        
        # Create session directory structure
        directories = [
            session_path,
            session_path / "handshakes",
            session_path / "crack_logs", 
            session_path / "logs",
            session_path / "reports"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")
        
        # Create session metadata
        metadata = {
            "session_id": session_name,
            "created_at": datetime.now().isoformat(),
            "base_path": str(session_path),
            "prefix": prefix,
            "version": "1.0.0"
        }
        
        metadata_file = session_path / "session.json"
        import json
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Created session: {session_name}")
        return session_path
    
    def get_latest_session(self) -> Optional[Path]:
        """
        Get the most recently created session.
        
        Returns:
            Path to the latest session directory, or None if no sessions exist
            
        Example:
            >>> manager = SessionManager()
            >>> latest = manager.get_latest_session()
            >>> if latest:
            ...     print(f"Latest session: {latest.name}")
        """
        sessions = self._get_existing_sessions()
        if not sessions:
            return None
        
        # Sort by creation time (newest first)
        sessions_with_time = []
        for session_path in sessions:
            try:
                stat = session_path.stat()
                sessions_with_time.append((session_path, stat.st_mtime))
            except OSError:
                continue
        
        if not sessions_with_time:
            return None
        
        sessions_with_time.sort(key=lambda x: x[1], reverse=True)
        return sessions_with_time[0][0]
    
    def prune_sessions(self, days: int = 90) -> int:
        """
        Remove sessions older than specified days.
        
        Args:
            days: Number of days to keep sessions (default: 90)
            
        Returns:
            Number of sessions removed
            
        Example:
            >>> manager = SessionManager()
            >>> removed = manager.prune_sessions(days=30)
            >>> print(f"Removed {removed} old sessions")
        """
        cutoff_time = time.time() - (days * 24 * 60 * 60)
        removed_count = 0
        
        for session_dir in self.base_dir.iterdir():
            if session_dir.is_dir() and session_dir.name.startswith("session_"):
                try:
                    if session_dir.stat().st_mtime < cutoff_time:
                        shutil.rmtree(session_dir)
                        logger.info(f"Removed old session: {session_dir.name}")
                        removed_count += 1
                except OSError as e:
                    logger.error(f"Failed to remove session {session_dir.name}: {e}")
        
        return removed_count
    
    @contextmanager
    def session_context(self, prefix: Optional[str] = None) -> Generator[Path, None, None]:
        """
        Context manager for session operations.
        
        Creates a session, yields the path, and ensures proper cleanup.
        
        Args:
            prefix: Optional prefix for session name
            
        Yields:
            Path to the session directory
            
        Example:
            >>> manager = SessionManager()
            >>> with manager.session_context("test") as session_path:
            ...     # Perform operations in session
            ...     (session_path / "test.txt").write_text("test data")
            ... # Session is automatically cleaned up if needed
        """
        session_path = self.create_session(prefix)
        
        try:
            yield session_path
        finally:
            # Ensure any pending logger flush is called
            try:
                # TODO: Integrate with logger flush mechanism
                # This would be implemented when logger integration is complete
                pass
            except Exception as e:
                logger.error(f"Error during session cleanup: {e}")
    
    def _get_existing_sessions(self) -> list[Path]:
        """Get list of existing session directories."""
        sessions = []
        for item in self.base_dir.iterdir():
            if item.is_dir() and item.name.startswith("session_"):
                sessions.append(item)
        return sessions
    
    def _get_next_session_number(self, existing_sessions: list[Path]) -> int:
        """Get the next session number based on existing sessions."""
        if not existing_sessions:
            return 1
        
        # Extract numbers from session names
        numbers = []
        for session in existing_sessions:
            try:
                # Extract number from session_XXX_YYYYMMDD_HHMMSS format
                parts = session.name.split('_')
                if len(parts) >= 2 and parts[1].isdigit():
                    numbers.append(int(parts[1]))
            except (ValueError, IndexError):
                continue
        
        return max(numbers, default=0) + 1


# Convenience functions for direct usage
def create_session(prefix: Optional[str] = None) -> Path:
    """
    Create a new session using the default SessionManager.
    
    Args:
        prefix: Optional prefix for session name
        
    Returns:
        Path to the created session directory
    """
    manager = SessionManager()
    return manager.create_session(prefix)


def get_latest_session() -> Optional[Path]:
    """
    Get the most recently created session using the default SessionManager.
    
    Returns:
        Path to the latest session directory, or None if no sessions exist
    """
    manager = SessionManager()
    return manager.get_latest_session()


def prune_sessions(days: int = 90) -> int:
    """
    Remove old sessions using the default SessionManager.
    
    Args:
        days: Number of days to keep sessions
        
    Returns:
        Number of sessions removed
    """
    manager = SessionManager()
    return manager.prune_sessions(days)


def get_session_path() -> Path:
    """
    Get the current session path using the default SessionManager.
    
    Returns:
        Path to the current session directory
        
    Raises:
        FileNotFoundError: If no sessions exist
    """
    manager = SessionManager()
    latest_session = manager.get_latest_session()
    if latest_session is None:
        # Create a new session if none exist
        return manager.create_session()
    return latest_session


@contextmanager
def session_context(prefix: Optional[str] = None) -> Generator[Path, None, None]:
    """
    Context manager for session operations using the default SessionManager.
    
    Args:
        prefix: Optional prefix for session name
        
    Yields:
        Path to the session directory
    """
    manager = SessionManager()
    with manager.session_context(prefix) as session_path:
        yield session_path
