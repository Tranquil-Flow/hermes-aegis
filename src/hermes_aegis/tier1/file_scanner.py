"""Workspace file write scanner for Tier 1.

Monkey-patches os.open and builtins.open to intercept file writes in /workspace
and scan for secrets. This is best-effort protection - direct syscalls and
compiled extensions bypass this.
"""
from __future__ import annotations

import builtins
import os
import sys
import warnings
from pathlib import Path
from typing import Any, Callable

from hermes_aegis.audit.trail import AuditTrail
from hermes_aegis.patterns.secrets import scan_for_secrets


# Global state for file scanner
_original_builtin_open: Callable | None = None
_original_os_open: Callable | None = None
_audit_trail: AuditTrail | None = None
_vault_values: list[str] = []
_monitored_path: Path = Path("/workspace")
_max_file_size: int = 10 * 1024 * 1024  # 10MB limit for scanning


class FileWriteWrapper:
    """Wrapper for file objects to scan content on close."""
    
    def __init__(self, file_obj: Any, filepath: str, mode: str) -> None:
        self._file = file_obj
        self._filepath = filepath
        self._mode = mode
        self._should_scan = self._is_write_mode(mode) and self._should_monitor_path(filepath)
    
    def _is_write_mode(self, mode: str) -> bool:
        """Check if file is opened in write mode."""
        # Handle mode as string or int
        if isinstance(mode, str):
            return any(m in mode for m in ['w', 'a', '+'])
        # For os.open flags
        return bool(mode & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT))
    
    def _should_monitor_path(self, filepath: str) -> bool:
        """Check if filepath is under monitored directory."""
        try:
            path = Path(filepath).resolve()
            return _monitored_path in path.parents or path == _monitored_path
        except Exception:
            return False
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - scan file on close."""
        # Close the file first to flush all writes
        if hasattr(self._file, '__exit__'):
            result = self._file.__exit__(exc_type, exc_val, exc_tb)
        else:
            if hasattr(self._file, 'close'):
                self._file.close()
            result = None
        
        # Then scan after file is closed and flushed
        if self._should_scan and exc_type is None:
            self._scan_file()
        
        return result
    
    def close(self) -> None:
        """Close the file and scan for secrets."""
        # Close file first to flush writes
        if hasattr(self._file, 'close'):
            self._file.close()
        
        # Then scan
        if self._should_scan:
            self._scan_file()
    
    def _scan_file(self) -> None:
        """Scan the file for secrets after write."""
        if _audit_trail is None:
            return
        
        try:
            # Check file size first
            path = Path(self._filepath)
            if not path.exists():
                return
            
            if path.stat().st_size > _max_file_size:
                # Skip large files
                return
            
            # Try to read and scan the file
            try:
                content = path.read_text(encoding='utf-8', errors='ignore')
            except (UnicodeDecodeError, PermissionError, OSError):
                # Skip binary files or files we can't read
                return
            
            # Scan for secrets
            matches = scan_for_secrets(content, exact_values=_vault_values)
            
            if matches:
                # Log violation to audit trail
                pattern_names = list(set(m.pattern_name for m in matches))
                
                # Log to audit trail
                _audit_trail.log(
                    tool_name="file_write_scanner",
                    args_redacted={
                        "filepath": str(self._filepath),
                        "patterns_detected": pattern_names,
                        "match_count": len(matches),
                    },
                    decision="SECRET_DETECTED",
                    middleware="FileWriteScanner",
                )
                
                # Warn user
                warning_msg = (
                    f"WARNING: Secret(s) detected in file write to {self._filepath}\n"
                    f"Patterns detected: {', '.join(pattern_names)}\n"
                    f"Match count: {len(matches)}\n"
                    f"This has been logged to the audit trail."
                )
                warnings.warn(warning_msg, category=SecurityWarning, stacklevel=3)
        
        except Exception as e:
            # Don't break file operations if scanning fails
            if _audit_trail is not None:
                try:
                    _audit_trail.log(
                        tool_name="file_write_scanner",
                        args_redacted={
                            "filepath": str(self._filepath),
                            "error": str(e),
                        },
                        decision="SCAN_ERROR",
                        middleware="FileWriteScanner",
                    )
                except Exception:
                    pass  # Silently fail if audit logging fails
    
    def __getattr__(self, name: str) -> Any:
        """Delegate all other attributes to wrapped file."""
        return getattr(self._file, name)
    
    def __iter__(self):
        """Support iteration."""
        return iter(self._file)
    
    def __next__(self):
        """Support iteration."""
        return next(self._file)


class SecurityWarning(UserWarning):
    """Warning category for security-related issues."""
    pass


def install_file_write_scanner(
    audit_trail: AuditTrail,
    vault_values: list[str] | None = None,
    monitored_path: str = "/workspace",
    max_file_size: int = 10 * 1024 * 1024,
) -> None:
    """Install the file write scanner.
    
    Args:
        audit_trail: AuditTrail instance to log violations
        vault_values: List of exact secret values to scan for (optional)
        monitored_path: Directory path to monitor (default: /workspace)
        max_file_size: Maximum file size to scan in bytes (default: 10MB)
    """
    global _original_builtin_open, _original_os_open
    global _audit_trail, _vault_values, _monitored_path, _max_file_size
    
    # Store configuration
    _audit_trail = audit_trail
    _vault_values = vault_values or []
    _monitored_path = Path(monitored_path).resolve()
    _max_file_size = max_file_size
    
    # Save original functions
    _original_builtin_open = builtins.open
    _original_os_open = os.open
    
    # Replace with scanning versions
    builtins.open = _scanning_open
    os.open = _scanning_os_open


def uninstall_file_write_scanner() -> None:
    """Remove the file write scanner and restore original functions."""
    global _original_builtin_open, _original_os_open
    
    if _original_builtin_open is not None:
        builtins.open = _original_builtin_open
        _original_builtin_open = None
    
    if _original_os_open is not None:
        os.open = _original_os_open
        _original_os_open = None


def _scanning_open(file, mode='r', *args, **kwargs) -> Any:
    """Intercept builtins.open and wrap file objects for scanning."""
    if _original_builtin_open is None:
        raise RuntimeError("File scanner not properly installed")
    
    # Open file with original function
    file_obj = _original_builtin_open(file, mode, *args, **kwargs)
    
    # Wrap if write mode and in monitored path
    wrapper = FileWriteWrapper(file_obj, str(file), mode)
    
    # Return wrapper if should scan, otherwise return original
    if wrapper._should_scan:
        return wrapper
    return file_obj


def _scanning_os_open(path, flags, *args, **kwargs) -> int:
    """Intercept os.open - note this returns a file descriptor, not object.
    
    For os.open, we can't easily wrap since it returns an int fd.
    We'll rely on builtins.open monitoring instead, which is more common.
    Most code uses builtins.open rather than os.open directly.
    """
    if _original_os_open is None:
        raise RuntimeError("File scanner not properly installed")
    
    # For now, just pass through - monitoring os.open is complex
    # since it returns a file descriptor, not a file object
    return _original_os_open(path, flags, *args, **kwargs)
