"""
Validators for WiGuard user inputs and database configuration.
"""
from pathlib import Path
import os
from utils.helpers import is_valid_bssid

def validate_ssid(ssid: str) -> bool:
    """Checks if the SSID is not empty and has a valid length (1-32 characters)."""
    if not ssid:
        return False
    return 1 <= len(ssid) <= 32

def validate_bssid(bssid: str) -> bool:
    """Checks if BSSID is valid."""
    return is_valid_bssid(bssid)

def validate_file_writeable(file_path: str) -> bool:
    """Checks if the destination path can be written to."""
    path = Path(file_path)
    try:
        # Check if parent directory exists or can be created
        path.parent.mkdir(parents=True, exist_ok=True)
        # Try to open file for appending
        with open(path, "a", encoding="utf-8"):
            pass
        return True
    except Exception:
        return False

def validate_database_file(db_path: str) -> bool:
    """Validates that the database file path is in a writable location and directory exists."""
    return validate_file_writeable(db_path)
