"""
Helper utility functions for WiGuard.
"""
from datetime import datetime
import re

def normalize_mac(mac: str) -> str:
    """Normalizes MAC addresses to uppercase colon-separated format.
    
    Example: aa-bb-cc-dd-ee-ff -> AA:BB:CC:DD:EE:FF
             AABBCCDDEEFF -> AA:BB:CC:DD:EE:FF
    """
    cleaned = re.sub(r'[^a-fA-F0-9]', '', mac).upper()
    if len(cleaned) != 12:
        return mac.upper()  # fallback if malformed
    
    return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))

def normalize_ssid(ssid: str) -> str:
    """Cleans and normalizes SSID strings."""
    if not ssid:
        return "<Hidden SSID>"
    # Remove outer quotes that some OS scan utilities include
    ssid = ssid.strip()
    if (ssid.startswith('"') and ssid.endswith('"')) or (ssid.startswith("'") and ssid.endswith("'")):
        ssid = ssid[1:-1]
    return ssid.strip()

def signal_percentage_to_dbm(percentage: int) -> int:
    """Converts standard 0-100% signal strength to dBm range (approximate).
    
    Formula: dBm = (percentage / 2) - 100
    """
    # Clamp percentage
    pct = max(0, min(100, percentage))
    return int((pct / 2) - 100)

def dbm_to_signal_percentage(dbm: int) -> int:
    """Converts dBm signal strength to 0-100% (approximate)."""
    # Typical dBm ranges from -100 (poor) to -50 or above (excellent)
    if dbm >= -50:
        return 100
    if dbm <= -100:
        return 0
    return int((dbm + 100) * 2)

def format_timestamp(dt: datetime | None = None) -> str:
    """Formats current or given datetime to standard display format."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def is_valid_bssid(bssid: str) -> bool:
    """Validates if a string is a properly formatted MAC address/BSSID."""
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^[0-9A-Fa-f]{12}$')
    return bool(mac_pattern.match(bssid))
