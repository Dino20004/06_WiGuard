"""
Data models representing database entities in WiGuard.
"""
from dataclasses import dataclass
from datetime import datetime

@dataclass
class TrustedNetwork:
    """Represents a trusted WiFi network baseline."""
    id: int | None
    ssid: str
    bssid: str
    vendor: str
    encryption: str
    signal_baseline: int
    channel: int
    date_added: str

@dataclass
class ScanHistory:
    """Represents a historic record of a scanned network."""
    id: int | None
    timestamp: str
    ssid: str
    bssid: str
    vendor: str
    encryption: str
    signal: int
    channel: int
    risk_score: int
    risk_status: str

@dataclass
class SecurityAlert:
    """Represents a detected security alert."""
    id: int | None
    timestamp: str
    ssid: str
    bssid: str
    alert_type: str
    risk_score: int
    reason: str
    resolved: int  # 0 for active, 1 for resolved
