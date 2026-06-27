"""
Network Parser Module.
Converts raw dictionary scans into structured ScannedNetwork models and performs OUI vendor lookups.
"""
from dataclasses import dataclass
import json
import logging
from pathlib import Path
from typing import Dict, List, Any
import requests
from utils.helpers import normalize_mac

logger = logging.getLogger("WiGuard.NetworkParser")

# Small offline database of common OUI prefixes (first 3 octets)
COMMON_OUIS: Dict[str, str] = {
    "00:00:0C": "Cisco Systems",
    "00:14:22": "Dell Inc.",
    "00:1A:11": "Google Inc.",
    "00:1C:BF": "Intel Corporation",
    "00:25:90": "Super Micro Computer",
    "00:90:7F": "WatchGuard Technologies",
    "04:18:D6": "Ubiquiti Networks",
    "08:00:27": "Oracle (VirtualBox)",
    "0C:85:25": "Hewlett Packard Enterprise",
    "10:00:00": "Apple Inc.",
    "18:E8:29": "TP-Link Technologies",
    "24:0A:C4": "Espressif Systems",
    "3C:37:86": "Netgear Inc.",
    "44:E1:37": "Arris Group",
    "50:6F:9A": "Samsung Electronics",
    "70:3A:CB": "XiaoMi Communications",
    "84:16:F9": "Huawei Technologies",
    "A4:2B:B0": "ASUSTek Computer",
    "A8:5E:45": "Linksys",
    "B4:75:0E": "D-Link Corporation",
    "C0:25:67": "Amazon Technologies",
    "E4:A7:C5": "Sagemcom Broadband",
    "F4:3E:61": "Broadcom"
}

@dataclass
class ScannedNetwork:
    """Represents a WiFi access point detected during a scan."""
    ssid: str
    bssid: str
    signal: int          # dBm
    channel: int
    encryption: str
    vendor: str = "Unknown"

class VendorLookup:
    """Handles MAC address OUI vendor resolution with caching and online updating."""

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            self.db_path = Path(__file__).parent / "oui_db.json"
        else:
            self.db_path = db_path
            
        self.vendors: Dict[str, str] = COMMON_OUIS.copy()
        self.load()

    def load(self) -> None:
        """Loads cached OUI database from JSON."""
        try:
            if self.db_path.exists():
                with open(self.db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        # Merge loaded data with common defaults
                        self.vendors.update(data)
                        logger.info("Loaded %d OUI vendor mappings", len(self.vendors))
            else:
                self.save()
        except Exception as e:
            logger.error("Failed to load OUI database: %s", e)

    def save(self) -> None:
        """Saves current database to JSON file."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self.vendors, f, indent=2)
        except Exception as e:
            logger.error("Failed to save OUI database: %s", e)

    def lookup(self, mac: str) -> str:
        """Looks up the manufacturer of a MAC address by its OUI prefix."""
        norm_mac = normalize_mac(mac)
        # OUI is the first 8 characters (XX:XX:XX)
        oui = norm_mac[:8]
        return self.vendors.get(oui, "Unknown Vendor")

    def update_from_web(self) -> bool:
        """Downloads a fresh list of OUI mappings from standard IEEE repository."""
        logger.info("Downloading IEEE OUI dataset...")
        try:
            # IEEE official txt registry
            url = "https://standards-oui.ieee.org/oui/oui.txt"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                new_vendors: Dict[str, str] = {}
                # Parse IEEE OUI txt output
                # Example line:
                # 00-18-0A   (hex)		Cisco Systems, Inc.
                lines = response.text.splitlines()
                pattern = re_compile = r'^\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$'
                import re
                compiled = re.compile(pattern)
                
                for line in lines:
                    match = compiled.match(line)
                    if match:
                        o1, o2, o3, vendor = match.groups()
                        oui = f"{o1}:{o2}:{o3}".upper()
                        new_vendors[oui] = vendor.strip()
                        
                if new_vendors:
                    self.vendors.update(new_vendors)
                    self.save()
                    logger.info("OUI database updated with %d manufacturers", len(self.vendors))
                    return True
            logger.warning("Failed to update OUI database: non-200 response.")
            return False
        except Exception as e:
            logger.error("Error updating OUI database from web: %s", e)
            return False

# Global instance
vendor_lookup = VendorLookup()

def parse_scan_results(raw_networks: List[Dict[str, Any]]) -> List[ScannedNetwork]:
    """Converts list of raw dicts into ScannedNetwork objects with vendor tags."""
    scanned_list: List[ScannedNetwork] = []
    for raw in raw_networks:
        bssid = normalize_mac(raw["bssid"])
        vendor = vendor_lookup.lookup(bssid)
        scanned_list.append(ScannedNetwork(
            ssid=raw["ssid"],
            bssid=bssid,
            signal=raw["signal"],
            channel=raw["channel"],
            encryption=raw["encryption"],
            vendor=vendor
        ))
    return scanned_list
