"""
macOS WiFi network scanner module.
Runs the Apple80211 airport tool and parses its output.
"""
import subprocess
import logging
import re
from typing import List, Dict, Any
from utils.helpers import normalize_mac, normalize_ssid

logger = logging.getLogger("WiGuard.MacScanner")

def run_airport() -> str:
    """Executes the airport utility and returns output."""
    try:
        airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport"
        result = subprocess.run(
            [airport_path, "-s"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=True
        )
        return result.stdout
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.debug("airport command failed or is unavailable: %s", e)
        raise RuntimeError("airport scan failed") from e

def parse_airport_output(stdout: str) -> List[Dict[str, Any]]:
    """Parses airport -s command output."""
    networks: List[Dict[str, Any]] = []
    lines = stdout.splitlines()
    if not lines:
        return networks
        
    # Find columns index from header: SSID BSSID RSSI CHANNEL HT CC SECURITY
    # Since SSID can contain spaces, we can parse lines from right to left:
    # Rightmost is Security, CC, HT, Channel, RSSI, BSSID, and the rest is SSID
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
            
        try:
            # Match BSSID (xx:xx:xx:xx:xx:xx) to split SSID from the rest
            bssid_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
            if not bssid_match:
                continue
                
            bssid = normalize_mac(bssid_match.group(0))
            bssid_idx = line.find(bssid_match.group(0))
            
            ssid = normalize_ssid(line[:bssid_idx].strip())
            
            # Parse components after BSSID
            post_bssid = line[bssid_idx + len(bssid_match.group(0)):].strip()
            # Split by whitespace
            parts = post_bssid.split()
            if len(parts) >= 2:
                rssi = int(parts[0])  # RSSI is negative dBm
                channel = int(parts[1].split(",")[0])  # Handle channel like 36,+1
                
                # Security is the remainder of the fields
                # E.g. WPA2(PSK/AES/AES)
                security = " ".join(parts[4:]) if len(parts) > 4 else "Unknown"
            else:
                rssi = -100
                channel = 1
                security = "Unknown"
                
            networks.append({
                "ssid": ssid,
                "bssid": bssid,
                "signal": rssi,
                "channel": channel,
                "encryption": security
            })
        except Exception as e:
            logger.debug("Failed parsing airport line: %s. Error: %s", line, e)
            continue
            
    return networks

def scan_mac() -> List[Dict[str, Any]]:
    """Initiates a macOS WiFi scan."""
    try:
        stdout = run_airport()
        return parse_airport_output(stdout)
    except Exception as e:
        logger.debug("Failed macOS native scan: %s. Rethrowing.", e)
        raise
