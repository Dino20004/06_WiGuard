"""
Windows WiFi network scanner module.
Runs 'netsh wlan show networks mode=bssid' and parses the output.
"""
import subprocess
import logging
from typing import List, Dict, Any
from utils.helpers import normalize_mac, normalize_ssid, signal_percentage_to_dbm

logger = logging.getLogger("WiGuard.WindowsScanner")

def run_netsh() -> str:
    """Executes the netsh command to scan networks and returns stdout."""
    try:
        # Run command with English locale to ensure consistent parsing
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=True
        )
        return result.stdout
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.warning("netsh command failed or is unavailable: %s. Using simulation mode.", e)
        raise RuntimeError("netsh scan failed") from e

def parse_netsh_output(stdout: str) -> List[Dict[str, Any]]:
    """Parses netsh show networks output into structured dicts."""
    networks: List[Dict[str, Any]] = []
    current_net: Dict[str, Any] = {}
    current_bssid: Dict[str, Any] = {}
    
    # Simple line-by-line parser state machine
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
            
        # Parse SSID line
        if line.startswith("SSID "):
            # Save previous network if it exists
            if current_net and "bssids" in current_net and current_net["bssids"]:
                # Yield copies
                for bssid_data in current_net["bssids"]:
                    networks.append({
                        "ssid": current_net["ssid"],
                        "bssid": bssid_data["bssid"],
                        "signal": bssid_data["signal"],
                        "channel": bssid_data["channel"],
                        "encryption": current_net.get("encryption", "Unknown")
                    })
            
            parts = line.split(":", 1)
            ssid_name = parts[1].strip() if len(parts) > 1 else ""
            current_net = {
                "ssid": normalize_ssid(ssid_name),
                "encryption": "Unknown",
                "bssids": []
            }
            current_bssid = {}
            
        elif line.startswith("Authentication"):
            parts = line.split(":", 1)
            if len(parts) > 1 and current_net:
                auth = parts[1].strip()
                current_net["encryption"] = auth
                
        elif line.startswith("Encryption"):
            parts = line.split(":", 1)
            # If Authentication was Open, or Encryption type is WEP etc.
            if len(parts) > 1 and current_net and current_net["encryption"] == "Unknown":
                current_net["encryption"] = parts[1].strip()
                
        elif line.startswith("BSSID "):
            parts = line.split(":", 1)
            if len(parts) > 1 and current_net:
                bssid_val = normalize_mac(parts[1].strip())
                current_bssid = {
                    "bssid": bssid_val,
                    "signal": -100,
                    "channel": 1
                }
                current_net["bssids"].append(current_bssid)
                
        elif line.startswith("Signal"):
            parts = line.split(":", 1)
            if len(parts) > 1 and current_bssid:
                pct_str = parts[1].strip().replace("%", "")
                try:
                    pct = int(pct_str)
                    current_bssid["signal"] = signal_percentage_to_dbm(pct)
                except ValueError:
                    current_bssid["signal"] = -100
                    
        elif line.startswith("Channel"):
            parts = line.split(":", 1)
            if len(parts) > 1 and current_bssid:
                try:
                    current_bssid["channel"] = int(parts[1].strip())
                except ValueError:
                    current_bssid["channel"] = 1

    # Add the last parsed network
    if current_net and "bssids" in current_net and current_net["bssids"]:
        for bssid_data in current_net["bssids"]:
            networks.append({
                "ssid": current_net["ssid"],
                "bssid": bssid_data["bssid"],
                "signal": bssid_data["signal"],
                "channel": bssid_data["channel"],
                "encryption": current_net.get("encryption", "Unknown")
            })
            
    return networks

def scan_windows() -> List[Dict[str, Any]]:
    """Initiates a Windows WiFi scan."""
    try:
        stdout = run_netsh()
        return parse_netsh_output(stdout)
    except Exception as e:
        logger.debug("Failed Windows native scan: %s. Rethrowing for orchestrator fallback.", e)
        raise
