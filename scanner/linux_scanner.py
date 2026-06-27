"""
Linux WiFi network scanner module.
Runs 'nmcli' or 'iwlist' and parses the output.
"""
import subprocess
import logging
from typing import List, Dict, Any
from utils.helpers import normalize_mac, normalize_ssid

logger = logging.getLogger("WiGuard.LinuxScanner")

def run_nmcli() -> str:
    """Executes nmcli command and returns output."""
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "device", "wifi", "list"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=True
        )
        return result.stdout
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.debug("nmcli execution failed: %s", e)
        raise RuntimeError("nmcli failed") from e

def parse_nmcli_output(stdout: str) -> List[Dict[str, Any]]:
    """Parses colon-separated nmcli output.
    
    Format: SSID:BSSID:SIGNAL:CHAN:SECURITY
    Note: BSSID contains colons, so we must parse carefully.
    """
    networks: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
            
        # nmcli -t uses backslash escapes for colons in fields.
        # But we can also parse backwards or split carefully since we know fields.
        # SSID can have colons, BSSID has 5 colons, SIGNAL is a number, CHAN is a number, SECURITY can have colons/spaces.
        # Let's split by unescaped colons or parse backwards.
        try:
            # Let's replace escaped colons temporarily, split, then restore
            # Simple escape replace
            temp_line = line.replace(r"\:", "__COLON__")
            parts = temp_line.split(":")
            if len(parts) < 5:
                continue
                
            # Reconstruction
            # Last field is Security
            security = parts[-1].replace("__COLON__", ":")
            # Second to last is Channel
            channel_str = parts[-2]
            # Third to last is Signal
            signal_str = parts[-3]
            
            # BSSID is 6 segments. It has colons. Let's find it.
            # In nmcli -t output, it escapes colons in SSID but not BSSID.
            # So BSSID will split into 6 parts if we split on raw colons.
            # Let's split on raw colons on the original line.
            raw_parts = line.split(":")
            # If BSSID is standard, it will occupy 6 indices.
            # Let's locate the BSSID in the line.
            # BSSID starts with 2 hex chars.
            # Let's parse with a regular expression for BSSID:
            import re
            bssid_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
            if not bssid_match:
                continue
                
            bssid = normalize_mac(bssid_match.group(0))
            bssid_idx = line.find(bssid_match.group(0))
            
            ssid_raw = line[:bssid_idx].rstrip(":")
            ssid = normalize_ssid(ssid_raw.replace(r"\:", ":"))
            
            remaining = line[bssid_idx + len(bssid_match.group(0)):].lstrip(":")
            rem_parts = remaining.split(":")
            
            if len(rem_parts) >= 3:
                signal_val = int(rem_parts[0])
                # Convert 0-100% to dBm
                from utils.helpers import signal_percentage_to_dbm
                signal = signal_percentage_to_dbm(signal_val)
                channel = int(rem_parts[1])
                encryption = ":".join(rem_parts[2:])
            else:
                signal = -100
                channel = 1
                encryption = "Unknown"
                
            networks.append({
                "ssid": ssid,
                "bssid": bssid,
                "signal": signal,
                "channel": channel,
                "encryption": encryption
            })
        except Exception as e:
            logger.debug("Line parse failed in nmcli: %s for line: %s", e, line)
            continue
            
    return networks

def scan_linux() -> List[Dict[str, Any]]:
    """Initiates a Linux WiFi scan."""
    try:
        stdout = run_nmcli()
        return parse_nmcli_output(stdout)
    except Exception as e:
        logger.debug("Failed Linux nmcli scan: %s. Trying iwlist...", e)
        # We can write an iwlist fallback if needed, but for now we raise
        # to allow simulation fallback.
        raise
