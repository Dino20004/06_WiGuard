"""
Main WiFi Scanner orchestrator for WiGuard.
Detects OS platform, triggers correct scanner, and processes results.
"""
import platform
import logging
from typing import List
from scanner.network_parser import ScannedNetwork, parse_scan_results
from scanner.windows_scanner import scan_windows
from scanner.linux_scanner import scan_linux
from scanner.mac_scanner import scan_mac

logger = logging.getLogger("WiGuard.WifiScanner")

def scan_simulated() -> List[ScannedNetwork]:
    """Returns simulated WiFi networks for development, testing, and VMs without adapters."""
    logger.info("Using simulated WiFi scan results.")
    raw_simulated = [
        {
            "ssid": "OfficeNet",
            "bssid": "00:14:22:01:23:45",
            "signal": -45,
            "channel": 36,
            "encryption": "WPA3-Personal"
        },
        {
            "ssid": "OfficeNet",
            "bssid": "00:14:22:99:99:99",
            "signal": -20,  # Loud signal
            "encryption": "Open",  # Downgraded encryption
            "channel": 1
        },
        {
            "ssid": "GuestWiFi",
            "bssid": "18:E8:29:A1:B2:C3",
            "signal": -60,
            "channel": 6,
            "encryption": "WPA2-Personal"
        },
        {
            "ssid": "HomeWiFi_5G",
            "bssid": "3C:37:86:11:22:33",
            "signal": -50,
            "channel": 149,
            "encryption": "WPA2-Personal"
        },
        {
            "ssid": "UnknownRouter",
            "bssid": "AA:BB:CC:DD:EE:FF",  # Untrusted Vendor
            "signal": -75,
            "channel": 11,
            "encryption": "WPA2-Personal"
        }
    ]
    return parse_scan_results(raw_simulated)

def scan_networks(force_simulate: bool = False) -> List[ScannedNetwork]:
    """Scans for nearby WiFi networks on Windows, Linux, or macOS.
    
    Falls back to simulated data if native utilities fail or are absent.
    """
    if force_simulate:
        return scan_simulated()
        
    system = platform.system().lower()
    logger.info("Detected platform: %s", system)
    
    try:
        if "windows" in system:
            raw_results = scan_windows()
        elif "linux" in system:
            raw_results = scan_linux()
        elif "darwin" in system:
            raw_results = scan_mac()
        else:
            logger.warning("Unsupported OS platform: %s. Falling back to simulation.", system)
            return scan_simulated()
            
        if not raw_results:
            logger.info("No networks found by system scanner. Trying simulation.")
            return scan_simulated()
            
        return parse_scan_results(raw_results)
        
    except Exception as e:
        logger.warning("Native scanner failed: %s. Falling back to simulation.", e)
        return scan_simulated()

if __name__ == "__main__":
    # Test scanner
    nets = scan_networks(force_simulate=True)
    for n in nets:
        print(f"SSID: {n.ssid} | BSSID: {n.bssid} | Signal: {n.signal} dBm | Chan: {n.channel} | Vendor: {n.vendor} | Enc: {n.encryption}")
