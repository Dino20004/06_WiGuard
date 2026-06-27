"""
Encryption downgrade detector module.
Identifies if an access point has dropped its encryption level compared to the trusted baseline
or if a duplicate SSID lacks security.
"""
import logging
from typing import Tuple, List
from scanner.network_parser import ScannedNetwork
from database.database import db_manager

logger = logging.getLogger("WiGuard.EncryptionDetector")

class EncryptionDetector:
    """Checks for encryption downgrades and unencrypted twins."""

    def analyze(self, net: ScannedNetwork, all_scanned: List[ScannedNetwork]) -> Tuple[bool, str]:
        """Analyzes encryption security for a scanned network.
        
        Returns:
            Tuple[bool, str]: (is_downgraded, description_reason)
        """
        # Scenario 1: Check against trusted database baseline
        trusted = db_manager.get_trusted_network_by_bssid(net.bssid)
        if trusted:
            # Simple security level comparisons
            # Standard order: Open < WEP < WPA < WPA2 < WPA3
            levels = ["open", "wep", "wpa", "wpa2", "wpa3"]
            
            def get_level(enc_str: str) -> int:
                enc_lower = enc_str.lower()
                for i, name in enumerate(levels):
                    if name in enc_lower:
                        return i
                return 0  # Treat default/empty/unknown as Open level
                
            trusted_lvl = get_level(trusted.encryption)
            current_lvl = get_level(net.encryption)
            
            if current_lvl < trusted_lvl:
                reason = f"Encryption downgrade detected on {net.bssid} ({net.ssid}). Trusted: {trusted.encryption}, Scanned: {net.encryption}"
                logger.warning(reason)
                return True, reason

        # Scenario 2: Check duplicate networks in the same scan
        # If there's another network with the same SSID that is encrypted, but this one is Open
        is_open = "open" in net.encryption.lower() or not net.encryption or net.encryption == "None"
        if is_open:
            for other in all_scanned:
                if other.ssid == net.ssid and other.bssid != net.bssid:
                    other_open = "open" in other.encryption.lower() or not other.encryption or other.encryption == "None"
                    if not other_open:
                        reason = f"Suspicious Open access point '{net.ssid}' ({net.bssid}) alongside encrypted twin ({other.bssid})"
                        logger.warning(reason)
                        return True, reason
                        
        return False, ""
