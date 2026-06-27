"""
Duplicate SSID detector module.
Identifies if there are multiple active Access Points advertising the exact same SSID with different BSSIDs.
"""
import logging
from typing import List, Dict
from scanner.network_parser import ScannedNetwork

logger = logging.getLogger("WiGuard.DuplicateDetector")

class DuplicateDetector:
    """Detects access points with duplicate SSIDs but distinct BSSIDs."""

    def analyze(self, networks: List[ScannedNetwork]) -> Dict[str, List[ScannedNetwork]]:
        """Analyzes scan list and returns a dict mapping duplicate SSIDs to their AP objects.
        
        Example return:
        {
            "OfficeNet": [ScannedNetwork(bssid=A), ScannedNetwork(bssid=B)]
        }
        """
        ssid_map: Dict[str, List[ScannedNetwork]] = {}
        for net in networks:
            if not net.ssid or net.ssid == "<Hidden SSID>":
                continue
            ssid_map.setdefault(net.ssid, []).append(net)
            
        duplicates = {ssid: nets for ssid, nets in ssid_map.items() if len(nets) > 1}
        
        if duplicates:
            logger.warning("Duplicate SSIDs detected: %s", list(duplicates.keys()))
            
        return duplicates
