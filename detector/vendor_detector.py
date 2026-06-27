"""
Vendor detector module.
Compares manufacturer vendor prefixes of scanned networks against trusted baselines.
"""
import logging
from typing import Dict, Tuple
from scanner.network_parser import ScannedNetwork
from database.database import db_manager

logger = logging.getLogger("WiGuard.VendorDetector")

class VendorDetector:
    """Checks if a scanned network's MAC vendor matches the trusted database configuration."""

    def analyze(self, net: ScannedNetwork) -> Tuple[bool, str]:
        """Analyzes a scanned network against the trusted baseline.
        
        Returns:
            Tuple[bool, str]: (is_mismatch, description_reason)
        """
        trusted = db_manager.get_trusted_network_by_bssid(net.bssid)
        if not trusted:
            # Not in trusted baseline yet - check if there is another trusted AP with same SSID
            # that has a different vendor.
            trusted_list = db_manager.get_trusted_networks()
            same_ssid_trusted = [t for t in trusted_list if t.ssid == net.ssid]
            
            if same_ssid_trusted:
                # There is a trusted baseline for this SSID, but this BSSID is new.
                # Check if vendors match.
                for t in same_ssid_trusted:
                    if t.vendor != net.vendor:
                        reason = f"Vendor mismatch for SSID '{net.ssid}'. Baseline vendor: '{t.vendor}', Current: '{net.vendor}'"
                        logger.warning(reason)
                        return True, reason
            return False, ""
            
        # In baseline - check if current vendor matches trusted vendor
        if trusted.vendor != net.vendor:
            reason = f"MAC Vendor mismatch for BSSID {net.bssid}. Trusted: '{trusted.vendor}', Current: '{net.vendor}'"
            logger.warning(reason)
            return True, reason
            
        return False, ""
