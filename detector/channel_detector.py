"""
Channel change detector module.
Identifies unexpected channel assignments or shifts from the trusted configuration baseline.
"""
import logging
from typing import Tuple
from scanner.network_parser import ScannedNetwork
from database.database import db_manager

logger = logging.getLogger("WiGuard.ChannelDetector")

class ChannelDetector:
    """Detects unexpected wireless channel shifts."""

    def analyze(self, net: ScannedNetwork) -> Tuple[bool, str]:
        """Compares current channel against trusted configuration baseline.
        
        Returns:
            Tuple[bool, str]: (is_changed, description_reason)
        """
        trusted = db_manager.get_trusted_network_by_bssid(net.bssid)
        if not trusted:
            return False, ""
            
        if trusted.channel != net.channel:
            reason = f"Channel shift detected on BSSID {net.bssid} ({net.ssid}). Trusted: Channel {trusted.channel}, Current: Channel {net.channel}"
            logger.warning(reason)
            return True, reason
            
        return False, ""
