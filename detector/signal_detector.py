"""
Signal anomaly detector module.
Analyzes deviations in signal strength (dBm) compared to trusted baseline levels.
"""
import logging
from typing import Tuple
from scanner.network_parser import ScannedNetwork
from database.database import db_manager
from utils.constants import SIGNAL_DEVIATION_THRESHOLD

logger = logging.getLogger("WiGuard.SignalDetector")

class SignalDetector:
    """Analyzes signal levels for anomalies suggesting proximity attacks."""

    def analyze(self, net: ScannedNetwork) -> Tuple[bool, str]:
        """Compares signal strength against baseline.
        
        Returns:
            Tuple[bool, str]: (is_anomalous, description_reason)
        """
        trusted = db_manager.get_trusted_network_by_bssid(net.bssid)
        if not trusted:
            return False, ""
            
        # Signal is negative dBm, e.g., -60 dBm is weaker than -30 dBm
        # If current signal is much stronger than baseline (e.g. current is -20, baseline is -65)
        # current - baseline = -20 - (-65) = +45 dBm
        deviation = net.signal - trusted.signal_baseline
        
        if deviation >= SIGNAL_DEVIATION_THRESHOLD:
            reason = f"Signal strength anomaly on BSSID {net.bssid} ({net.ssid}). Deviation: +{deviation} dBm (Baseline: {trusted.signal_baseline} dBm, Current: {net.signal} dBm)"
            logger.warning(reason)
            return True, reason
            
        return False, ""
