"""
Main Risk Engine module for WiGuard.
Combines multiple detection vectors, calculates a risk score (0-100),
assigns threat status, and logs alerts to database and files.
"""
import logging
from typing import List, Dict, Tuple, Any
from scanner.network_parser import ScannedNetwork
from database.database import db_manager
from database.models import SecurityAlert, ScanHistory
from utils.helpers import format_timestamp
from utils.constants import (
    WEIGHT_DUPLICATE_SSID,
    WEIGHT_ENCRYPTION_DOWNGRADE,
    WEIGHT_VENDOR_MISMATCH,
    WEIGHT_SIGNAL_ANOMALY,
    WEIGHT_CHANNEL_CHANGE,
    RISK_SAFE,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL
)
from detector.duplicate_detector import DuplicateDetector
from detector.vendor_detector import VendorDetector
from detector.encryption_detector import EncryptionDetector
from detector.signal_detector import SignalDetector
from detector.channel_detector import ChannelDetector
from config.config_loader import config_loader

logger = logging.getLogger("WiGuard.RiskEngine")

class RiskEngine:
    """Orchestrates security scanners, aggregates scores, and issues alerts."""

    def __init__(self) -> None:
        self.dup_detector = DuplicateDetector()
        self.vendor_detector = VendorDetector()
        self.enc_detector = EncryptionDetector()
        self.sig_detector = SignalDetector()
        self.chan_detector = ChannelDetector()

    def get_risk_status(self, score: int) -> str:
        """Categorizes numerical risk score into descriptive categories."""
        if score < 20:
            return RISK_SAFE
        elif score < 40:
            return RISK_LOW
        elif score < 60:
            return RISK_MEDIUM
        elif score < 80:
            return RISK_HIGH
        return RISK_CRITICAL

    def evaluate_networks(self, networks: List[ScannedNetwork]) -> List[Dict[str, Any]]:
        """Processes scanned networks, assesses risk vectors, and saves history/alerts."""
        evaluated: List[Dict[str, Any]] = []
        timestamp = format_timestamp()
        
        # Pre-calculate duplicate SSIDs
        duplicates = self.dup_detector.analyze(networks)
        risk_threshold = config_loader.get("risk_threshold", 50)

        for net in networks:
            score = 0
            reasons: List[str] = []
            alerts_triggered: List[Tuple[str, str]] = []  # List of (alert_type, reason)

            # 1. Duplicate SSID check
            is_dup = net.ssid in duplicates
            if is_dup:
                score += WEIGHT_DUPLICATE_SSID
                reason_str = f"SSID '{net.ssid}' has duplicate access points visible."
                reasons.append(reason_str)
                alerts_triggered.append(("Duplicate SSID", reason_str))

            # 2. Vendor validation check
            is_vendor_mismatch, vendor_reason = self.vendor_detector.analyze(net)
            if is_vendor_mismatch:
                score += WEIGHT_VENDOR_MISMATCH
                reasons.append(vendor_reason)
                alerts_triggered.append(("Vendor Mismatch", vendor_reason))

            # 3. Encryption Downgrade check
            is_enc_downgrade, enc_reason = self.enc_detector.analyze(net, networks)
            if is_enc_downgrade:
                score += WEIGHT_ENCRYPTION_DOWNGRADE
                reasons.append(enc_reason)
                alerts_triggered.append(("Encryption Downgrade", enc_reason))

            # 4. Signal Anomaly check
            is_sig_anomaly, sig_reason = self.sig_detector.analyze(net)
            if is_sig_anomaly:
                score += WEIGHT_SIGNAL_ANOMALY
                reasons.append(sig_reason)
                alerts_triggered.append(("Signal Anomaly", sig_reason))

            # 5. Channel Change check
            is_chan_change, chan_reason = self.chan_detector.analyze(net)
            if is_chan_change:
                score += WEIGHT_CHANNEL_CHANGE
                reasons.append(chan_reason)
                alerts_triggered.append(("Channel Shift", chan_reason))

            # Cap risk score at 100
            score = min(100, score)
            status = self.get_risk_status(score)
            
            # Log scan history to database
            history_record = ScanHistory(
                id=None,
                timestamp=timestamp,
                ssid=net.ssid,
                bssid=net.bssid,
                vendor=net.vendor,
                encryption=net.encryption,
                signal=net.signal,
                channel=net.channel,
                risk_score=score,
                risk_status=status
            )
            db_manager.add_scan_history(history_record)

            # If risk exceeds threshold, log a security alert to database
            if score >= risk_threshold and score > 0:
                reasons_joined = " | ".join(reasons)
                alert_record = SecurityAlert(
                    id=None,
                    timestamp=timestamp,
                    ssid=net.ssid,
                    bssid=net.bssid,
                    alert_type="Evil Twin Threat",
                    risk_score=score,
                    reason=reasons_joined,
                    resolved=0
                )
                db_manager.add_alert(alert_record)
                logger.warning(
                    "[ALERT] Evil Twin Threat detected! SSID: %s | BSSID: %s | Risk Score: %d | Reasons: %s",
                    net.ssid, net.bssid, score, reasons_joined
                )

            evaluated.append({
                "network": net,
                "score": score,
                "status": status,
                "reasons": reasons
            })

        return evaluated
