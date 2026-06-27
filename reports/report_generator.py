"""
Report generator module for WiGuard.
Compiles scan results, alerts, and baselines into JSON, CSV, or plain text formats.
"""
import json
import csv
import logging
from pathlib import Path
from typing import List, Dict, Any
from database.database import db_manager
from utils.helpers import format_timestamp

logger = logging.getLogger("WiGuard.ReportGenerator")

class ReportGenerator:
    """Handles compiles and export of security reports."""

    def __init__(self, export_dir: Path | None = None) -> None:
        if export_dir is None:
            # Save inside reports/export directory of package root
            self.export_dir = Path(__file__).parent.parent / "reports" / "export"
        else:
            self.export_dir = Path(export_dir)
            
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def _compile_data(self) -> Dict[str, Any]:
        """Collects database information for compilation."""
        trusted_raw = db_manager.get_trusted_networks()
        alerts_raw = db_manager.get_alerts()
        history_raw = db_manager.get_scan_history(limit=50)

        trusted = [
            {
                "ssid": t.ssid,
                "bssid": t.bssid,
                "vendor": t.vendor,
                "encryption": t.encryption,
                "signal_baseline": t.signal_baseline,
                "channel": t.channel,
                "date_added": t.date_added
            } for t in trusted_raw
        ]

        alerts = [
            {
                "timestamp": a.timestamp,
                "ssid": a.ssid,
                "bssid": a.bssid,
                "alert_type": a.alert_type,
                "risk_score": a.risk_score,
                "reason": a.reason,
                "resolved": "Yes" if a.resolved else "No"
            } for a in alerts_raw
        ]

        history = [
            {
                "timestamp": h.timestamp,
                "ssid": h.ssid,
                "bssid": h.bssid,
                "vendor": h.vendor,
                "encryption": h.encryption,
                "signal": h.signal,
                "channel": h.channel,
                "risk_score": h.risk_score,
                "risk_status": h.risk_status
            } for h in history_raw
        ]

        return {
            "generated_at": format_timestamp(),
            "author": "Dino20004",
            "stats": {
                "total_trusted": len(trusted),
                "total_alerts": len(alerts),
                "active_alerts": len([a for a in alerts_raw if not a.resolved]),
                "total_scans_logged": len(history)
            },
            "trusted_networks": trusted,
            "alerts": alerts,
            "recent_scans": history
        }

    def generate_json(self) -> Path:
        """Exports data to JSON report."""
        data = self._compile_data()
        filename = f"wiguard_report_{format_timestamp().replace(':', '-').replace(' ', '_')}.json"
        dest_path = self.export_dir / filename
        
        try:
            with open(dest_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.info("JSON report exported to %s", dest_path)
            return dest_path
        except Exception as e:
            logger.error("Failed to export JSON report: %s", e)
            raise

    def generate_csv(self) -> Path:
        """Exports security alerts to a CSV report."""
        data = self._compile_data()
        filename = f"wiguard_report_{format_timestamp().replace(':', '-').replace(' ', '_')}.csv"
        dest_path = self.export_dir / filename
        
        try:
            with open(dest_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(["WiGuard Security Alerts Report"])
                writer.writerow(["Generated At", data["generated_at"]])
                writer.writerow([])
                writer.writerow(["Timestamp", "SSID", "BSSID", "Alert Type", "Risk Score", "Reason", "Resolved"])
                
                for alert in data["alerts"]:
                    writer.writerow([
                        alert["timestamp"],
                        alert["ssid"],
                        alert["bssid"],
                        alert["alert_type"],
                        alert["risk_score"],
                        alert["reason"],
                        alert["resolved"]
                    ])
            logger.info("CSV report exported to %s", dest_path)
            return dest_path
        except Exception as e:
            logger.error("Failed to export CSV report: %s", e)
            raise

    def generate_txt(self) -> Path:
        """Exports human-readable summary to a TXT report."""
        data = self._compile_data()
        filename = f"wiguard_report_{format_timestamp().replace(':', '-').replace(' ', '_')}.txt"
        dest_path = self.export_dir / filename
        
        try:
            with open(dest_path, "w", encoding="utf-8") as f:
                f.write("==================================================\n")
                f.write("               WiGuard Security Report             \n")
                f.write("==================================================\n")
                f.write(f"Generated At: {data['generated_at']}\n")
                f.write(f"Author:       {data['author']}\n\n")
                
                f.write("--- Stats Summary ---\n")
                f.write(f"Trusted Baselines:       {data['stats']['total_trusted']}\n")
                f.write(f"Total Detections/Alerts: {data['stats']['total_alerts']}\n")
                f.write(f"Active Alerts:           {data['stats']['active_alerts']}\n")
                f.write(f"Total Scans Logged:      {data['stats']['total_scans_logged']}\n\n")
                
                f.write("--- Active Security Alerts ---\n")
                active_alerts = [a for a in data["alerts"] if a["resolved"] == "No"]
                if active_alerts:
                    for i, alert in enumerate(active_alerts, 1):
                        f.write(f"{i}. [{alert['timestamp']}] [{alert['alert_type']}] Risk: {alert['risk_score']}/100\n")
                        f.write(f"   SSID:    {alert['ssid']}\n")
                        f.write(f"   BSSID:   {alert['bssid']}\n")
                        f.write(f"   Reason:  {alert['reason']}\n\n")
                else:
                    f.write("No active security threats detected.\n\n")
                    
                f.write("--- Trusted Networks Baseline ---\n")
                if data["trusted_networks"]:
                    for i, t in enumerate(data["trusted_networks"], 1):
                        f.write(f"{i}. SSID: {t['ssid']} | BSSID: {t['bssid']} | Vendor: {t['vendor']} | Enc: {t['encryption']} | Chan: {t['channel']}\n")
                else:
                    f.write("No trusted networks registered.\n")
                    
            logger.info("Text report exported to %s", dest_path)
            return dest_path
        except Exception as e:
            logger.error("Failed to export text report: %s", e)
            raise

# Global instance
report_generator = ReportGenerator()
