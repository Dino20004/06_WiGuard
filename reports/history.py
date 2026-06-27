"""
History tracking and analysis module for WiGuard reports.
Computes stats and organizes historic scan data.
"""
from typing import Dict, Any, List
from database.database import db_manager

class HistoryManager:
    """Aggregates history and alerts information for CLI display and reports."""

    def get_recent_history(self, limit: int = 50) -> List[Any]:
        """Retrieves raw history objects from the database layer."""
        return db_manager.get_scan_history(limit=limit)

    def get_stats(self) -> Dict[str, Any]:
        """Calculates security telemetry and statistical analysis over logged scans."""
        history = db_manager.get_scan_history(limit=1000)
        alerts = db_manager.get_alerts()
        
        if not history:
            return {
                "total_scans": 0,
                "threat_ratio": 0.0,
                "highest_risk": 0,
                "most_common_ssid": "None",
                "total_alerts": len(alerts),
                "active_alerts": len([a for a in alerts if not a.resolved])
            }
            
        total_scans = len(history)
        total_threats = sum(1 for h in history if h.risk_score > 0)
        highest_risk = max(h.risk_score for h in history)
        
        # Calculate most scanned SSID
        ssid_counts: Dict[str, int] = {}
        for h in history:
            ssid_counts[h.ssid] = ssid_counts.get(h.ssid, 0) + 1
        most_common_ssid = max(ssid_counts, key=ssid_counts.get) if ssid_counts else "None"
        
        return {
            "total_scans": total_scans,
            "threat_ratio": round((total_threats / total_scans) * 100, 1),
            "highest_risk": highest_risk,
            "most_common_ssid": most_common_ssid,
            "total_alerts": len(alerts),
            "active_alerts": len([a for a in alerts if not a.resolved])
        }

# Global instance
history_manager = HistoryManager()
