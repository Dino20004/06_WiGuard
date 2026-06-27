"""
SQLite database manager for WiGuard.
Handles table creation, reads, writes, and database operations.
"""
import sqlite3
import logging
from pathlib import Path
from typing import List, Tuple, Any, Dict
from config.config_loader import config_loader
from database.models import TrustedNetwork, ScanHistory, SecurityAlert
from utils.helpers import format_timestamp

logger = logging.getLogger("WiGuard.Database")

class DatabaseManager:
    """Manages SQLite database storage for WiGuard."""

    def __init__(self, db_path: str | None = None) -> None:
        if db_path is None:
            # Resolve db_path from config
            relative_db_path = config_loader.get("database_path", "database/trusted_networks.db")
            # Make path relative to package root
            package_root = Path(__file__).parent.parent
            self.db_path = str(package_root / relative_db_path)
            # Ensure directory exists
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        elif db_path == ":memory:":
            self.db_path = ":memory:"
        else:
            self.db_path = str(Path(db_path))
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self.conn = sqlite3.connect(self.db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a connection to the SQLite database."""
        return self.conn

    def _init_db(self) -> None:
        """Initializes tables in the SQLite database if they don't exist."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Table: TrustedNetworks
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS TrustedNetworks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ssid TEXT NOT NULL,
                        bssid TEXT NOT NULL UNIQUE,
                        vendor TEXT,
                        encryption TEXT,
                        signal_baseline INTEGER,
                        channel INTEGER,
                        date_added TEXT NOT NULL
                    )
                """)
                
                # Table: ScanHistory
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ScanHistory (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        ssid TEXT NOT NULL,
                        bssid TEXT NOT NULL,
                        vendor TEXT,
                        encryption TEXT,
                        signal INTEGER,
                        channel INTEGER,
                        risk_score INTEGER,
                        risk_status TEXT
                    )
                """)
                
                # Table: SecurityAlerts
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS SecurityAlerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        ssid TEXT NOT NULL,
                        bssid TEXT NOT NULL,
                        alert_type TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        reason TEXT NOT NULL,
                        resolved INTEGER DEFAULT 0
                    )
                """)
                conn.commit()
                logger.info("Database tables initialized at %s", self.db_path)
        except sqlite3.Error as e:
            logger.error("Failed to initialize database: %s", e)
            raise

    # --- TrustedNetworks Operations ---
    
    def add_trusted_network(self, net: TrustedNetwork) -> bool:
        """Adds a network to the trusted baseline, or updates it if already trusted by BSSID."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO TrustedNetworks 
                    (ssid, bssid, vendor, encryption, signal_baseline, channel, date_added)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (net.ssid, net.bssid, net.vendor, net.encryption, net.signal_baseline, net.channel, net.date_added))
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error("Error adding trusted network: %s", e)
            return False

    def remove_trusted_network(self, ssid: str, bssid: str | None = None) -> int:
        """Removes trusted network(s) by SSID and optionally BSSID. Returns number of rows deleted."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if bssid:
                    cursor.execute("DELETE FROM TrustedNetworks WHERE ssid = ? AND bssid = ?", (ssid, bssid))
                else:
                    cursor.execute("DELETE FROM TrustedNetworks WHERE ssid = ?", (ssid,))
                conn.commit()
                return cursor.rowcount
        except sqlite3.Error as e:
            logger.error("Error removing trusted network: %s", e)
            return 0

    def get_trusted_networks(self) -> List[TrustedNetwork]:
        """Returns a list of all trusted networks."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, ssid, bssid, vendor, encryption, signal_baseline, channel, date_added FROM TrustedNetworks")
                rows = cursor.fetchall()
                return [TrustedNetwork(*row) for row in rows]
        except sqlite3.Error as e:
            logger.error("Error fetching trusted networks: %s", e)
            return []

    def get_trusted_network_by_bssid(self, bssid: str) -> TrustedNetwork | None:
        """Retrieves a trusted network by BSSID."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, ssid, bssid, vendor, encryption, signal_baseline, channel, date_added FROM TrustedNetworks WHERE bssid = ?", (bssid,))
                row = cursor.fetchone()
                if row:
                    return TrustedNetwork(*row)
                return None
        except sqlite3.Error as e:
            logger.error("Error fetching trusted network by BSSID: %s", e)
            return None

    def clear_trusted_networks(self) -> bool:
        """Clears all trusted networks from the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM TrustedNetworks")
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error("Error clearing trusted networks: %s", e)
            return False

    # --- ScanHistory Operations ---
    
    def add_scan_history(self, history: ScanHistory) -> bool:
        """Records a scanned network in history."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO ScanHistory (timestamp, ssid, bssid, vendor, encryption, signal, channel, risk_score, risk_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (history.timestamp, history.ssid, history.bssid, history.vendor, history.encryption, history.signal, history.channel, history.risk_score, history.risk_status))
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error("Error writing scan history: %s", e)
            return False

    def get_scan_history(self, limit: int = 100) -> List[ScanHistory]:
        """Fetches recent scan history."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, timestamp, ssid, bssid, vendor, encryption, signal, channel, risk_score, risk_status 
                    FROM ScanHistory ORDER BY id DESC LIMIT ?
                """, (limit,))
                rows = cursor.fetchall()
                return [ScanHistory(*row) for row in rows]
        except sqlite3.Error as e:
            logger.error("Error reading scan history: %s", e)
            return []

    def clear_scan_history(self) -> bool:
        """Clears scan history."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM ScanHistory")
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error("Error clearing scan history: %s", e)
            return False

    # --- SecurityAlerts Operations ---
    
    def add_alert(self, alert: SecurityAlert) -> bool:
        """Inserts a security alert into the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO SecurityAlerts (timestamp, ssid, bssid, alert_type, risk_score, reason, resolved)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (alert.timestamp, alert.ssid, alert.bssid, alert.alert_type, alert.risk_score, alert.reason, alert.resolved))
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error("Error inserting alert: %s", e)
            return False

    def get_alerts(self, only_active: bool = False) -> List[SecurityAlert]:
        """Fetches security alerts."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if only_active:
                    cursor.execute("""
                        SELECT id, timestamp, ssid, bssid, alert_type, risk_score, reason, resolved 
                        FROM SecurityAlerts WHERE resolved = 0 ORDER BY id DESC
                    """)
                else:
                    cursor.execute("""
                        SELECT id, timestamp, ssid, bssid, alert_type, risk_score, reason, resolved 
                        FROM SecurityAlerts ORDER BY id DESC
                    """)
                rows = cursor.fetchall()
                return [SecurityAlert(*row) for row in rows]
        except sqlite3.Error as e:
            logger.error("Error reading alerts: %s", e)
            return []

    def clear_alerts(self) -> bool:
        """Clears all security alerts."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM SecurityAlerts")
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error("Error clearing alerts: %s", e)
            return False

    def resolve_all_alerts(self) -> int:
        """Marks all active alerts as resolved. Returns number of alerts resolved."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE SecurityAlerts SET resolved = 1 WHERE resolved = 0")
                conn.commit()
                return cursor.rowcount
        except sqlite3.Error as e:
            logger.error("Error resolving alerts: %s", e)
            return 0

# Global instance
db_manager = DatabaseManager()
