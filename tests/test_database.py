"""
Unit tests for the SQLite storage database manager.
"""
import unittest
from pathlib import Path
from database.database import DatabaseManager
from database.models import TrustedNetwork
from utils.helpers import format_timestamp

class TestDatabase(unittest.TestCase):
    """Verifies baseline CRUD operations on the SQLite db layer."""

    def setUp(self) -> None:
        # Use an in-memory SQLite database for testing
        self.db = DatabaseManager(":memory:")

    def test_add_and_get_trusted_network(self) -> None:
        net = TrustedNetwork(
            id=None,
            ssid="OfficeWiFi",
            bssid="00:11:22:33:44:55",
            vendor="Dell Inc.",
            encryption="WPA2-Personal",
            signal_baseline=-45,
            channel=36,
            date_added=format_timestamp()
        )
        self.assertTrue(self.db.add_trusted_network(net))
        
        # Retrieve and verify BSSID
        trusted = self.db.get_trusted_network_by_bssid("00:11:22:33:44:55")
        self.assertIsNotNone(trusted)
        self.assertEqual(trusted.ssid, "OfficeWiFi")
        self.assertEqual(trusted.vendor, "Dell Inc.")

    def test_remove_trusted_network(self) -> None:
        net = TrustedNetwork(
            id=None,
            ssid="OfficeWiFi",
            bssid="00:11:22:33:44:55",
            vendor="Dell Inc.",
            encryption="WPA2-Personal",
            signal_baseline=-45,
            channel=36,
            date_added=format_timestamp()
        )
        self.db.add_trusted_network(net)
        
        # Delete and verify
        deleted_count = self.db.remove_trusted_network("OfficeWiFi")
        self.assertEqual(deleted_count, 1)
        self.assertIsNone(self.db.get_trusted_network_by_bssid("00:11:22:33:44:55"))

if __name__ == "__main__":
    unittest.main()
