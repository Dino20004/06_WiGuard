"""
Unit tests for the threat detection engine.
"""
import unittest
from scanner.network_parser import ScannedNetwork
from detector.duplicate_detector import DuplicateDetector
from detector.risk_engine import RiskEngine

class TestDetectors(unittest.TestCase):
    """Verifies threat detection heuristics and risk scoring logic."""

    def test_duplicate_ssid_detector(self) -> None:
        detector = DuplicateDetector()
        networks = [
            ScannedNetwork("TestNet", "00:11:22:33:44:55", -50, 6, "WPA2"),
            ScannedNetwork("TestNet", "00:11:22:33:44:66", -60, 11, "WPA2"),
            ScannedNetwork("UniqueNet", "00:11:22:33:44:77", -70, 1, "WPA2")
        ]
        dups = detector.analyze(networks)
        self.assertIn("TestNet", dups)
        self.assertNotIn("UniqueNet", dups)
        self.assertEqual(len(dups["TestNet"]), 2)

    def test_risk_engine_score_bounds(self) -> None:
        engine = RiskEngine()
        status_safe = engine.get_risk_status(10)
        status_critical = engine.get_risk_status(95)
        self.assertEqual(status_safe, "SAFE")
        self.assertEqual(status_critical, "CRITICAL")

if __name__ == "__main__":
    unittest.main()
