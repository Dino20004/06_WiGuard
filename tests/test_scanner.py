"""
Unit tests for the scanner parsing utilities.
"""
import unittest
from scanner.windows_scanner import parse_netsh_output
from scanner.linux_scanner import parse_nmcli_output
from scanner.mac_scanner import parse_airport_output
from scanner.network_parser import parse_scan_results, vendor_lookup

class TestScanners(unittest.TestCase):
    """Tests the parser logic for each OS scan output."""

    def test_windows_netsh_parser(self) -> None:
        mock_output = (
            "SSID 1 : OfficeWiFi\n"
            "    Network type            : Infrastructure\n"
            "    Authentication          : WPA2-Personal\n"
            "    Encryption              : CCMP\n"
            "    BSSID 1                 : 00:1c:bf:11:22:33\n"
            "        Signal              : 90%\n"
            "        Channel             : 6\n"
        )
        parsed = parse_netsh_output(mock_output)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["ssid"], "OfficeWiFi")
        self.assertEqual(parsed[0]["bssid"], "00:1C:BF:11:22:33")
        self.assertEqual(parsed[0]["channel"], 6)

    def test_linux_nmcli_parser(self) -> None:
        mock_output = (
            "HomeNet:00:14:22:aa:bb:cc:80:11:WPA2\n"
        )
        parsed = parse_nmcli_output(mock_output)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["ssid"], "HomeNet")
        self.assertEqual(parsed[0]["bssid"], "00:14:22:AA:BB:CC")
        self.assertEqual(parsed[0]["channel"], 11)

    def test_mac_airport_parser(self) -> None:
        mock_output = (
            "                            SSID BSSID             RSSI CHANNEL HT CC SECURITY\n"
            "                       OfficeWiFi 00:90:7f:55:66:77 -55  36      Y  US WPA3(PSK/AES)\n"
        )
        parsed = parse_airport_output(mock_output)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["ssid"], "OfficeWiFi")
        self.assertEqual(parsed[0]["bssid"], "00:90:7F:55:66:77")
        self.assertEqual(parsed[0]["signal"], -55)

    def test_vendor_lookup(self) -> None:
        # Check standard default OUI lookup
        vendor = vendor_lookup.lookup("00:14:22:01:02:03")
        self.assertEqual(vendor, "Dell Inc.")

if __name__ == "__main__":
    unittest.main()
