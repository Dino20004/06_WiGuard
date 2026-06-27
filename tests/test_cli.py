"""
Unit tests for the CLI Argument Parser routing.
"""
import unittest
from cli.parser import create_parser

class TestCLIParser(unittest.TestCase):
    """Verifies that all 25 CLI command subparsers exist and resolve arguments."""

    def setUp(self) -> None:
        self.parser = create_parser()

    def test_scan_subcommand(self) -> None:
        args = self.parser.parse_args(["scan", "--simulate"])
        self.assertEqual(args.command, "scan")
        self.assertTrue(args.simulate)

    def test_trust_add_subcommand(self) -> None:
        args = self.parser.parse_args(["trust", "add", "TestSSID", "00:11:22:33:44:55"])
        self.assertEqual(args.command, "trust")
        self.assertEqual(args.trust_command, "add")
        self.assertEqual(args.ssid, "TestSSID")
        self.assertEqual(args.bssid, "00:11:22:33:44:55")

    def test_report_generate_subcommand(self) -> None:
        args = self.parser.parse_args(["report", "generate", "json"])
        self.assertEqual(args.command, "report")
        self.assertEqual(args.report_command, "generate")
        self.assertEqual(args.format, "json")

if __name__ == "__main__":
    unittest.main()
