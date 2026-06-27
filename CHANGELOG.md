# Changelog

All notable changes to **WiGuard** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-27
### Added
- Initial release of **WiGuard** by **Dino20004**.
- Standardized command line interface with 25 working commands and subcommands.
- Multi-platform scanner logic (Windows, Linux, macOS) utilizing native utility parser engines.
- Advanced Evil Twin Detection pipeline:
  - Duplicate SSID detection.
  - MAC Vendor validation and OUI verification.
  - Encryption downgrade analysis.
  - Signal strength anomaly tracking.
  - Unexpected channel change alerts.
- Integrated Risk Engine producing scores from 0-100 and risk classifications (SAFE, LOW, MEDIUM, HIGH, CRITICAL).
- SQLite storage backend for trusted baselines, history tracking, and security alerts.
- Structured report generator with TXT, CSV, and JSON formats.
- Complete system diagnostic module.
