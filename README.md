# WiGuard

AI-Powered WiFi Evil Twin Detection CLI.

Developed by **Dino20004**.

<img width="1904" height="695" alt="Screenshot (147)" src="https://github.com/user-attachments/assets/64ff19d6-a459-41ee-9c8c-1696d6cc6cec" />

---

## Features
- **Duplicate SSID Detection**: Alert when multiple APs advertise the same SSID but have differing MACs.
- **Rogue AP Detection**: Detect rogue points utilizing untrusted vendors or signal anomalies.
- **MAC Vendor Verification**: Match network card vendor information against known baselines.
- **Encryption Downgrade Protection**: Instantly flag access points that drop encryption levels (e.g., WPA3 to WPA2 or Open).
- **Signal Strength Anomaly Analysis**: Detect high-power attackers spoofing a distant trusted network.
- **Unexpected Channel Shift Alerts**: Flag APs that migrate channels unexpectedly.
- **Continuous Monitoring Mode**: Actively scans and notifies in real-time.
- **SQLite Baseline Store**: Local storage for trusted baselines, security logs, and scan history.
- **Modular Design**: Cross-platform ready (Windows, Linux, macOS) utilizing native tools.

---

## Supported Operating Systems
- **Windows**: Parsed via `netsh wlan` native commands.
- **Linux**: Parsed via `nmcli` or `iw` commands.
- **macOS**: Parsed via `/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport`.

---

## Requirements
- Python 3.12+
- Packages listed in `requirements.txt` (`rich`, `tabulate`, `requests`, `psutil`)

---

## Installation

```bash
git clone https://github.com/Dino20004/06_WiGuard.git
cd 06_WiGuard
python -m venv venv
call venv\Scripts\activate
pip install -e .
wiguard version
```

For development:
```bash
pip install -r requirements.txt
python main.py version
python main.py diag
python main.py scan --simulate
```

---

## Usage & Commands (25 Commands)

WiGuard supports a full suite of commands:

### Scanning & Monitoring
1. `wiguard scan` - Scan nearby WiFi networks.
2. `wiguard monitor` - Continuous monitoring for threats.
3. `wiguard list` - Show nearby networks from the last scan.
4. `wiguard stats` - Show threat metrics and statistics.
5. `wiguard diag` - Run system diagnostic tests.

### Trust Configuration
6. `wiguard trust add <SSID> <BSSID>` - Add network to trusted list.
7. `wiguard trust remove <SSID> [BSSID]` - Remove network from trusted list.
8. `wiguard trust list` - Display trusted networks.
9. `wiguard trust import <file>` - Import trusted networks from JSON/CSV.
10. `wiguard trust export <file>` - Export trusted networks to JSON/CSV.
11. `wiguard trust clear` - Clear all trusted networks.

### Reports & History
12. `wiguard report generate <format>` - Generate security scan report (TXT, CSV, JSON).
13. `wiguard report list` - List all generated reports.
14. `wiguard report view <report_id>` - View summary details of a specific report.
15. `wiguard history show` - Show detection history logs.
16. `wiguard history clear` - Clear history logs.
17. `wiguard history stats` - Show statistical insights of history logs.

### Application Configuration
18. `wiguard config show` - View config parameters.
19. `wiguard config set <key> <value>` - Modify a config parameter.
20. `wiguard config reset` - Reset configuration to factory defaults.

### Security Alerts & OUI
21. `wiguard alert list` - List active security alerts.
22. `wiguard alert clear` - Clear security alerts.
23. `wiguard vendor lookup <MAC>` - Lookup vendor name by MAC address.
24. `wiguard vendor update` - Update OUI list.

### Help & Diagnostics
25. `wiguard version` - Display version info.

---

## Project Structure
```
WiGuard/
├── README.md
├── LICENSE
├── requirements.txt
├── setup.py
├── pyproject.toml
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── main.py
├── wiguard.py
├── docs/
│   ├── architecture.md
│   ├── installation.md
│   ├── usage.md
│   └── examples.md
├── scanner/
│   ├── wifi_scanner.py
│   ├── windows_scanner.py
│   ├── linux_scanner.py
│   ├── mac_scanner.py
│   └── network_parser.py
├── detector/
│   ├── duplicate_detector.py
│   ├── vendor_detector.py
│   ├── encryption_detector.py
│   ├── signal_detector.py
│   ├── channel_detector.py
│   └── risk_engine.py
├── database/
│   ├── database.py
│   └── models.py
├── reports/
│   ├── report_generator.py
│   └── history.py
├── utils/
│   ├── banner.py
│   ├── colors.py
│   ├── constants.py
│   ├── helpers.py
│   └── validators.py
├── cli/
│   ├── parser.py
│   └── commands.py
├── config/
│   ├── config.json
│   └── config_loader.py
└── tests/
```

---

## License
Licensed under the [MIT License](LICENSE).
