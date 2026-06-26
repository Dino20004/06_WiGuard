# WiGuard

**AI-Powered WiFi Evil Twin Detection CLI**

A professional open-source command-line tool that detects Evil Twin and Rogue Access Point attacks by continuously monitoring nearby WiFi networks and comparing them against trusted baselines.

## Features

- **Duplicate SSID Detection**
- **Rogue AP & Vendor Mismatch Detection**
- **Encryption Downgrade Alerts**
- **Signal Strength Anomaly Detection**
- **Suspicious Channel Changes**
- **Risk Scoring Engine** (0-100)
- **Trusted Network Database** (SQLite)
- **Beautiful Rich CLI output** with color
- **Real-time Monitoring mode**
- **Report generation** (JSON, CSV, TXT)
- **Cross-platform** support (Windows, Linux)

## Quick Start

```bash
git clone https://github.com/yourusername/wiguard.git
cd wiguard
pip install -r requirements.txt
pip install .
wiguard trust "MyHomeWiFi"
wiguard scan
wiguard monitor
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `wiguard scan` | One-time scan |
| `wiguard monitor` | Continuous monitoring |
| `wiguard trust <SSID>` | Add trusted network |
| `wiguard remove <SSID>` | Remove trusted |
| `wiguard list` | List trusted networks |
| `wiguard report` | Generate report |
| `wiguard history` | Show history |
| `wiguard version` | Show version |

## Requirements

- Python 3.12+
- Admin/root privileges for scanning
- Windows or Linux (macOS partial)

See full docs in `docs/`.

## License

MIT License
