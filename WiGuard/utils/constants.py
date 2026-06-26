"""Constants for WiGuard."""

RISK_WEIGHTS = {
    "duplicate": 30,
    "encryption": 25,
    "vendor": 20,
    "signal": 15,
    "channel": 10,
}

RISK_LEVELS = {
    0: "SAFE",
    30: "LOW",
    60: "MEDIUM",
    80: "HIGH",
    100: "CRITICAL"
}

DEFAULT_SCAN_INTERVAL = 5
VERSION = "1.0.0"
