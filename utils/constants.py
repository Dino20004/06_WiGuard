"""
Constants used across the WiGuard application.
"""

APP_NAME = "WiGuard"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Dino20004"
APP_LICENSE = "MIT"

# Risk Engine weights (Sum to 100)
WEIGHT_DUPLICATE_SSID = 30
WEIGHT_ENCRYPTION_DOWNGRADE = 25
WEIGHT_VENDOR_MISMATCH = 20
WEIGHT_SIGNAL_ANOMALY = 15
WEIGHT_CHANNEL_CHANGE = 10

# Threat Thresholds
SIGNAL_DEVIATION_THRESHOLD = 25  # dBm deviation that raises anomaly alert
CHANNEL_JUMP_THRESHOLD = 3       # number of channel hops considered suspicious

# Risk Categories
RISK_SAFE = "SAFE"
RISK_LOW = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH = "HIGH"
RISK_CRITICAL = "CRITICAL"

# Default configuration path
DEFAULT_CONFIG_FILENAME = "config.json"
DEFAULT_DB_FILENAME = "trusted_networks.db"
DEFAULT_LOG_FILENAME = "wiguard.log"
