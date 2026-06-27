"""
Config Loader Module for WiGuard.
Handles reading, writing, and updating config.json.
"""
import json
import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger("WiGuard.Config")

DEFAULT_CONFIG: Dict[str, Any] = {
    "scan_interval": 5,
    "risk_threshold": 50,
    "logging_enabled": True,
    "theme": "dark",
    "database_path": "database/trusted_networks.db",
    "log_file": "logs/wiguard.log"
}

class ConfigLoader:
    """Manages application configuration settings."""

    def __init__(self, config_path: Path | None = None) -> None:
        if config_path is None:
            # Locate relative to this file
            self.config_path = Path(__file__).parent / "config.json"
        else:
            self.config_path = Path(config_path)
            
        self.config: Dict[str, Any] = DEFAULT_CONFIG.copy()
        self.load()

    def load(self) -> None:
        """Loads configuration from JSON file. If file not found or invalid, uses defaults."""
        try:
            if self.config_path.exists():
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        # Merge with defaults to ensure all keys exist
                        for k, v in DEFAULT_CONFIG.items():
                            self.config[k] = data.get(k, v)
                        logger.info("Configuration loaded from %s", self.config_path)
                    else:
                        logger.warning("Invalid format in config.json. Using defaults.")
            else:
                self.save()
                logger.info("Config file created with default values at %s", self.config_path)
        except Exception as e:
            logger.error("Error loading config: %s. Using default settings.", e)
            self.config = DEFAULT_CONFIG.copy()

    def save(self) -> None:
        """Saves current configuration to file."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
            logger.info("Configuration saved to %s", self.config_path)
        except Exception as e:
            logger.error("Error saving config: %s", e)

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves a configuration value."""
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Sets a configuration value and saves it."""
        if key in DEFAULT_CONFIG:
            # Handle types
            expected_type = type(DEFAULT_CONFIG[key])
            try:
                if expected_type == bool:
                    if isinstance(value, str):
                        value = value.lower() in ("true", "1", "yes")
                    else:
                        value = bool(value)
                elif expected_type == int:
                    value = int(value)
                elif expected_type == float:
                    value = float(value)
                else:
                    value = str(value)
            except (ValueError, TypeError) as e:
                logger.error("Invalid type for %s. Expected %s. Error: %s", key, expected_type, e)
                raise ValueError(f"Invalid type for key '{key}'. Expected {expected_type.__name__}.") from e

            self.config[key] = value
            self.save()
        else:
            logger.warning("Attempted to set unrecognized config key: %s", key)
            raise KeyError(f"Key '{key}' is not a valid configuration setting.")

    def reset(self) -> None:
        """Resets configuration to default settings."""
        self.config = DEFAULT_CONFIG.copy()
        self.save()
        logger.info("Configuration reset to defaults.")

# Global instance
config_loader = ConfigLoader()

if __name__ == "__main__":
    # Example usage
    print("Default Scan Interval:", config_loader.get("scan_interval"))
    config_loader.set("scan_interval", 10)
    print("New Scan Interval:", config_loader.get("scan_interval"))
    config_loader.reset()
