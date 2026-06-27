"""
Standardized terminal color definitions for WiGuard CLI.
Provides Rich console style strings.
"""

# Rich text style formats
COLOR_SAFE = "green"
COLOR_LOW = "blue"
COLOR_MEDIUM = "yellow"
COLOR_HIGH = "orange3"
COLOR_CRITICAL = "red"

COLOR_BANNER = "cyan"
COLOR_INFO = "white"
COLOR_SUCCESS = "bold green"
COLOR_WARNING = "bold yellow"
COLOR_ERROR = "bold red"
COLOR_MUTED = "dim"

def get_risk_style(status: str) -> str:
    """Returns the Rich formatting style based on risk level."""
    status_upper = status.upper()
    if status_upper == "SAFE":
        return COLOR_SAFE
    elif status_upper == "LOW":
        return COLOR_LOW
    elif status_upper == "MEDIUM":
        return COLOR_MEDIUM
    elif status_upper == "HIGH":
        return COLOR_HIGH
    elif status_upper == "CRITICAL":
        return f"bold {COLOR_CRITICAL}"
    return COLOR_INFO
