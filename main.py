"""
WiGuard Main Entry Point.
Sets up professional logging, resolves local directories, and runs the CLI parser.
"""
import sys
import logging
from pathlib import Path
from config.config_loader import config_loader
from cli.parser import parse_and_route

def setup_global_logging() -> None:
    """Configures rotating-like logging to a file and console warning output."""
    log_file_relative = config_loader.get("log_file", "logs/wiguard.log")
    # Resolve relative to package directory
    package_root = Path(__file__).parent
    log_path = package_root / log_file_relative
    
    # Ensure directory exists
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            # Direct warning/error logging to stderr
            logging.StreamHandler(sys.stderr)
        ]
    )
    # Set console log stream to only output WARNING or higher to avoid cluttering CLI table output
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
            handler.setLevel(logging.WARNING)

def main() -> None:
    """Orchestrates initialization and routing."""
    try:
        # Load configuration settings
        config_loader.load()
        
        # Setup logging paths and configurations
        setup_global_logging()
        
        # Execute parsed arguments and route
        parse_and_route()
    except KeyboardInterrupt:
        print("\n[!] Execution cancelled by keyboard interrupt.", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"[!] Unhandled fatal exception during runtime: {e}", file=sys.stderr)
        logging.exception("Fatal unhandled crash")
        sys.exit(1)

if __name__ == "__main__":
    main()
