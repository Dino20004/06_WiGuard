"""
Banner display utility for WiGuard.
"""
from rich.console import Console
from rich.panel import Panel
from rich.align import Align

def get_banner() -> str:
    """Returns the ASCI art banner text for WiGuard."""
    banner_text = (
        "██╗    ██╗██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ \n"
        "██║    ██║██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗\n"
        "██║ █╗ ██║██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║\n"
        "██║███╗██║██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║\n"
        "╚███╔███╔╝██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝\n"
        " ╚══╝╚══╝ ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
    )
    return banner_text

def print_banner() -> None:
    """Prints the styled banner to console using Rich."""
    console = Console()
    banner = get_banner()
    panel = Panel(
        Align.center(f"[bold cyan]{banner}[/bold cyan]\n\n[bold white]WiGuard - WiFi Evil Twin Detection CLI[/bold white]\n[dim]Created by Dino20004 | v1.0.0[/dim]"),
        border_style="cyan"
    )
    console.print(panel)

if __name__ == "__main__":
    print_banner()
