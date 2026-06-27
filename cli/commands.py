"""
Command execution implementations for WiGuard CLI.
Provides the entry point functions for each of the 25 commands.
"""
import sys
import time
import os
import csv
import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live

from scanner.wifi_scanner import scan_networks
from detector.risk_engine import RiskEngine
from database.database import db_manager
from database.models import TrustedNetwork, SecurityAlert
from config.config_loader import config_loader
from reports.report_generator import report_generator
from reports.history import history_manager
from scanner.network_parser import vendor_lookup
from utils.banner import print_banner
from utils.helpers import format_timestamp, normalize_mac
from utils.colors import get_risk_style
from utils.constants import APP_VERSION, APP_AUTHOR, APP_LICENSE

console = Console()

# --- Helper function for printing titles ---
def print_title(text: str) -> None:
    console.print(Panel(f"[bold cyan]{text}[/bold cyan]", expand=False))

# --- Command 1: wiguard scan ---
def cmd_scan(force_simulate: bool = False) -> None:
    print_title("WiFi Scan Initiative")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        progress.add_task(description="Scanning airwaves...", total=None)
        scanned = scan_networks(force_simulate=force_simulate)
        
        progress.add_task(description="Calculating risk indices...", total=None)
        engine = RiskEngine()
        results = engine.evaluate_networks(scanned)

    table = Table(title="Nearby Access Points Detection")
    table.add_column("SSID", style="bold white")
    table.add_column("BSSID", style="cyan")
    table.add_column("Signal", justify="right")
    table.add_column("Channel", justify="right")
    table.add_column("Vendor", style="magenta")
    table.add_column("Encryption", style="yellow")
    table.add_column("Risk Score", justify="center")
    table.add_column("Status", justify="center")

    for res in results:
        net = res["network"]
        score = res["score"]
        status = res["status"]
        style = get_risk_style(status)
        
        table.add_row(
            net.ssid,
            net.bssid,
            f"{net.signal} dBm",
            str(net.channel),
            net.vendor,
            net.encryption,
            f"[{style}]{score}[/{style}]",
            f"[{style}]{status}[/{style}]"
        )
        
        # Print specific warning highlights if risky
        if score > 0 and res["reasons"]:
            for reason in res["reasons"]:
                logger_desc = f"  ↳ [bold red]ALERT:[/bold red] {reason}"
                # We log print statements below the table
                
    console.print(table)
    
    # Print alerts summary below the table
    risky_networks = [r for r in results if r["score"] > 0]
    if risky_networks:
        console.print("\n[bold red]Security Anomalies Identified:[/bold red]")
        for r in risky_networks:
            for reason in r["reasons"]:
                console.print(f"  [bold yellow]![/bold yellow] {r['network'].ssid} ({r['network'].bssid}): {reason}")
    else:
        console.print("\n[bold green]No threats detected. All networks appear safe.[/bold green]")

# --- Command 2: wiguard monitor ---
def cmd_monitor(force_simulate: bool = False) -> None:
    print_title("Continuous WiFi Monitoring Mode")
    interval = config_loader.get("scan_interval", 5)
    console.print(f"[dim]Starting active listening loop. Scanning every {interval} seconds...[/dim]")
    console.print("[dim]Press Ctrl+C to terminate security monitoring.[/dim]\n")
    
    engine = RiskEngine()
    scan_count = 0
    
    try:
        while True:
            scan_count += 1
            timestamp = datetime.now().strftime("%H:%M:%S")
            console.print(f"\n[cyan][{timestamp}][/cyan] [bold]Scan cycle #{scan_count}[/bold] executing...")
            
            scanned = scan_networks(force_simulate=force_simulate)
            results = engine.evaluate_networks(scanned)
            
            # Print alerts if found
            threat_found = False
            for res in results:
                if res["score"] >= config_loader.get("risk_threshold", 50):
                    threat_found = True
                    style = get_risk_style(res["status"])
                    console.print(
                        f"  [bold red][ALERT][/bold red] SSID: [white]{res['network'].ssid}[/white] | "
                        f"BSSID: {res['network'].bssid} | "
                        f"Risk: [{style}]{res['status']} ({res['score']})[/{style}]"
                    )
                    for reason in res["reasons"]:
                        console.print(f"    ↳ [yellow]{reason}[/yellow]")
            
            if not threat_found:
                console.print("  [green]✔ Scan quiet. No active threats detected.[/green]")
                
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Monitoring terminated by user request.[/bold yellow]")

# --- Command 3: wiguard trust add ---
def cmd_trust_add(ssid: str, bssid: str, force_simulate: bool = False) -> None:
    # Attempt to resolve details from air scan if possible, or use standard defaults
    mac = normalize_mac(bssid)
    vendor = vendor_lookup.lookup(mac)
    
    # Try to find default values from a quick scan
    scanned = scan_networks(force_simulate=force_simulate)
    match = next((n for n in scanned if n.bssid == mac), None)
    
    enc = match.encryption if match else "WPA2-Personal"
    sig = match.signal if match else -50
    chan = match.channel if match else 6
    
    net = TrustedNetwork(
        id=None,
        ssid=ssid,
        bssid=mac,
        vendor=vendor,
        encryption=enc,
        signal_baseline=sig,
        channel=chan,
        date_added=format_timestamp()
    )
    
    if db_manager.add_trusted_network(net):
        console.print(f"[bold green]Success:[/bold green] Added network '{ssid}' ({mac}) to trusted baseline.")
    else:
        console.print("[bold red]Error:[/bold red] Failed to write network to database.")

# --- Command 4: wiguard trust remove ---
def cmd_trust_remove(ssid: str, bssid: str | None = None) -> None:
    count = db_manager.remove_trusted_network(ssid, bssid)
    if count > 0:
        console.print(f"[bold green]Success:[/bold green] Removed {count} entries matching '{ssid}' from trust list.")
    else:
        console.print(f"[bold yellow]No networks match SSID '{ssid}' (and BSSID '{bssid}' if provided).[/bold yellow]")

# --- Command 5: wiguard trust list ---
def cmd_trust_list() -> None:
    print_title("Trusted Networks Baseline")
    trusted = db_manager.get_trusted_networks()
    
    if not trusted:
        console.print("[yellow]No networks currently registered in trusted database.[/yellow]")
        return
        
    table = Table()
    table.add_column("SSID", style="bold white")
    table.add_column("BSSID", style="cyan")
    table.add_column("Vendor", style="magenta")
    table.add_column("Encryption", style="yellow")
    table.add_column("Baseline Signal", justify="right")
    table.add_column("Channel", justify="right")
    table.add_column("Date Added", style="dim")
    
    for t in trusted:
        table.add_row(
            t.ssid,
            t.bssid,
            t.vendor,
            t.encryption,
            f"{t.signal_baseline} dBm",
            str(t.channel),
            t.date_added
        )
    console.print(table)

# --- Command 6: wiguard trust import ---
def cmd_trust_import(file_path: str) -> None:
    path = Path(file_path)
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
        return
        
    count = 0
    try:
        if path.suffix.lower() == ".json":
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                networks = data if isinstance(data, list) else data.get("trusted_networks", [])
                for item in networks:
                    net = TrustedNetwork(
                        id=None,
                        ssid=item["ssid"],
                        bssid=normalize_mac(item["bssid"]),
                        vendor=item.get("vendor", vendor_lookup.lookup(item["bssid"])),
                        encryption=item.get("encryption", "WPA2-Personal"),
                        signal_baseline=item.get("signal_baseline", -50),
                        channel=item.get("channel", 6),
                        date_added=format_timestamp()
                    )
                    if db_manager.add_trusted_network(net):
                        count += 1
        elif path.suffix.lower() == ".csv":
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    net = TrustedNetwork(
                        id=None,
                        ssid=row["ssid"],
                        bssid=normalize_mac(row["bssid"]),
                        vendor=row.get("vendor", vendor_lookup.lookup(row["bssid"])),
                        encryption=row.get("encryption", "WPA2-Personal"),
                        signal_baseline=int(row.get("signal_baseline", -50)),
                        channel=int(row.get("channel", 6)),
                        date_added=format_timestamp()
                    )
                    if db_manager.add_trusted_network(net):
                        count += 1
        else:
            console.print("[bold red]Error:[/bold red] Unsupported file format. Please use JSON or CSV.")
            return
            
        console.print(f"[bold green]Success:[/bold green] Imported {count} trusted networks from {file_path}")
    except Exception as e:
        console.print(f"[bold red]Error during import:[/bold red] {e}")

# --- Command 7: wiguard trust export ---
def cmd_trust_export(file_path: str) -> None:
    path = Path(file_path)
    trusted = db_manager.get_trusted_networks()
    
    if not trusted:
        console.print("[bold yellow]No trusted networks found in database to export.[/bold yellow]")
        return
        
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix.lower() == ".json":
            out = [
                {
                    "ssid": t.ssid,
                    "bssid": t.bssid,
                    "vendor": t.vendor,
                    "encryption": t.encryption,
                    "signal_baseline": t.signal_baseline,
                    "channel": t.channel,
                    "date_added": t.date_added
                } for t in trusted
            ]
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"trusted_networks": out}, f, indent=2)
        elif path.suffix.lower() == ".csv":
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ssid", "bssid", "vendor", "encryption", "signal_baseline", "channel", "date_added"])
                for t in trusted:
                    writer.writerow([t.ssid, t.bssid, t.vendor, t.encryption, t.signal_baseline, t.channel, t.date_added])
        else:
            console.print("[bold red]Error:[/bold red] Unsupported export format. Use JSON or CSV suffix.")
            return
            
        console.print(f"[bold green]Success:[/bold green] Exported {len(trusted)} trusted networks to {file_path}")
    except Exception as e:
        console.print(f"[bold red]Error during export:[/bold red] {e}")

# --- Command 8: wiguard trust clear ---
def cmd_trust_clear() -> None:
    if db_manager.clear_trusted_networks():
        console.print("[bold green]Success:[/bold green] Cleared all trusted networks baseline.")
    else:
        console.print("[bold red]Error:[/bold red] Failed to clear trust baseline.")

# --- Command 9: wiguard list ---
def cmd_list() -> None:
    print_title("Latest Discovered Access Points")
    history = db_manager.get_scan_history(limit=50)
    
    if not history:
        console.print("[yellow]No historical network data logged. Run a scan first.[/yellow]")
        return
        
    # Group by last scanned timestamp
    latest_timestamp = history[0].timestamp
    latest_networks = [h for h in history if h.timestamp == latest_timestamp]
    
    table = Table(title=f"Scan Logs at {latest_timestamp}")
    table.add_column("SSID", style="bold white")
    table.add_column("BSSID", style="cyan")
    table.add_column("Vendor", style="magenta")
    table.add_column("Encryption", style="yellow")
    table.add_column("Signal", justify="right")
    table.add_column("Channel", justify="right")
    table.add_column("Risk Score", justify="center")
    
    for net in latest_networks:
        style = get_risk_style(net.risk_status)
        table.add_row(
            net.ssid,
            net.bssid,
            net.vendor,
            net.encryption,
            f"{net.signal} dBm",
            str(net.channel),
            f"[{style}]{net.risk_score}[/{style}]"
        )
    console.print(table)

# --- Command 10: wiguard report generate ---
def cmd_report_generate(fmt: str) -> None:
    fmt = fmt.lower()
    try:
        if fmt == "json":
            path = report_generator.generate_json()
        elif fmt == "csv":
            path = report_generator.generate_csv()
        elif fmt == "txt":
            path = report_generator.generate_txt()
        else:
            console.print("[bold red]Error:[/bold red] Invalid format. Choose txt, csv, or json.")
            return
        console.print(f"[bold green]Success:[/bold green] Report generated at [cyan]{path}[/cyan]")
    except Exception as e:
        console.print(f"[bold red]Failed to generate report:[/bold red] {e}")

# --- Command 11: wiguard report list ---
def cmd_report_list() -> None:
    print_title("Generated Reports Register")
    export_dir = report_generator.export_dir
    files = list(export_dir.glob("wiguard_report_*"))
    
    if not files:
        console.print("[yellow]No reports found in exports folder.[/yellow]")
        return
        
    table = Table()
    table.add_column("Report Filename", style="bold white")
    table.add_column("Format", style="cyan")
    table.add_column("Size (Bytes)", justify="right")
    table.add_column("Created Date", style="dim")
    
    for f in sorted(files, key=os.path.getmtime, reverse=True):
        mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        table.add_row(
            f.name,
            f.suffix[1:].upper(),
            f"{f.stat().st_size:,}",
            mtime
        )
    console.print(table)

# --- Command 12: wiguard report view ---
def cmd_report_view(filename: str) -> None:
    export_dir = report_generator.export_dir
    path = export_dir / filename
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] Report not found: {filename}")
        return
        
    print_title(f"Viewing Report: {filename}")
    try:
        if path.suffix.lower() == ".json":
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                console.print_json(data=data)
        elif path.suffix.lower() == ".txt":
            with open(path, "r", encoding="utf-8") as f:
                console.print(f.read())
        elif path.suffix.lower() == ".csv":
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                table = Table()
                headers = next(reader, None)
                if headers:
                    for h in headers:
                        table.add_column(h)
                    for row in reader:
                        table.add_row(*row)
                    console.print(table)
        else:
            console.print("[bold red]Error:[/bold red] Unrecognized file suffix.")
    except Exception as e:
        console.print(f"[bold red]Error displaying report:[/bold red] {e}")

# --- Command 13: wiguard history show ---
def cmd_history_show() -> None:
    print_title("Scan History Logs")
    history = db_manager.get_scan_history(limit=50)
    
    if not history:
        console.print("[yellow]No historical scan telemetry found.[/yellow]")
        return
        
    table = Table()
    table.add_column("Timestamp", style="cyan")
    table.add_column("SSID", style="bold white")
    table.add_column("BSSID")
    table.add_column("Vendor", style="magenta")
    table.add_column("Signal")
    table.add_column("Chan", justify="right")
    table.add_column("Risk Score", justify="center")
    table.add_column("Risk Status", justify="center")
    
    for h in history:
        style = get_risk_style(h.risk_status)
        table.add_row(
            h.timestamp,
            h.ssid,
            h.bssid,
            h.vendor,
            f"{h.signal} dBm",
            str(h.channel),
            f"[{style}]{h.risk_score}[/style]",
            f"[{style}]{h.risk_status}[/style]"
        )
    console.print(table)

# --- Command 14: wiguard history clear ---
def cmd_history_clear() -> None:
    if db_manager.clear_scan_history():
        console.print("[bold green]Success:[/bold green] Scan history logs deleted.")
    else:
        console.print("[bold red]Error:[/bold red] Failed to clear history.")

# --- Command 15: wiguard history stats ---
def cmd_history_stats() -> None:
    print_title("History Statistical Insights")
    stats = history_manager.get_stats()
    
    if stats["total_scans"] == 0:
        console.print("[yellow]Not enough scan logs in history database to compute stats.[/yellow]")
        return
        
    console.print(f"Total Scans Performed:   [bold cyan]{stats['total_scans']}[/bold cyan]")
    console.print(f"Aggregated Threat Ratio: [bold red]{stats['threat_ratio']}%[/bold red]")
    console.print(f"Highest Risk Identified: [bold red]{stats['highest_risk']}/100[/bold red]")
    console.print(f"Most Encountered SSID:   [bold white]'{stats['most_common_ssid']}'[/bold white]")
    console.print(f"Total Logged Alerts:     [bold yellow]{stats['total_alerts']}[/bold yellow]")
    console.print(f"Active Alerts:           [bold red]{stats['active_alerts']}[/bold red]")

# --- Command 16: wiguard config show ---
def cmd_config_show() -> None:
    print_title("Active Configuration Settings")
    for k, v in config_loader.config.items():
        console.print(f"  [bold white]{k}:[/bold white] [green]{v}[/green]")

# --- Command 17: wiguard config set ---
def cmd_config_set(key: str, value: str) -> None:
    try:
        config_loader.set(key, value)
        console.print(f"[bold green]Success:[/bold green] Updated configuration '{key}' to '{value}'.")
    except KeyError:
        console.print(f"[bold red]Error:[/bold red] Key '{key}' does not exist in configuration settings.")
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

# --- Command 18: wiguard config reset ---
def cmd_config_reset() -> None:
    config_loader.reset()
    console.print("[bold green]Success:[/bold green] Configuration reset to defaults.")

# --- Command 19: wiguard vendor lookup ---
def cmd_vendor_lookup(mac: str) -> None:
    mac = normalize_mac(mac)
    vendor = vendor_lookup.lookup(mac)
    console.print(f"MAC Address: [cyan]{mac}[/cyan] | Resolved Vendor: [bold white]{vendor}[/bold white]")

# --- Command 20: wiguard vendor update ---
def cmd_vendor_update() -> None:
    print_title("Vendor Prefix OUI Database Update")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        progress.add_task(description="Downloading IEEE standards catalog...", total=None)
        success = vendor_lookup.update_from_web()
        
    if success:
        console.print("[bold green]Success:[/bold green] Updated OUI database with current manufacturers.")
    else:
        console.print("[bold red]Error:[/bold red] Online update failed. Falling back to offline dictionary.")

# --- Command 21: wiguard alert list ---
def cmd_alert_list() -> None:
    print_title("Security Alerts Summary")
    alerts = db_manager.get_alerts(only_active=True)
    
    if not alerts:
        console.print("[bold green]All quiet. No active threat alerts outstanding.[/bold green]")
        return
        
    table = Table()
    table.add_column("Alert ID", justify="center")
    table.add_column("Timestamp", style="cyan")
    table.add_column("SSID", style="bold white")
    table.add_column("BSSID")
    table.add_column("Threat Score", justify="center")
    table.add_column("Detection Reason", style="yellow")
    
    for a in alerts:
        table.add_row(
            str(a.id),
            a.timestamp,
            a.ssid,
            a.bssid,
            f"[bold red]{a.risk_score}[/bold red]",
            a.reason
        )
    console.print(table)

# --- Command 22: wiguard alert clear ---
def cmd_alert_clear() -> None:
    resolved_count = db_manager.resolve_all_alerts()
    console.print(f"[bold green]Success:[/bold green] Cleared/resolved {resolved_count} security alerts.")

# --- Command 23: wiguard stats ---
def cmd_stats() -> None:
    print_title("WiGuard Telemetry Dashboard")
    stats = history_manager.get_stats()
    trusted = db_manager.get_trusted_networks()
    
    total_trusted = len(trusted)
    risk_metric = "SECURE"
    risk_color = "green"
    
    if stats["active_alerts"] > 0:
        risk_metric = "CRITICAL THREAT"
        risk_color = "bold red"
    elif stats["highest_risk"] >= 50:
        risk_metric = "WARNING"
        risk_color = "bold yellow"
        
    console.print(f"Overall System Security State: [{risk_color}]{risk_metric}[/{risk_color}]")
    console.print(f"Registered Trusted Access Points: [cyan]{total_trusted}[/cyan]")
    console.print(f"Total Scans Performed:            [cyan]{stats['total_scans']}[/cyan]")
    console.print(f"Unresolved Alerts:                [red]{stats['active_alerts']}[/red]")
    console.print(f"Historical Highest Risk Score:    [magenta]{stats['highest_risk']}[/magenta]")

# --- Command 24: wiguard diag ---
def cmd_diag() -> None:
    print_title("Self-Diagnostic Diagnostics")
    
    # 1. OS check
    sys_name = sys.platform
    console.print(f"[*] Operating System identified: [cyan]{sys_name}[/cyan]")
    
    # 2. Database write test
    db_ok = False
    try:
        db_path = db_manager.db_path
        console.print(f"[*] Checking database location: [cyan]{db_path}[/cyan]")
        if db_path.parent.exists():
            db_ok = True
            console.print("  [green]✔ Database location is writeable.[/green]")
    except Exception as e:
        console.print(f"  [red]✖ Database check failed: {e}[/red]")
        
    # 3. Logging check
    log_ok = False
    try:
        log_file = Path(config_loader.get("log_file", "logs/wiguard.log"))
        console.print(f"[*] Checking log file path: [cyan]{log_file}[/cyan]")
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, "a", encoding="utf-8"):
            pass
        log_ok = True
        console.print("  [green]✔ Logging path is writeable.[/green]")
    except Exception as e:
        console.print(f"  [red]✖ Logging path check failed: {e}[/red]")

    # 4. WiFi adapter check (Platform specific)
    console.print("[*] Verifying native WiFi scan components...")
    try:
        if sys.platform.startswith("win"):
            # run netsh mock check
            from scanner.windows_scanner import run_netsh
            run_netsh()
            console.print("  [green]✔ Netsh native WiFi scan command available.[/green]")
        elif sys.platform.startswith("linux"):
            from scanner.linux_scanner import run_nmcli
            run_nmcli()
            console.print("  [green]✔ nmcli native WiFi scan command available.[/green]")
        elif sys.platform.startswith("darwin"):
            from scanner.mac_scanner import run_airport
            run_airport()
            console.print("  [green]✔ Airport native WiFi scan command available.[/green]")
        else:
            console.print("  [yellow]! Unsupported OS platform. System will use simulation scanner.[/yellow]")
    except Exception as e:
        console.print(f"  [yellow]! Native hardware scanner not available: {e}. Sim mode will be active.[/yellow]")

    # Final result
    if db_ok and log_ok:
        console.print("\n[bold green]Diagnostics SUCCESS. WiGuard is fully functional.[/bold green]")
    else:
        console.print("\n[bold red]Diagnostics WARNING: Configuration errors detected. Check permissions.[/bold red]")

# --- Command 25: wiguard version ---
def cmd_version() -> None:
    print_banner()
    console.print(f"[bold cyan]WiGuard Version:[/bold cyan] {APP_VERSION}")
    console.print(f"[bold cyan]Developed By:[/bold cyan]    {APP_AUTHOR}")
    console.print(f"[bold cyan]License:[/bold cyan]         {APP_LICENSE}")
    console.print("[bold cyan]Compatibility:[/bold cyan]   Windows (netsh), Linux (nmcli), macOS (airport)")
