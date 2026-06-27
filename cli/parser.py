"""
CLI Argument Parser Module for WiGuard.
Handles setup of argparse, commands routing, and subcommands definition.
"""
import argparse
import sys
from typing import List, Sequence

from cli.commands import (
    cmd_scan, cmd_monitor, cmd_trust_add, cmd_trust_remove, cmd_trust_list,
    cmd_trust_import, cmd_trust_export, cmd_trust_clear, cmd_list,
    cmd_report_generate, cmd_report_list, cmd_report_view, cmd_history_show,
    cmd_history_clear, cmd_history_stats, cmd_config_show, cmd_config_set,
    cmd_config_reset, cmd_vendor_lookup, cmd_vendor_update, cmd_alert_list,
    cmd_alert_clear, cmd_stats, cmd_diag, cmd_version
)

def create_parser() -> argparse.ArgumentParser:
    """Creates and configures the main argument parser for WiGuard."""
    parser = argparse.ArgumentParser(
        description="WiGuard - WiFi Evil Twin Attack Detection CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  wiguard scan
  wiguard monitor
  wiguard trust list
  wiguard trust add "OfficeWiFi" "00:11:22:33:44:55"
  wiguard report generate json
  wiguard config set scan_interval 10
  wiguard alert list
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="WiGuard command to run")

    # Command 1: scan
    p_scan = subparsers.add_parser("scan", help="Scan nearby WiFi networks for threat assessments")
    p_scan.add_argument("--simulate", action="store_true", help="Force simulated scan data")

    # Command 2: monitor
    p_monitor = subparsers.add_parser("monitor", help="Start continuous real-time WiFi threat monitor")
    p_monitor.add_argument("--simulate", action="store_true", help="Force simulated scan data")

    # Trust subcommands: wiguard trust <add|remove|list|clear|import|export>
    p_trust = subparsers.add_parser("trust", help="Configure trusted network baseline profiles")
    trust_sub = p_trust.add_subparsers(dest="trust_command", help="Trust subcommand")
    
    # trust add (Command 3)
    p_tadd = trust_sub.add_parser("add", help="Add a network to trusted baseline list")
    p_tadd.add_argument("ssid", type=str, help="SSID of the network")
    p_tadd.add_argument("bssid", type=str, help="BSSID (MAC Address) of the network")
    p_tadd.add_argument("--simulate", action="store_true", help="Resolve settings via simulation scan")

    # trust remove (Command 4)
    p_tremove = trust_sub.add_parser("remove", help="Remove network baseline from trusted list")
    p_tremove.add_argument("ssid", type=str, help="SSID of the network")
    p_tremove.add_argument("bssid", type=str, nargs="?", default=None, help="BSSID (MAC Address) of the network (optional)")

    # trust list (Command 5)
    trust_sub.add_parser("list", help="List all trusted baseline profiles")

    # trust import (Command 6)
    p_timport = trust_sub.add_parser("import", help="Import trusted profiles from file")
    p_timport.add_argument("file", type=str, help="Path to JSON or CSV file to import")

    # trust export (Command 7)
    p_texport = trust_sub.add_parser("export", help="Export trusted profiles to file")
    p_texport.add_argument("file", type=str, help="Export filepath ending in .json or .csv")

    # trust clear (Command 8)
    trust_sub.add_parser("clear", help="Clear all trusted baseline entries")

    # Command 9: list
    subparsers.add_parser("list", help="List nearby networks discovered during latest scan")

    # Report subcommands: wiguard report <generate|list|view>
    p_report = subparsers.add_parser("report", help="Generate and manage scan reports")
    report_sub = p_report.add_subparsers(dest="report_command", help="Report subcommand")
    
    # report generate (Command 10)
    p_rgen = report_sub.add_parser("generate", help="Compile and save security threat report")
    p_rgen.add_argument("format", choices=["txt", "csv", "json"], help="File format format to export")

    # report list (Command 11)
    report_sub.add_parser("list", help="List all generated report documents")

    # report view (Command 12)
    p_rview = report_sub.add_parser("view", help="View summary details of a specific report")
    p_rview.add_argument("filename", type=str, help="Report filename (e.g. wiguard_report_xxx.json)")

    # History subcommands: wiguard history <show|clear|stats>
    p_history = subparsers.add_parser("history", help="Query or clear scan telemetry history")
    history_sub = p_history.add_subparsers(dest="history_command", help="History subcommand")
    
    # history show (Command 13)
    history_sub.add_parser("show", help="Display scan history logs")
    
    # history clear (Command 14)
    history_sub.add_parser("clear", help="Clear scan history logs database table")
    
    # history stats (Command 15)
    history_sub.add_parser("stats", help="Show statistical metrics over historical scans")

    # Config subcommands: wiguard config <show|set|reset>
    p_config = subparsers.add_parser("config", help="Modify or view application configurations")
    config_sub = p_config.add_subparsers(dest="config_command", help="Config subcommand")
    
    # config show (Command 16)
    config_sub.add_parser("show", help="View current configuration settings")
    
    # config set (Command 17)
    p_cset = config_sub.add_parser("set", help="Modify a configuration parameter value")
    p_cset.add_argument("key", type=str, help="Configuration key to modify")
    p_cset.add_argument("value", type=str, help="New value for the setting")
    
    # config reset (Command 18)
    config_sub.add_parser("reset", help="Reset settings to defaults")

    # Vendor subcommands: wiguard vendor <lookup|update>
    p_vendor = subparsers.add_parser("vendor", help="OUI vendor database lookup and updates")
    vendor_sub = p_vendor.add_subparsers(dest="vendor_command", help="Vendor subcommand")
    
    # vendor lookup (Command 19)
    p_vlookup = vendor_sub.add_parser("lookup", help="Look up OUI manufacturer name of a MAC address")
    p_vlookup.add_argument("mac", type=str, help="MAC Address to query")
    
    # vendor update (Command 20)
    vendor_sub.add_parser("update", help="Update standard manufacturer prefixes dataset from web")

    # Alert subcommands: wiguard alert <list|clear>
    p_alert = subparsers.add_parser("alert", help="View or acknowledge security alerts")
    alert_sub = p_alert.add_subparsers(dest="alert_command", help="Alert subcommand")
    
    # alert list (Command 21)
    alert_sub.add_parser("list", help="List active unacknowledged threat alerts")
    
    # alert clear (Command 22)
    alert_sub.add_parser("clear", help="Acknowledge/clear all threat alerts")

    # Command 23: stats
    subparsers.add_parser("stats", help="Display overall system metrics dashboard")

    # Command 24: diag
    subparsers.add_parser("diag", help="Run system diagnostics tests")

    # Command 25: version
    subparsers.add_parser("version", help="Display application version, author, and info")

    return parser

def parse_and_route(args: Sequence[str] | None = None) -> None:
    """Parses standard arguments and executes the matched command functions."""
    parser = create_parser()
    parsed_args = parser.parse_args(args)

    if not parsed_args.command:
        parser.print_help()
        sys.exit(0)

    # Route top-level commands
    cmd = parsed_args.command
    if cmd == "scan":
        cmd_scan(force_simulate=parsed_args.simulate)
    elif cmd == "monitor":
        cmd_monitor(force_simulate=parsed_args.simulate)
    elif cmd == "list":
        cmd_list()
    elif cmd == "stats":
        cmd_stats()
    elif cmd == "diag":
        cmd_diag()
    elif cmd == "version":
        cmd_version()
        
    # Route trust subcommands
    elif cmd == "trust":
        tcmd = parsed_args.trust_command
        if not tcmd:
            parser.parse_args([cmd, "--help"])
            sys.exit(0)
            
        if tcmd == "add":
            cmd_trust_add(parsed_args.ssid, parsed_args.bssid, force_simulate=parsed_args.simulate)
        elif tcmd == "remove":
            cmd_trust_remove(parsed_args.ssid, parsed_args.bssid)
        elif tcmd == "list":
            cmd_trust_list()
        elif tcmd == "import":
            cmd_trust_import(parsed_args.file)
        elif tcmd == "export":
            cmd_trust_export(parsed_args.file)
        elif tcmd == "clear":
            cmd_trust_clear()
            
    # Route report subcommands
    elif cmd == "report":
        rcmd = parsed_args.report_command
        if not rcmd:
            parser.parse_args([cmd, "--help"])
            sys.exit(0)
            
        if rcmd == "generate":
            cmd_report_generate(parsed_args.format)
        elif rcmd == "list":
            cmd_report_list()
        elif rcmd == "view":
            cmd_report_view(parsed_args.filename)
            
    # Route history subcommands
    elif cmd == "history":
        hcmd = parsed_args.history_command
        if not hcmd:
            parser.parse_args([cmd, "--help"])
            sys.exit(0)
            
        if hcmd == "show":
            cmd_history_show()
        elif hcmd == "clear":
            cmd_history_clear()
        elif hcmd == "stats":
            cmd_history_stats()
            
    # Route config subcommands
    elif cmd == "config":
        ccmd = parsed_args.config_command
        if not ccmd:
            parser.parse_args([cmd, "--help"])
            sys.exit(0)
            
        if ccmd == "show":
            cmd_config_show()
        elif ccmd == "set":
            cmd_config_set(parsed_args.key, parsed_args.value)
        elif ccmd == "reset":
            cmd_config_reset()
            
    # Route vendor subcommands
    elif cmd == "vendor":
        vcmd = parsed_args.vendor_command
        if not vcmd:
            parser.parse_args([cmd, "--help"])
            sys.exit(0)
            
        if vcmd == "lookup":
            cmd_vendor_lookup(parsed_args.mac)
        elif vcmd == "update":
            cmd_vendor_update()
            
    # Route alert subcommands
    elif cmd == "alert":
        acmd = parsed_args.alert_command
        if not acmd:
            parser.parse_args([cmd, "--help"])
            sys.exit(0)
            
        if acmd == "list":
            cmd_alert_list()
        elif acmd == "clear":
            cmd_alert_clear()
            
    else:
        parser.print_help()
