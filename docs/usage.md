# WiGuard Usage Examples

This guide details typical workflows using WiGuard commands.

## Basic Scan
To execute a one-time scan of nearby networks:
```bash
wiguard scan
```

## Adding a Network to the Trusted Baseline
To add a network to the database of trusted access points, specify its SSID and BSSID:
```bash
wiguard trust add "MyHomeWiFi" "00:11:22:33:44:55"
```

## Setting up Monitoring Loop
To start real-time monitoring that scans every 10 seconds:
```bash
wiguard config set scan_interval 10
wiguard monitor
```

## Generating Reports
To generate a comprehensive report of nearby networks, threat levels, and trusted baselines:
```bash
wiguard report generate json
wiguard report list
```
