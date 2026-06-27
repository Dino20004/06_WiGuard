# WiGuard Architecture

WiGuard is a modular Python command-line utility for detecting Evil Twin wireless access points.

## System Block Diagram
```
                     User
                      │
                      ▼
              wiguard cli command
                      │
                      ▼
               [ CLI Parser ]
                      │
                      ▼
             [ Scanner module ]
             (OS Native Scanners)
                      │
                      ▼
            [ Network Parser ]
                      │
                      ▼
             [ Detector Pipeline ]
     ┌────────────────┼────────────────┬──────────────┐
     ▼                ▼                ▼              ▼
Duplicate SSID      Vendor         Encryption      Signal
  Detector         Detector         Detector      Detector
     │                │                │              │
     └────────────────┼────────────────┴──────────────┘
                      ▼
               [ Risk Engine ]
                      │
                      ▼
              [ SQLite Database ]
            (Baselines & History)
                      │
                      ▼
             [ Output Interfaces ]
              (Console, Report)
```

## Modules
1. **Scanner Module (`scanner/`)**: Handles scanning of nearby WiFi networks. Utilizes native command line utilities to discover networks across Windows, Linux, and macOS without requiring administrator/root privileges or specialized monitor mode NICs.
2. **Detector Module (`detector/`)**: Evaluates specific network properties against known safe configurations.
3. **Risk Engine (`detector/risk_engine.py`)**: Computes security scores (0-100) using weighted contributions of individual detectors.
4. **Database Module (`database/`)**: Manages SQLite storage for trusted baselines, past network sightings, alerts, and scans.
5. **Reports Module (`reports/`)**: Handles export functionalities (TXT, CSV, JSON).
6. **CLI Module (`cli/`)**: Defines commands and argument structures.
