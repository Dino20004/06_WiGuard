# WiGuard Installation Guide

WiGuard requires Python 3.12 or newer. Follow the instructions for your platform below.

## Windows
1. Open PowerShell or Command Prompt.
2. Clone or download the repository.
3. Install dependencies and the tool:
   ```powershell
   pip install .
   ```
4. Verify the installation:
   ```powershell
   wiguard diag
   ```

## Linux
1. Install network utility commands (`nmcli` or `iw`). On Ubuntu/Debian:
   ```bash
   sudo apt-get install network-manager
   ```
2. Clone the repository and install:
   ```bash
   pip install .
   ```
3. Run the diagnostics to verify the adapter setup:
   ```bash
   wiguard diag
   ```

## macOS
1. Ensure the airport command is accessible (on newer versions of macOS, command line tools or system library utilities must be enabled).
2. Install WiGuard:
   ```bash
   pip install .
   ```
3. Run the diagnostics:
   ```bash
   wiguard diag
   ```
