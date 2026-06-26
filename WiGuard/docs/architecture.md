# WiGuard Architecture

## High-Level Flow

User → CLI Parser → Scanner → Parser → Detectors → Risk Engine → Output/Database/Reports

## Modules

- **scanner/**: Platform-specific WiFi scanning
- **detector/**: Individual detection logic
- **core/**: (planned) Orchestration
- **database/**: Trusted networks persistence
- **utils/**: Helpers, constants
- **cli/**: Command handling

See code for details.
