# Domain Models

Core business entities used throughout the application. Defined in `models.py`.

## Models

| Class | Purpose |
|-------|---------|
| `ScanType` | Enum of scanner identifiers: `mobsf_scanner`, `lief`, `androguard`, `apktool`, `apksigner`, `apkid`, `ipsw`, `trufflehog`, `gitleaks`, `strings`, `plist_source`, `plist_binary`, `dependency_check`, and `syft` |
| `ScanResult` | Result from one scanner — scanner name, success/error state, and raw output |
| `ScanConfig` | Configuration for a scan session — paths, enabled scans, rules path, and ignore settings |

## Key Design Notes

- All models are `@dataclass` for simplicity
- `ScanResult.raw_output` stores raw scanner output without parsing or normalization
- `ScanConfig.display_project_path` stores a shorter label for terminal output when the displayed path should differ from the resolved local path
