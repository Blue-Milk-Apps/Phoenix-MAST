# Androguard Android evidence extraction

Phoenix uses Androguard's Python API for DEX strings with method references, caller/callee relationships and parsed signing-certificate details. Android identity and component inventory come from aapt2; cryptographic signature verification comes from Apksigner.

## Local setup

Androguard is a project dependency:

```bash
uv sync
uv run python -c "from androguard.misc import AnalyzeAPK; print(AnalyzeAPK)"
uv run phoenix scan --android-binary path/to/app.apk
```

## Artifacts

Files are saved under `scan-results/.../androguard/`:

| File | Content |
| --- | --- |
| `strings.json` | DEX string values and referring methods. |
| `api_calls.json` | Caller/callee facts and call locations. |
| `certificates.json` | Certificate subjects, issuers, validity dates and fingerprints. |
| `report_summary.json` | Extraction, string, API and error counts. |
| `scan_index.json` | Artifact inventory and item counts. |
| `errors.json` | Extraction errors, when present. |

Strings and API records are evidence, without Python keyword categories or inferred vulnerabilities. Binary OpenGrep rules can inspect them. Certificate details enrich the report's signing inventory. Repeated manifest, permission, component and file inventories have been removed from this adapter.

An extraction error fails the tool execution while preserving partial artifacts. Archive-level DEX and certificate extraction reads the original APK; member exclusions apply to the separate extracted/decoded trees and do not rewrite the signed archive.
