# Androguard Android Evidence Scanner

AppcritIQ uses Androguard for Android static-analysis evidence extraction during APK binary scans. Androguard is a Python toolkit for Android APK and DEX analysis. It is static-analysis focused and is useful for APK metadata extraction, AndroidManifest parsing, DEX inspection, StringAnalysis, sensitive API detection, and cross-reference relationship extraction.

This system intentionally avoids full APK dumping. The goal is actionable Android security evidence extraction.

## Local Install

The dependency is listed in `pyproject.toml`, so the normal workflow is:

```bash
uv sync
```

If you need to install it manually into an existing environment:

```bash
uv pip install androguard
```

Verify the import path AppcritIQ uses:

```bash
uv run python -c "from androguard.misc import AnalyzeAPK; print(AnalyzeAPK)"
```

## AppcritIQ Usage

Run AppcritIQ against one APK at a time:

```bash
uv run appcritiq scan --android-binary-path path/to/app.apk
```

The Androguard scanner skips non-APK inputs. It emits deterministic machine-readable JSON files under:

```text
scan-results/.../androguard/
```

## Generated Outputs

The scanner writes one JSON artifact per evidence category:

| File | Purpose |
| --- | --- |
| `metadata.json` | Package, app, SDK, version, and framework indicator metadata. |
| `manifest.json` | Parsed AndroidManifest XML representation. |
| `permissions.json` | Requested and declared permissions. |
| `components.json` | Activities, services, receivers, providers, intent filters, permissions, and exported indicators. |
| `strings.json` | High-signal strings with categories and method context. |
| `api_calls.json` | Security-relevant API call evidence with caller/callee context. |
| `xrefs.json` | Shallow high-value relationships such as string-to-method and method-to-sensitive-API. |
| `native_libs.json` | Native library inventory. |
| `assets.json` | APK asset inventory. |
| `certificates.json` | Signing certificate details and fingerprints by signing scheme. |
| `files.json` | APK file inventory. |
| `findings.json` | Evidence candidates assembled from extracted indicators. |
| `report_summary.json` | Counts, package metadata, framework indicators, and limitations. |
| `scan_index.json` | Output index with item counts and partial-failure flags. |
| `errors.json` | Extraction-stage errors captured during partial failures. |

`callgraph.gml` is intentionally not generated in v1. It can be added later as an optional output if a workflow needs graph tooling.

## Extraction Philosophy

AppcritIQ treats Androguard output as structured AppSec evidence, not as a reverse-engineering dump. The extractor favors high-signal evidence, contextual enrichment, deterministic JSON, and downstream automation.

The scanner preserves raw values, including strings, URLs, endpoints, and token-like values. Redaction is intentionally not performed in this layer because downstream systems may need exact evidence for correlation, triage, or policy matching.

Strings, API calls, and xrefs are selectively extracted. They are filtered for security relevance and enriched with class, method, descriptor, signature, offset, category, and xref context where available.

## High-Signal Strategy

The scanner prioritizes evidence related to:

- URLs, domains, endpoints, and IP addresses
- authentication indicators, secrets, tokens, JWTs, and API-key markers
- Firebase and cloud provider indicators
- crypto usage and keystore usage
- TLS and trust-management handling
- WebView usage
- reflection and dynamic loading
- Runtime execution
- exported components and intent filters
- dangerous or sensitive Android permissions

It intentionally avoids dumping every string, method, opcode, and framework API call.

## XREF Strategy

`xrefs.json` preserves only high-value 1-hop relationships:

- `STRING_TO_METHOD`
- `METHOD_TO_SENSITIVE_API`
- `METHOD_TO_DYNAMIC_LOADING`
- `METHOD_TO_REFLECTION`
- `METHOD_TO_NETWORKING`

The scanner avoids full transitive graph dumping in JSON. Relationship records are intended to connect evidence to enough local context for downstream analysis without creating a complete call graph.

## Findings Philosophy

findings.json contains evidence candidates, not final vulnerability conclusions.

Findings are contextual observations assembled from extracted evidence. They include severity, confidence, mappings, source artifact references, and evidence snippets. They are not exploit claims and should be interpreted by downstream security analysis systems, policy engines, or analysts.

## Static-Analysis Limitations

The scanner reports static evidence only. Results may be incomplete when behavior depends on:

- reflection
- dynamic loading
- encrypted or generated strings
- native libraries
- Flutter
- React Native
- Cordova
- Unity
- Xamarin
- runtime-only behavior

Framework indicators may be detected in `metadata.json` and summarized in `report_summary.json`, but framework-specific runtime behavior may require additional analysis.

## Operational Behavior

The scanner is designed for CI/CD and automation workflows:

- one APK per scan
- deterministic JSON output names
- stable artifact categories
- partial failure tolerance
- stage-level errors captured in `errors.json`
- no PDF or human-report generation
- no full decompilation workflow

If one extractor fails, AppcritIQ records the failure in `errors.json`, emits a partial artifact for that stage, and continues extraction where possible.

## Why Androguard

Androguard is a good fit for AppcritIQ because it provides APK and DEX analysis from Python, including manifest parsing, DEX metadata, StringAnalysis, xrefs, and API relationship extraction. Its Python API is suitable for repeatable local scans, CI jobs, and downstream JSON evidence generation without shelling out to a decompiler pipeline.

## What This Scanner Avoids

The Androguard scanner intentionally avoids:

- full APK dumping
- full opcode dumps
- dumping every API call
- dumping every method
- complete transitive call graphs
- PDF-style human reporting
- full decompilation workflows

The goal is concise, actionable Android security evidence that can be consumed by automated systems.
