# aapt2 Android evidence extraction

Phoenix runs aapt2 against the original APK to obtain package identity, manifest attributes, permissions, components, intent filters and resource facts. This is the primary Android binary identity/component inventory.

## Setup

For local execution, place Android SDK Build Tools' `aapt2` on `PATH`. The Docker image installs Debian's `aapt` package, which supplies `aapt2`.

```bash
aapt2 version
uv run phoenix scan --android-binary path/to/app.apk
```

## Executions and artifacts

The adapter invokes `aapt2 dump badging`, `dump permissions`, `dump xmltree --file AndroidManifest.xml` and `dump resources`. Stdout and stderr are retained under `aapt2/raw/`.

Normalized artifacts under `aapt2/` include:

| Artifacts | Content |
| --- | --- |
| `aapt2_evidence.json`, `execution_metadata.json` | Combined evidence, command outcomes, durations, parser errors and provenance. |
| `metadata.json`, `identity.json` | Package, version, SDK and application labels. |
| `application.json`, `manifest_security_posture.json` | Explicit manifest attributes and inventory counts. |
| `permissions.json` | Permission declarations and protection-level hints. |
| `components.json`, `intent_filters.json` | Components, explicit exported values and declared intent filters/URI patterns. |
| `resource_summary.json` | Counts by resource type; complete resource text remains in raw output. |
| `evidence_relationships.json` | Manifest relationships between declarations. |
| `correlation_requirements.json`, `limitations.json`, `scan_index.json` | Extraction boundaries and artifact index. |

Python resource-keyword classification, authentication-name guesses and suggested vulnerability-review candidates have been removed. Security findings belong to OpenGrep rules, which can inspect the normalized and raw evidence. Missing exported attributes remain unknown; the adapter does not infer runtime reachability.

Any command or parse failure makes the tool execution fail, retaining available evidence. Excluding members of the separate extracted/decoded tree does not rewrite the original APK read by aapt2.
