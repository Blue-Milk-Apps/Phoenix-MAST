# Apktool Evidence Extractor Setup

AppcritIQ uses apktool during APK binary scans to reconstruct Android semantics into a temporary workspace. AppcritIQ keeps normalized JSON evidence and removes the decoded project after extraction.

## Local Install

On macOS with Homebrew:

```bash
brew install apktool
apktool --version
```

On Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y apktool
apktool --version
```

AppcritIQ checks availability with the `apktool` command on `PATH`.

## Docker Install

The AppcritIQ Docker image installs a pinned apktool wrapper and JAR into `/usr/local/bin` and verifies it during the image build:

```bash
docker compose build appcritiq
docker compose run --rm appcritiq --help
```

## AppcritIQ Usage

Apktool runs automatically during APK binary scans:

```bash
uv run appcritiq scan --android-binary-path path/to/app.apk
```

The scanner skips non-APK inputs. It emits deterministic JSON artifacts under:

```text
scan-results/.../apktool/
```

## Generated Outputs

The scanner writes compact evidence artifacts rather than persisting the full decoded APK project:

| File | Purpose |
| --- | --- |
| `decode_metadata.json` | Tool version, APK hash, decode exit code, partial-success state, and command output summaries. |
| `manifest_summary.json` | Package, version, and application-level manifest flags. |
| `permissions.json` | Requested and declared permissions. |
| `attack_surface.json` | Activities, services, receivers, providers, exported state, permissions, and intent filters. |
| `deep_links.json` | Deep-link schemes, hosts, paths, actions, categories, and owning activities. |
| `network_security_config.json` | Network security config references, domains, cleartext policy, trust anchors, pins, and debug overrides. |
| `trust_boundaries.json` | Evidence records that describe app boundary crossings such as exported components. |
| `code_indicators.json` | Bounded smali/XML indicators for WebView, reflection, dynamic loading, crypto, trust management, and runtime execution. |
| `secrets_endpoints.json` | Bounded endpoint and secret-marker evidence with short line context. |
| `native_libraries.json` | Native library inventory with ABI, path, size, and SHA-256. |
| `assets_inventory.json` | Security-relevant asset inventory with path, size, suffix, and SHA-256. |
| `extraction_errors.json` | Extraction-stage errors captured during partial failures. |
| `evidence_index.json` | Artifact index and item counts. |

## Extraction Philosophy

AppcritIQ treats apktool as Android semantic reconstruction infrastructure, not as a long-term APK dump. The scanner prioritizes high-signal, provenance-rich AppSec evidence that downstream systems can enrich into findings later.

The decoded apktool workspace is temporary. AppcritIQ preserves contextual relationships in JSON artifacts and avoids storing full smali trees, giant string dumps, or UI-focused decoded resources.
