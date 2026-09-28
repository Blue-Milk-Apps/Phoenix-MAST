# Apktool Evidence Extractor Setup

Phoenix uses Apktool during APK binary scans to decode XML, smali and resources. It keeps the decoded tree under `apktool/decoded/`, alongside normalized configuration evidence, for subsequent tool executions.

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

phoenix checks availability with the `apktool` command on `PATH`.

## Docker Install

The phoenix Docker image installs a pinned apktool wrapper and JAR into `/usr/local/bin` and verifies it during the image build:

```bash
docker compose build phoenix
docker compose run --rm phoenix --help
```

## phoenix Usage

Apktool runs automatically during APK binary scans:

```bash
uv run phoenix scan --android-binary path/to/app.apk
```

The scanner skips non-APK inputs. It emits deterministic JSON artifacts under:

```text
scan-results/.../apktool/
```

## Generated Outputs

The adapter writes these artifacts and retains the decoded project:

| File | Purpose |
| --- | --- |
| `decode_metadata.json` | Tool version, APK hash, decode exit code, partial-success state, and command output summaries. |
| `manifest_summary.json` | Package, version, and application-level manifest flags. |
| `permissions.json` | Requested and declared permissions. |
| `attack_surface.json` | Activities, services, receivers, providers, exported state, permissions, and intent filters. |
| `deep_links.json` | Deep-link schemes, hosts, paths, actions, categories, and owning activities. |
| `network_security_config.json` | Network security config references, domains, cleartext policy, trust anchors, pins, and debug overrides. |
| `trust_boundaries.json` | Evidence records that describe app boundary crossings such as exported components. |
| `native_libraries.json` | Native library inventory with ABI, path, size, and SHA-256. |
| `assets_inventory.json` | Security-relevant asset inventory with path, size, suffix, and SHA-256. |
| `extraction_errors.json` | Extraction-stage errors captured during partial failures. |
| `evidence_index.json` | Artifact index and item counts. |

## Tool ownership

Apktool supplies decoded inputs and configuration inventories. OpenGrep owns vulnerability detection; Gitleaks and TruffleHog own credential detection. Phoenix no longer applies Python smali or secret-marker regex classifiers to the decoded tree.

`--exclude` patterns remove matching files from the disposable decoded tree before its inventories and downstream tools execute. A decode or extraction error fails the tool execution while preserving available artifacts.
