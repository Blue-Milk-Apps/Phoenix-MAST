# Phoenix MAST

Phoenix MAST coordinates mobile security scanners for iOS, Android, Flutter, and React Native. It collects scanner artifacts, assembles evidence, and generates JSON and PDF reports. Docker provides the scanner tools; the Python application controls their execution and reporting.

The engine is public. Detection rules are maintained privately in Phoenix-Rules and supplied at runtime. The public image contains the engine and scanner tools.

## Interactive Docker workflow

The image starts **Bash** and targets `linux/amd64`. Put your private YAML rules in the matching folders under `rules/`, then mount the application, rules, and output directory. Replace `<tag>` with a published image tag.

```bash
mkdir -p scan-results

docker run --rm -it --platform linux/amd64 \
  -v "/path/to/application:/workspace:ro" \
  -v "$PWD/rules:/app/rules:ro" \
  -v "$PWD/scan-results:/app/results" \
  "ghcr.io/blue-milk-apps/phoenix-mast:<tag>"

# Inside the container:
phoenix scan --ios-source /workspace \
  --output /app/results
```

For an automated run, override the entrypoint explicitly:

```bash
docker run --rm --platform linux/amd64 --entrypoint phoenix \
  -v "/path/to/application:/workspace:ro" \
  -v "$PWD/rules:/app/rules:ro" \
  -v "$PWD/scan-results:/app/results" \
  "ghcr.io/blue-milk-apps/phoenix-mast:<tag>" \
  scan --ios-source /workspace \
  --output /app/results
```

The empty rule folders are included in the checkout:

```text
rules/
  android/
    source/
    binary/
  ios/
    source/
    binary/
  flutter/
    source/
    binary/
  react_native/
    source/
    binary/
```

Add your custom OpenGrep yml rules files accordingly, and the scan target flag will use the required folders mounted under `/app/rules` automatically.

## Scan target flags

Pass exactly one target flag to choose the scan platform, source/binary mode, and input path.

| Target flag | Input | Rule directories under `/app/rules` |
| --- | --- | --- |
| `--ios-source` | iOS source directory | `ios/source` |
| `--android-source` | Android source directory | `android/source` |
| `--flutter-source` | Flutter source directory | `flutter/source`, `ios/source`, `android/source` |
| `--react-native-source` | React Native source directory | `react_native/source`, `ios/source`, `android/source` |
| `--ios-binary` | IPA file | `ios/binary` |
| `--android-binary` | APK file | `android/binary` |

Flutter and React Native scans apply framework rules to production framework sources, iOS rules to `ios/`, and Android rules to `android/`. Mount the relevant platform directories together under `/app/rules`. Missing embedded-platform source directories are recorded as skipped scopes.

Binary OpenGrep scans run against extracted `strings` output.

## Scanners and artifacts

Source workflows include Gitleaks, TruffleHog, Syft, OpenGrep, and platform metadata extraction. Binary workflows use Strings plus platform tools such as LIEF, ipsw, Androguard, Apktool, Apksigner, and APKiD. Missing external tools are recorded as unavailable rather than as completed clean scans.

The output directory contains per-scanner artifacts, `opengrep_results.json`, scan metadata, `post_scan_processing.json`, and the PDF report. Artifact filenames and subdirectories for other tools depend on the target.

`post_scan_processing.json` is the final report aggregate (`schema_version: 1`). JSON and PDF use the same findings, severity counts, risk summaries, coverage, secret-scan results, and platform details. The aggregate replaces the previous intermediate JSON structure:

| Content | Aggregate field |
| --- | --- |
| App identity and scan target | `metadata`, `metadata.target` |
| Matched checks, evidence, and remediation | `vulnerability_sections[].checks[]` |
| Weakness counts by severity | `findings_severity` |
| Category risks and explanations | `risk_summary`, `overall_evaluation` |
| OpenGrep execution coverage | `rule_status`, `rule_status_reason`, `rule_coverage` |
| Functionality, URL schemes, and other platform details | `platform_details` |
| Secret-scanner outcomes | `secret_scans` |

Raw scanner artifacts retain the original rule definitions and scanner output. To render a saved aggregate without rerunning scanners or assessments, use `ReportData.from_dict(json.loads(path.read_text()))` from `domain.report`, then pass that model to `PdfReportGenerator.generate`. The loader requires schema version 1 and complete model fields; it does not convert older intermediate JSON or fill missing findings with defaults.

## Local development

With Python 3.12+ and `uv` installed, run from this checkout:

```bash
uv sync
uv run pytest
```

Unit tests use synthetic rules. PDF tests also require [Pango and its native dependencies](setup/README.md#phoenix-pdf-report-setup).

## Local containers

Build an image from this checkout:

```bash
docker build --platform linux/amd64 -t phoenix:local .
```

Follow the [Docker examples above](#interactive-docker-workflow), using `phoenix:local` as the image name.

Phoenix MAST is maintained by Blue Milk Apps and released under the [Apache License 2.0](LICENSE).
