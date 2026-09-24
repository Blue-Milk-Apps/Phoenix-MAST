# Phoenix MAST

Phoenix MAST coordinates mobile security scanners for iOS, Android, Flutter, and React Native. It collects scanner artifacts, assembles evidence, and generates JSON and PDF reports. Docker provides the scanner tools; the Python application controls their execution and reporting.

The engine is public. Detection rules are supplied separately and can remain private. The `rules/` placeholder does not contain a working ruleset.

## Interactive Docker workflow

The image intentionally starts **Bash**. Mount the application, a private rules tree, and an output directory, then run Phoenix inside the container:

```bash
mkdir -p scan-results

docker run --rm -it \
  -v "/path/to/application:/workspace:ro" \
  -v "/path/to/Phoenix-Rules/rules:/app/rules:ro" \
  -v "$PWD/scan-results:/app/results" \
  ghcr.io/blue-milk-apps/phoenix-mast:<tag>

# Inside the container:
phoenix scan --native-ios-source-path /workspace \
  --output /app/results
```

For an automated run, override the entrypoint explicitly:

```bash
docker run --rm --entrypoint phoenix \
  -v "/path/to/application:/workspace:ro" \
  -v "/path/to/Phoenix-Rules/rules:/app/rules:ro" \
  -v "$PWD/scan-results:/app/results" \
  ghcr.io/blue-milk-apps/phoenix-mast:<tag> \
  scan --native-ios-source-path /workspace \
  --output /app/results
```

The container uses `/app/rules` automatically, regardless of the working directory. No `--rules-root` flag is needed. Mount or install private rules at that location; the scan target flag selects the platform and source/binary subdirectory.

You only need directories relevant to your scan. For an iOS-only source scan, you can mount just `rules/ios/source` at `/app/rules/ios/source`. Mounting the whole private `rules/` tree at `/app/rules` is convenient for mixed-platform work; Phoenix still selects only the relevant directories.

Private rules can also be supplied in an internal customer image. Keep them out of the public engine repository and public image build context.

## Container publishing

The [container workflow](.github/workflows/container.yml) runs on every branch push and pull request, and can also be started manually from GitHub Actions. It runs the public unit tests, builds a Linux AMD64 image, and verifies an offline iOS scan and PDF report using a synthetic rule. Private rules are excluded from the Docker build context and are never needed by CI.

Successful branch pushes publish to `ghcr.io/blue-milk-apps/phoenix-mast`:

- `branch-<branch>` follows that branch, with slashes replaced by hyphens (for example, `branch-feature-ios-review`).
- `sha-<full-commit-sha>` identifies the source commit used for the build.
- `latest` is updated only by `main`. The `develop` branch publishes `branch-develop`.

Pull requests build and verify without publishing. Manual runs publish the selected branch with the same tagging rules. GitHub Actions authenticates using its `GITHUB_TOKEN` with `packages: write`; no registry password or private rules token is required. The repository must have Actions access to the GHCR package. Superseded runs on the same branch are canceled, and Docker layers are cached between builds.

The image currently targets `linux/amd64`, including several architecture-specific scanner downloads. On Apple Silicon, add `--platform linux/amd64` to Docker build and run commands. The Bash entrypoint remains available for interactive use.

## Scan target flags

Pass exactly one target flag. It determines the scan platform and mode; rule directory names do not choose the scan mode.

| Target flag | Input | Rules relative to the rules root (`/app/rules` in Docker) |
| --- | --- | --- |
| `--native-ios-source-path` | iOS source directory | `ios/source` |
| `--native-android-source-path` | Android source directory | `android/source` |
| `--flutter-source-path` | Flutter source directory | `flutter/source`, `ios/source`, `android/source` |
| `--react-native-source-path` | React Native source directory | `react_native/source`, `ios/source`, `android/source` |
| `--ios-binary-path` | IPA file | `ios/binary` |
| `--android-binary-path` | APK file | `android/binary` |

Flutter and React Native scans preserve separate targets for each ruleset: framework rules scan production framework sources, iOS rules scan `ios/`, and Android rules scan `android/`. Missing embedded-platform directories are recorded as skipped scopes. The common OpenGrep adapter also accepts multiple configuration paths for a shared target.

Binary OpenGrep scans consume the generated `strings` artifacts. They require rules specifically written for that input. Binary rules are being deferred while source reporting is migrated; an absent binary directory produces unavailable coverage. Phoenix never automatically substitutes source rules. Other binary scanners still run. See [iOS build notes](docs/UnsignediOSBinaries.md) for preparing an IPA.

The Docker image sets `PHOENIX_RULES_ROOT=/app/rules`. Local runs can use `--rules-root` or `PHOENIX_RULES_ROOT` to select a private checkout; the flag takes precedence. With neither configured, local runs search the engine's `rules/` tree and `/app/rules`. A target-specific override takes precedence for its primary ruleset:

```text
--native-ios-source-opengrep-rules-path
--native-android-source-opengrep-rules-path
--flutter-source-opengrep-rules-path
--react-native-source-opengrep-rules-path
--ios-binary-opengrep-rules-path
--android-binary-opengrep-rules-path
```

For framework scans, the configured root also selects the embedded native rules. Inside Docker these are `/app/rules/ios/source` and `/app/rules/android/source`. Without a configured root, embedded rules are resolved from the same `rules/<platform>/source` tree as the framework override.

## iOS rules and reporting

Store category files at `rules/ios/source/<category>.yml`. The filename supplies the report category. Every iOS rule supplies its own ID, severity, message, detection pattern, and reporting metadata:

- `title`, `description`, `scope`, and `impact`
- `finding_type`: `weakness`, `review`, `control`, or `observation`
- `remediation.guidance` and optional `remediation.resources`
- optional `compliance` mappings and `reference`

`metadata.category` and `metadata.capability_type` are rejected. There is no iOS Python rule registry: new IDs and categories appear in reports from YAML metadata. Android, Flutter, and React Native retain their existing reporting contracts until their schema migrations.

The scan artifact records the loaded metadata, ruleset fingerprint, execution outcome for every rule, and original matches. Report generation uses that snapshot, so later YAML changes do not change an existing scan's meaning.

Matched weaknesses contribute to vulnerability counts. Reviews, controls, and observations remain separately identified. A control match does not cancel a weakness. No-match outcomes mean only that a successfully completed rule found no matches in the evaluated inputs. Incomplete executions remain **Not Evaluated**, and positive matches from partial scans are retained.

## Scanners and artifacts

Source workflows include Gitleaks, TruffleHog, Syft, OpenGrep, and platform metadata extraction. Binary workflows use Strings plus platform tools such as LIEF, ipsw, Androguard, Apktool, Apksigner, and APKiD. MobSF is optional for binary scans. Missing external tools are recorded as unavailable rather than as completed clean scans.

The output directory contains per-scanner artifacts, `opengrep_results.json`, scan metadata, `post_scan_processing.json`, and the PDF report. OpenGrep coverage and individual rule outcomes are included in the report. Artifact filenames and subdirectories for other tools depend on the target.

## Local development

```bash
uv sync
uv run phoenix scan --native-ios-source-path /path/to/application \
  --rules-root /path/to/Phoenix-Rules/rules --output ./scan-results
uv run pytest
```

Python dependencies alone do not install all external scanner binaries. Install the tools needed for your workflow, or use Docker. Local OpenGrep execution currently checks for both `opengrep` and `opengrep-core`. PDF generation also needs the native libraries required by WeasyPrint, including Pango. See [tool setup](setup/README.md).

Public unit tests use synthetic rules. Tests against a private bundle are opt-in:

```bash
PHOENIX_RULES_ROOT=/path/to/Phoenix-Rules/rules uv run pytest
```

The application uses ports and adapters: `domain/` defines evidence and report models, `application/` orchestrates workflows, `ports/` defines external interfaces, and `adapters/` implements scanners, storage, and report output. The CLI is in `entrypoints/cli.py`.

## Local containers and MobSF

```bash
make build
make run PROJECT_PATH=/path/to/application \
  RULES_PATH=/path/to/Phoenix-Rules/rules SCAN_FLAG=--native-ios-source-path

make compose-run PROJECT_PATH=/path/to/app.ipa \
  RULES_PATH=/path/to/Phoenix-Rules/rules SCAN_FLAG=--ios-binary-path
```

The wrappers override the Bash entrypoint for their automated scans. Quote paths containing spaces. When `PROJECT_PATH` is a file, its parent directory is mounted and the filename becomes the scan target.

To enable MobSF, start the sidecar and supply its URL:

```bash
make services-up
MOBSF_URL=http://localhost:8000 uv run phoenix scan --ios-binary-path /path/to/app.ipa
make services-down
```

For a Compose scan, use `MOBSF_URL=http://mobsf-scanner:8000` after starting the sidecar. Configure `MOBSF_API_KEY` to match the service.

Phoenix MAST is maintained by Blue Milk Apps and released under the [Apache License 2.0](LICENSE).
