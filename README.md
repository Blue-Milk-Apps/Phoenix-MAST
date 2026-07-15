# AppCritIQ Core

AppCritIQ Core is an open source mobile application security testing toolkit for iOS and Android. It packages a practical set of OSS security and analysis tools into a Docker-first workflow, then adds lightweight Python orchestration so teams can run repeatable checks against source projects and mobile binaries.

The project is intentionally modular. Scanner adapters live behind stable ports, so AppCritIQ can be extended, slimmed down, or customized for a specific review process without rewriting the whole pipeline.

## Features

- Static analysis orchestration for iOS, Android, Flutter, and React Native projects
- Secret detection with OSS scanners such as Gitleaks and TruffleHog
- OpenGrep support for custom source and binary pattern matching
- Dependency vulnerability checks with OWASP Dependency-Check
- SBOM generation with Syft
- IPA and APK binary analysis with tools such as Strings, LIEF, ipsw, Androguard, Apktool, Apksigner, and APKiD
- Optional MobSF integration for deeper binary scanning
- Docker and Docker Compose workflows for repeatable local and CI usage
- Python port-and-adapter architecture for adding, removing, or swapping scanner implementations

## Quick Start

The most convenient way to run AppCritIQ is the released Docker image from GitHub Container Registry.

```bash
mkdir -p scan-results

docker run --rm \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/scan-results:/app/results" \
  ghcr.io/blue-milk-apps/appcritiq-core:<version> \
  scan --native-ios-source-path /workspace --output /app/results
```

Replace `<version>` with the release tag you want to run, and replace the scan flag with the target type that matches your app.

## Scan Targets

`appcritiq scan` requires exactly one scan target flag.

```bash
appcritiq scan --ios-binary-path path/to/app.ipa
appcritiq scan --android-binary-path path/to/app.apk
appcritiq scan --flutter-source-path path/to/project
appcritiq scan --react-native-source-path path/to/project
appcritiq scan --native-android-source-path path/to/project
appcritiq scan --native-ios-source-path path/to/project
```

Source scans run Gitleaks, TruffleHog, Dependency-Check, and Syft, with plist extraction included for Flutter, React Native, and native iOS source scans.

Binary scans run Strings, with LIEF, ipsw, and plist extraction for iOS binaries and Androguard, Apktool, Apksigner, and APKiD for Android binaries. MobSF runs for binary scans only when `MOBSF_URL` is configured.

OpenGrep runs only when a rules path is available. For source targets, OpenGrep scans the project directory directly. For binary targets, AppCritIQ first generates `strings` output from the IPA or APK contents and then runs OpenGrep over those generated text artifacts.

By default, AppCritIQ looks for OpenGrep rules in these folders:

- `rules/ios` for `--ios-binary-path` and `--native-ios-source-path`
- `rules/android` for `--android-binary-path` and `--native-android-source-path`
- `rules/flutter` for `--flutter-source-path`
- `rules/react_native` for `--react-native-source-path`

You can override the default rules location per scan target with these flags:

- `--ios-binary-opengrep-rules-path`
- `--android-binary-opengrep-rules-path`
- `--flutter-source-opengrep-rules-path`
- `--react-native-source-opengrep-rules-path`
- `--native-android-source-opengrep-rules-path`
- `--native-ios-source-opengrep-rules-path`

These override flags can point to rule directories outside this repository when you run `appcritiq scan` directly. For container runs, the rules directory must be mounted into the container and passed as a container path. The current `make compose-run` wrapper does not provide a dedicated variable for passing extra OpenGrep override flags, so direct `appcritiq scan` or `docker run` is the better path when you want an external rules directory.

Binary scans require the binary to be unsigned. If you have access to source code, you can build an unsigned .ipa easily [using these instructions](docs/UnsignediOSBinaries.md).

## Running AppCritIQ

### 1. Released Docker Image

Use the pre-built, versioned container when you want the fastest path with the scanner tooling already bundled.

For source projects:

```bash
mkdir -p scan-results

docker run --rm \
  -v "/path/to/project:/workspace:ro" \
  -v "$PWD/scan-results:/app/results" \
  ghcr.io/blue-milk-apps/appcritiq-core:<version> \
  scan --react-native-source-path /workspace --output /app/results
```

For mobile binaries, mount the directory that contains the binary and scan the file path inside the container:

```bash
mkdir -p scan-results

docker run --rm \
  -v "/path/to/binaries:/workspace:ro" \
  -v "$PWD/scan-results:/app/results" \
  ghcr.io/blue-milk-apps/appcritiq-core:<version> \
  scan --ios-binary-path /workspace/app.ipa --output /app/results
```

Use `--android-binary-path /workspace/app.apk` for APK scans.

### 2. Local Docker Compose

Use `make compose-run` when you are working from a clone of this repository and want AppCritIQ to build locally, start its Compose services, mount the target, and write results to `./scan-results`.

```bash
git clone https://github.com/Blue-Milk-Apps/appcritiq-core.git
cd appcritiq-core

make compose-run PROJECT_PATH=path/to/project SCAN_FLAG=--native-ios-source-path
```

For binary files, pass the matching binary scan flag. When `PROJECT_PATH` is a file, the Makefile mounts its parent directory and scans the file under `/workspace`.

```bash
make compose-run PROJECT_PATH=path/to/app.ipa SCAN_FLAG=--ios-binary-path
make compose-run PROJECT_PATH=path/to/app.apk SCAN_FLAG=--android-binary-path
```

If the binary path contains spaces, quote the entire `PROJECT_PATH` value:

```bash
make compose-run PROJECT_PATH="/Users/name/Desktop/ipas/My Lawn.ipa" SCAN_FLAG=--ios-binary-path
```

When `PROJECT_PATH` is a directory that contains a binary, set `PHOENIX_SCAN_PATH` to the file path inside the container:

```bash
make compose-run PROJECT_PATH=path/to/files SCAN_FLAG=--ios-binary-path PHOENIX_SCAN_PATH=/workspace/app.ipa
```

To include MobSF in a Compose scan, point AppCritIQ at the MobSF sidecar:

```bash
MOBSF_URL=http://mobsf-scanner:8000 \
make compose-run PROJECT_PATH=path/to/app.ipa SCAN_FLAG=--ios-binary-path
```

### 3. Local Developer Install

Use a local install when you are developing AppCritIQ itself, debugging scanner adapters, or intentionally running against tools installed on your host.

Install `uv`:

```bash
brew install uv
```

Or use the official installer:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Clone and install the project:

```bash
git clone https://github.com/Blue-Milk-Apps/appcritiq-core.git
cd appcritiq-core
uv venv
source .venv/bin/activate
uv sync
make hooks-install
```

`make hooks-install` installs the repository's pre-commit hook. It runs the test suite, Ruff lint, formatting, and secret detection before each commit.

`uv sync` installs the Python package dependencies for AppCritIQ, but that alone is not enough for local OpenGrep scans. The Python `opengrep` package is only a launcher and still requires a real `opengrep-core` binary on your host.

Run the CLI locally:

```bash
uv run appcritiq scan --native-ios-source-path path/to/project
```

To use a non-default OpenGrep rules directory locally:

```bash
uv run appcritiq scan \
  --native-ios-source-path path/to/project \
  --native-ios-source-opengrep-rules-path path/to/rules
```

If you want OpenGrep locally, install the standalone OpenGrep binary so that both `opengrep` and `opengrep-core` are available on your `PATH`, or run AppCritIQ through Docker or Docker Compose instead.

Local scans use scanner binaries from your host `PATH`. Install the tools you plan to run before using this mode.

At minimum, local development scans may require:

- the standalone `opengrep` and `opengrep-core` binaries for local OpenGrep scans
- `trufflehog`
- `gitleaks`
- `dependency-check`
- `syft`
- `strings`
- `ipsw` for IPA signing, entitlement, and Mach-O load-command analysis
- `apktool` for APK semantic reconstruction and evidence extraction
- `apksigner` for APK signing integrity and signer identity evidence
- Java and local NVD data for OWASP Dependency-Check
- The Python packages used by binary scanners, including `lief`, `androguard`, and `apkid`

Detailed setup notes are available in [setup/README.md](setup/README.md), including tool-specific instructions for [MobSF](setup/mobsf-scanner/README.md), [Dependency-Check](setup/dependency-check/README.md), [Syft](setup/syft/README.md), [TruffleHog](setup/trufflehog/README.md), [Gitleaks](setup/gitleaks/README.md), [Strings](setup/strings/README.md), [LIEF](setup/lief/README.md), [ipsw](setup/ipsw/README.md), [Apktool](setup/apktool/README.md), and [Apksigner](setup/apksigner/README.md).

## MobSF Sidecar

MobSF is optional and only applies to IPA/APK binary scans.

For local CLI scans with MobSF:

```bash
make services-up
MOBSF_URL=http://localhost:8000 uv run appcritiq scan --ios-binary-path "path/to/app.ipa"
make services-down
```

For Compose scans with MobSF:

```bash
MOBSF_URL=http://mobsf-scanner:8000 \
make compose-run PROJECT_PATH=path/to/app.ipa SCAN_FLAG=--ios-binary-path
```

## Results

Scan output is written to the configured output directory. Docker and Compose examples in this README write reports to `./scan-results` on the host and `/app/results` inside the container. When OpenGrep is enabled, it writes `opengrep_results.json` alongside the other scan artifacts.

## Development

Run the test suite:

```bash
make test
```

Run the CLI from the local environment:

```bash
uv run appcritiq scan <scan-target-flag> path/to/target
```

The codebase follows a port-and-adapter layout:

- `domain/` contains core dataclasses and enums.
- `ports/` defines scanner and storage interfaces.
- `application/` contains orchestration such as `ScannerService`.
- `adapters/` contains scanner, storage, and output implementations.
- `entrypoints/cli.py` contains the command-line interface.
- `utilities/` contains helper code for binary extraction and target discovery.

## Getting Help

Use GitHub issues for bugs, setup problems, and feature requests:

```text
https://github.com/Blue-Milk-Apps/appcritiq-core/issues
```

## Maintainers And Contributors

AppCritIQ Core is maintained by Blue Milk Apps. Contributions should be made through pull requests against this repository.

## License

AppCritIQ Core is released under the [Apache License 2.0](LICENSE).
