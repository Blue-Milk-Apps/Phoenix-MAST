# appcritiq-core

AppcritIQ Core is the Python foundation for AppcritIQ, an all-in-one Mobile Application Security Testing (MAST) tool for iOS and Android applications.

## What The Project Does

AppcritIQ Core is intended to coordinate mobile security scanning workflows from one project:

- Static analysis for mobile application security issues
- Secret detection for accidental credential exposure
- Dependency vulnerability checks
- Software Bill of Materials (SBOM) generation

The project is designed to give engineers and security reviewers a consistent place to run and extend mobile application security checks.

## Why The Project Is Useful

Mobile application reviews often require several tools, output formats, and setup steps. AppcritIQ Core aims to make that workflow easier to repeat by collecting scanner orchestration, and configuration in one Python project.

Using `uv` keeps Python dependency management fast and reproducible for local development and CI.

## Getting Started

Install `uv`:

```bash
brew install uv
```

Or use the official installer:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Clone the repository:

```bash
git clone https://github.com/Blue-Milk-Apps/appcritiq-core.git
cd appcritiq-core
```

Create a local environment with `uv`:

```bash
uv venv
source .venv/bin/activate
```

When project dependencies are defined, install them with:

```bash
uv sync
```

## Local Scanner Setup

AppcritIQ runs several external scanner tools from your local `PATH`. For local scans, install the scanner binaries and prepare any required local data before running `appcritiq scan`.

At minimum:

- Install `trufflehog`, `gitleaks`, `dependency-check`, and `syft`.
- Install the `lief` Python package for IPA-only binary analysis.
- Install `ipsw` for IPA-only signing, entitlement, and Mach-O load-command analysis.
- Install `apktool` for APK semantic reconstruction and evidence extraction.
- Install `apksigner` for APK signing integrity and signer identity evidence.
- Make sure `strings` is installed and available on your `PATH` for binary scans.
- For OWASP Dependency-Check, install Java and prepare the local NVD database under `nvd-owasp-data/`.
- MobSF is optional for IPA/APK binary scans. Set `MOBSF_URL` when you want AppcritIQ to include MobSF results.

Detailed setup instructions are in [setup/README.md](setup/README.md), with tool-specific notes for:

- [MobSF Scanner and MobSF](setup/mobsf-scanner/README.md)
- [OWASP Dependency-Check and NVD data](setup/dependency-check/README.md)
- [Syft](setup/syft/README.md)
- [TruffleHog](setup/trufflehog/README.md)
- [Gitleaks](setup/gitleaks/README.md)
- [Strings](setup/strings/README.md)
- [LIEF](setup/lief/README.md)
- [ipsw](setup/ipsw/README.md)
- [Apktool](setup/apktool/README.md)
- [Apksigner](setup/apksigner/README.md)

## How to Run

### Scan Target Flags

`appcritiq scan` requires exactly one scan target flag. Any of these flags is valid:
Run with `appcritiq scan <source_scan_flag> path/to/file|folder
e.g

```bash
appcritiq scan --ios-binary-path path/to/app.ipa
appcritiq scan --android-binary-path path/to/app.apk
appcritiq scan --flutter-source-path path/to/project
appcritiq scan --react-native-source-path path/to/project
appcritiq scan --native-android-source-path path/to/project
appcritiq scan --native-ios-source-path path/to/project
```

Source scans run Gitleaks, TruffleHog, Dependency-Check, and Syft, with plist extraction included for Flutter, React Native, and native iOS source scans. Binary scans run Strings, with LIEF, ipsw, and plist extraction for iOS binaries and Androguard, Apktool, Apksigner, and APKiD for Android binaries. MobSF runs for binary scans only when `MOBSF_URL` is configured.

## Makefile Usage

Use `make run` to run the AppcritIQ Docker image directly against a local target. `PROJECT_PATH` defaults to the current directory, `PHOENIX_SCAN_PATH` defaults to `/workspace`, and `RESULTS_DIR` defaults to `./scan-results`.

```bash
make run PROJECT_PATH=path/to/project SCAN_FLAG=--<scan-target-flag>
```

Use `make compose-run` for the Docker Compose workflow. It builds AppcritIQ, starts required Compose services, mounts the target, and passes the scan target flag into the AppcritIQ container. MobSF is not enabled unless `MOBSF_URL` is provided.

```bash
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

When using `PROJECT_PATH` as a directory that contains a binary, set `PHOENIX_SCAN_PATH` to the file path inside the container:

```bash
make compose-run PROJECT_PATH=path/to/files SCAN_FLAG=--ios-binary-path PHOENIX_SCAN_PATH=/workspace/app.ipa
```

Use `make services-up` only when you want to run AppcritIQ locally while using the MobSF sidecar:

```bash
make services-up
MOBSF_URL=http://localhost:8000 uv run appcritiq scan --ios-binary-path "path/to/app.ipa"
make services-down
```

To include MobSF in a Compose scan, point AppcritIQ at the MobSF sidecar:

```bash
MOBSF_URL=http://mobsf-scanner:8000 \
make compose-run PROJECT_PATH=path/to/app.ipa SCAN_FLAG=--ios-binary-path
```

When using `docker compose` directly, pass `SCAN_FLAG`, `PHOENIX_SCAN_PATH`, and `PROJECT_MOUNT_PATH` so the container receives the matching scan target. Mount the directory that contains the binary, not the binary file itself:

```bash
PROJECT_MOUNT_PATH="/Users/name/Desktop/ipas" \
PHOENIX_SCAN_PATH="/workspace/My Lawn.ipa" \
SCAN_FLAG="--ios-binary-path" \
docker compose up --build --exit-code-from appcritiq appcritiq
```

To include MobSF when running `docker compose` directly, also pass `MOBSF_URL=http://mobsf-scanner:8000`.

## How to Test

See the [scan target flags](#scan-target-flags) list for valid `<scan-target-flag>` values.

```bash
make test
uv run appcritiq scan <scan-target-flag> path/to/target
```

## Getting Help

Use the GitHub issue tracker for bugs, setup problems, and feature requests:

```text
https://github.com/Blue-Milk-Apps/appcritiq-core/issues
```

## Maintainers And Contributors

AppcritIQ Core is maintained by Blue Milk Apps. Contributions should be made through pull requests against this repository.
