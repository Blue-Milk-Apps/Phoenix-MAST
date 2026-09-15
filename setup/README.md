# AppcritIQ Scanner Setup

AppcritIQ scanner adapters call external tools from the local `PATH`. The current adapters are:

| Scanner | Required local command | Extra local data |
| --- | --- | --- |
| MobSF Scanner | MobSF service | `MOBSF_URL` pointing to MobSF |
| LIEF | Python `lief` package | IPA files only |
| ipsw | `ipsw` | IPA files only |
| Androguard | Python `androguard` package | APK files only |
| aapt2 | `aapt2` | APK files only |
| Apktool | `apktool` | APK files only |
| Apksigner | `apksigner` | APK files only |
| APKiD | `apkid` | APK files only |
| TruffleHog | `trufflehog` | None |
| Gitleaks | `gitleaks` | `.gitleaks.toml` in the scanned project or `GITLEAKS_CONFIG` |
| Strings | `strings` | App binaries and embedded frameworks / native libraries |
| OWASP Dependency-Check | `dependency-check` | NVD data under `nvd-owasp-data/` or `DEPENDENCY_CHECK_DATA_DIR` |
| Syft | `syft` | None |

These setup notes document the manual steps that the Makefile targets should later automate.

## Docker Tool Pins

The AppcritIQ Docker image pins scanner tool versions with build arguments so CI images are reproducible and upgrades are explicit:

| Build arg | Default |
| --- | --- |
| `SYFT_VERSION` | `v1.44.0` |
| `TRUFFLEHOG_VERSION` | `v3.95.2` |
| `GITLEAKS_VERSION` | `8.30.1` |
| `APKTOOL_VERSION` | `2.10.0` |
| `IPSW_VERSION` | `3.1.687` |
| `DEPENDENCY_CHECK_VERSION` | `12.2.0` |
| `APKID_VERSION` | `3.1.0` |
| `ANDROGUARD_VERSION` | `4.1.3` |
| `LIEF_VERSION` | `0.17.2` |

Override a pin only when intentionally refreshing the scanner image:

```bash
docker compose build appcritiq --build-arg GITLEAKS_VERSION=8.30.1
```

## Readmes

- [MobSF Scanner and MobSF](mobsf-scanner/README.md)
- [LIEF](lief/README.md)
- [ipsw](ipsw/README.md)
- [Androguard](androguard/README.md)
- [aapt2](aapt2/README.md)
- [Apktool](apktool/README.md)
- [Apksigner](apksigner/README.md)
- [APKiD](apkid/README.md)
- [OWASP Dependency-Check and NVD data](dependency-check/README.md)
- [Syft](syft/README.md)
- [TruffleHog](trufflehog/README.md)
- [Gitleaks](gitleaks/README.md)
- [Strings](strings/README.md)

## AppcritIQ paths

AppcritIQ uses `MOBSF_URL` to find the MobSF service for binary scans. If `MOBSF_URL` is not set, AppcritIQ skips MobSF and continues with the other configured scanners. When using `make services-up`, MobSF is available at `http://localhost:8000`.

## Scan Target Flags

`appcritiq scan` requires exactly one scan target flag. Any of these flags is valid:

```bash
appcritiq scan --ios-binary-path path/to/app.ipa
appcritiq scan --android-binary-path path/to/app.apk
appcritiq scan --flutter-source-path path/to/project
appcritiq scan --react-native-source-path path/to/project
appcritiq scan --native-android-source-path path/to/project
appcritiq scan --native-ios-source-path path/to/project
```

Source scans run Gitleaks as part of the AppcritIQ pipeline, while binary scans run LIEF, ipsw, and plist extraction for iOS binaries, Androguard, Apktool, Apksigner, and APKiD for Android binaries, and Strings against app binaries plus embedded frameworks/native libraries. MobSF runs for binary scans only when `MOBSF_URL` is configured. ipsw writes compact signing, entitlement, and Mach-O summary evidence under `scan-results/.../ipsw/`. Apktool writes compact Android evidence JSON under `scan-results/.../apktool/` and removes the decoded project after extraction. Apksigner writes APK signing evidence under `scan-results/.../apksigner/`. APKiD writes compact environmental intelligence under `scan-results/.../apkid/`.

For local APK signing evidence, AppcritIQ resolves `apksigner` from `PATH`. For Docker scans, the AppcritIQ image installs `apksigner` inside the container during image build, so host Android SDK paths are not needed. APKiD follows the same runtime availability model: local scans need `apkid` on `PATH`, while Docker scans use the APKiD command installed in the AppcritIQ image.

AppcritIQ currently looks for OWASP Dependency-Check data in this order:

1. `DEPENDENCY_CHECK_DATA_DIR` from the process environment.
2. `DEPENDENCY_CHECK_DATA_DIR` from `.env` in the current working directory.
3. `DEPENDENCY_CHECK_DATA_DIR` from `.env` in the scanned project.
4. `nvd-owasp-data/` in the current working directory.
5. `/opt/dependency-check/data` in the container when `DC_NO_UPDATE=1`.

For local offline scans, the easiest stable setup is:

```bash
mkdir -p rules nvd-owasp-data
cat > .env <<'ENV'
DEPENDENCY_CHECK_DATA_DIR=nvd-owasp-data/
DC_NO_UPDATE=1
ENV
```

`nvd-owasp-data/` should contain the Dependency-Check H2 database file named `odc.mv.db`.

## Verification

After setup, these commands should all resolve:

```bash
trufflehog --version
gitleaks version
strings --help
apktool --version
aapt2 version
apksigner version
apkid --version
ipsw version
dependency-check --version
syft version
```

Run AppcritIQ locally with:

See the [scan target flags](#scan-target-flags) list for valid `<scan-target-flag>` values.

```bash
uv run appcritiq scan <scan-target-flag> path/to/target
```

Run AppcritIQ locally against an IPA or APK while using the MobSF sidecar:

```bash
make services-up
MOBSF_URL=http://localhost:8000 uv run appcritiq scan --ios-binary-path "path/to/app.ipa"
```

Run a Compose scan with MobSF by pointing AppcritIQ at the Compose sidecar:

```bash
MOBSF_URL=http://mobsf-scanner:8000 make compose-run PROJECT_PATH="path/to/app.ipa" SCAN_FLAG=--ios-binary-path
```

## Online references

- MobSF Docker setup: https://mobsf.github.io/Mobile-Security-Framework-MobSF/
- OWASP Dependency-Check project: https://owasp.org/www-project-dependency-check/
- OWASP Dependency-Check CLI arguments: https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html
- Syft installation: https://oss.anchore.com/docs/installation/syft
- TruffleHog installation and usage: https://github.com/trufflesecurity/trufflehog
- ipsw installation: https://blacktop.github.io/ipsw/docs/getting-started/installation/
