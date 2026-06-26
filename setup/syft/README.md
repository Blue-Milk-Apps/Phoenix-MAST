# Syft Setup

AppcritIQ uses Syft to generate CycloneDX SBOM output. The adapter expects a `syft` command on `PATH`.

## What AppcritIQ expects

- `syft` installed and available on `PATH`.
- No extra local database is required.
- AppcritIQ writes `sbom.json` and `sbom.xml` under the scan output directory.

The adapter runs:

```bash
syft scan <project> \
  -o cyclonedx-json=<output>/sbom.json \
  -o cyclonedx-xml=<output>/sbom.xml
```

## Install Syft

Official installer:

```bash
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
syft version
```

macOS Homebrew:

```bash
brew tap anchore/syft
brew install syft
syft version
```

Docker is also available:

```bash
docker pull anchore/syft
```

AppcritIQ local scans need the host binary. Docker-only Syft installs are useful for manual validation, but they do not satisfy `shutil.which("syft")` in the local adapter.

## Run a manual check

```bash
syft scan . -o cyclonedx-json=/tmp/appcritiq-sbom.json
```

Then run AppcritIQ with the scan target flag that matches your app or source project. See the [`<scan-target-flag>` list](../README.md#scan-target-flags) for valid options.

```bash
uv run appcritiq scan <scan-target-flag> path/to/target
```

## Troubleshooting

- `syft: command not found`: install Syft or add it to `PATH`.
- Empty SBOM: run Syft manually with verbose output against the same project path and confirm package manifests are present.
- Permission errors: ensure the output directory is writable.

## Online references

- Syft installation: https://oss.anchore.com/docs/installation/syft
- Syft GitHub repository: https://github.com/anchore/syft
