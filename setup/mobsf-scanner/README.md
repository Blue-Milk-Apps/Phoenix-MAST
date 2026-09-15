# MobSF Scanner And MobSF Setup

AppcritIQ can use MobSF for IPA and APK binary analysis. The scanner talks to a running MobSF API service instead of a local binary command, and it only runs when `MOBSF_URL` is configured.

## Start MobSF Only

Start the MobSF sidecar without running the full AppcritIQ Docker workflow:

```bash
make services-up
```

This starts the `mobsf-scanner` compose service and exposes MobSF on:

```text
http://localhost:8000
```

Then run AppcritIQ locally:

```bash
MOBSF_URL=http://localhost:8000 uv run appcritiq scan --ios-binary-path "path/to/app.ipa"
```

The same works for APK files:

```bash
MOBSF_URL=http://localhost:8000 uv run appcritiq scan --android-binary-path "path/to/app.apk"
```

## API Key

`make services-up` starts MobSF with this local default API key:

```text
appcritiq-local-mobsf-api-key
```

The AppcritIQ MobSF scanner uses the same default when `MOBSF_API_KEY` is not set, so this command works without extra key setup:

```bash
MOBSF_URL=http://localhost:8000 uv run appcritiq scan --ios-binary-path "path/to/app.ipa"
```

To use a custom key, pass the same value to both the sidecar and the local scan:

```bash
MOBSF_API_KEY="your-key" make services-up # pragma: allowlist secret
MOBSF_URL=http://localhost:8000 MOBSF_API_KEY="your-key" uv run appcritiq scan --ios-binary-path "path/to/app.ipa" # pragma: allowlist secret
```

## Stop MobSF

Stop the sidecar when finished:

```bash
make services-down
```

Use `make compose-down` if you want to stop the whole compose stack.

## Local Versus Compose

`make services-up` starts only MobSF. It does not start the NVD sidecar and it does not run AppcritIQ inside Docker. Local `appcritiq scan` still uses local scanner prerequisites for TruffleHog, Gitleaks, Dependency-Check, and Syft.

Use the Compose workflow when you want Docker to run AppcritIQ against a mounted scan target. MobSF is optional in this flow; pass `MOBSF_URL` when you want MobSF evidence included:

```bash
MOBSF_URL=http://mobsf-scanner:8000 make compose-run PROJECT_PATH="path/to/app.ipa" SCAN_FLAG=--ios-binary-path
```

Without `MOBSF_URL`, the same binary scan runs the other binary scanners and skips MobSF:

```bash
make compose-run PROJECT_PATH="path/to/app.ipa" SCAN_FLAG=--ios-binary-path
```

For source directories, pass the matching source scan target flag. Source scans do not need MobSF:

```bash
make compose-run PROJECT_PATH="path/to/project" SCAN_FLAG=--react-native-source-path
```

## Troubleshooting

- `MobSF Scanner is not available`: confirm `MOBSF_URL` is set and the configured MobSF service is reachable. For the local sidecar, `docker compose ps mobsf-scanner` should show the service as healthy.
- API errors: make sure `MOBSF_API_KEY` matches on both the MobSF service and the AppcritIQ scan command.
- Port conflicts: stop the process using port `8000`, or change the compose port mapping and set `MOBSF_URL` to match.
- Slow first start: MobSF may download and initialize its internal analysis tools the first time the container starts.

## Online references

- MobSF Docker setup: https://mobsf.github.io/Mobile-Security-Framework-MobSF/
- MobSF Docker image: https://hub.docker.com/r/opensecurity/mobile-security-framework-mobsf/
