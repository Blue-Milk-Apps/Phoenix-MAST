# TruffleHog Setup

Phoenix uses TruffleHog to detect verified secrets in the scanned filesystem. The adapter expects a `trufflehog` command on `PATH`.

## What Phoenix expects

- `trufflehog` installed and available on `PATH`.
- No extra local database is required.
- Phoenix writes newline-delimited JSON to `trufflehog_results.json`.

The adapter runs:

```bash
trufflehog filesystem <project> \
  --log-level=-1 \
  --json \
  --no-update \
  --only-verified
```

`--only-verified` means Phoenix reports secrets TruffleHog can verify as active. That lowers false positives, but verification can require network access to the relevant provider APIs.

## Install TruffleHog

macOS:

```bash
brew install trufflehog
trufflehog --version
```

Official installer:

```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
trufflehog --version
```

Docker is also available:

```bash
docker pull trufflesecurity/trufflehog:latest
```

Phoenix local scans need the host binary. Docker-only TruffleHog installs are useful for manual validation, but they do not satisfy `shutil.which("trufflehog")` in the local adapter.

## Run a manual check

```bash
trufflehog filesystem . --json --only-verified --no-update
```

Then run Phoenix with the scan target flag that matches your app or source project. See the [`<scan-target-flag>` list](../README.md#scan-target-flags) for valid options.

```bash
uv run phoenix scan <scan-target-flag> path/to/target
```

## Troubleshooting

- `trufflehog: command not found`: install TruffleHog or add it to `PATH`.
- No output: TruffleHog may have found no verified secrets. That is normal for clean projects.
- Network verification failures: run TruffleHog manually without `--only-verified` when investigating whether unverified detections exist.
- Large repository scans: exclude generated folders in the future Phoenix trigger layer or run a manual TruffleHog command against a narrower path.

## Online references

- TruffleHog GitHub repository: https://github.com/trufflesecurity/trufflehog
- TruffleHog docs: https://docs.trufflesecurity.com/getting-started
