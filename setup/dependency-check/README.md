# OWASP Dependency-Check Setup

Phoenix uses OWASP Dependency-Check for dependency vulnerability scanning. The adapter expects a `dependency-check` command on `PATH` and runs scans with `--noupdate`, so the NVD data must already exist locally before offline Phoenix scans work.

## What Phoenix expects

- Java installed.
- `dependency-check` installed and available on `PATH`.
- Local Dependency-Check data in `nvd-owasp-data/` at the Phoenix repo root, or a path supplied with `DEPENDENCY_CHECK_DATA_DIR`.
- The data directory must include `odc.mv.db`.

The current adapter also passes `--disableBundleAudit`, `--disableYarnAudit`, `--disableNodeAudit`, `--disableAssembly`, and `--enableExperimental`. That keeps Phoenix focused on the local Dependency-Check database and avoids several analyzers that would otherwise need extra language tooling.

## Install Java

Dependency-Check 11.0.0 and newer require Java 11 or newer. Java 17 is a practical default because the Docker image already uses `openjdk-17-jdk`.

macOS:

```bash
brew install openjdk@17
java -version
```

Linux:

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk
java -version
```

## Install Dependency-Check

macOS Homebrew:

```bash
brew install dependency-check
dependency-check --version
```

Portable release zip:

```bash
VERSION="$(curl -s https://dependency-check.github.io/DependencyCheck/current.txt)"
curl -Ls "https://github.com/dependency-check/DependencyCheck/releases/download/v${VERSION}/dependency-check-${VERSION}-release.zip" --output dependency-check.zip
unzip dependency-check.zip -d /tmp
sudo ln -sf "/tmp/dependency-check/bin/dependency-check.sh" /usr/local/bin/dependency-check
dependency-check --version
```

For the future Makefile target, prefer a project-local install path such as `.tools/dependency-check/` instead of `/tmp`, then add `.tools/dependency-check/bin` to `PATH` during the target.

## Set up the NVD API key

Dependency-Check uses the NVD API when it builds or refreshes vulnerability data. Use an API key for repeatable setup; unauthenticated updates are slower and more likely to hit rate limits.

1. Request a key from NVD:

```text
https://nvd.nist.gov/developers/request-an-api-key
```

2. Confirm the email from NVD and copy the API key.

3. Export it for the current shell:

```bash
export NVD_API_KEY="paste-your-key-here" # pragma: allowlist secret
```

4. Or store it in the local `.env` file, which is already ignored by git:

```bash
cat >> .env <<'ENV'
NVD_API_KEY=paste-your-key-here
ENV
```

5. Load `.env` before running manual update commands:

```bash
set -a
. ./.env
set +a
test -n "$NVD_API_KEY"
```

Do not commit the API key, print it in logs, or bake it into Docker images. The Makefile target should read `NVD_API_KEY` from the environment and pass it to Dependency-Check as `--nvdApiKey`.

Planned Makefile usage:

```bash
make setup-dependency-check-data NVD_API_KEY="$NVD_API_KEY"
```

or, if we use one generic tool target:

```bash
make setup-tool TOOL=dependency-check NVD_API_KEY="$NVD_API_KEY"
```

## Build or refresh local NVD data

Request an NVD API key when possible. Dependency-Check can update without one, but current Dependency-Check documentation strongly recommends an API key because unauthenticated NVD API updates are slow and rate limited.

```bash
mkdir -p nvd-owasp-data
dependency-check \
  --updateonly \
  --data "$(pwd)/nvd-owasp-data" \
  --nvdApiKey "$NVD_API_KEY"
```

Without an API key:

```bash
mkdir -p nvd-owasp-data
dependency-check \
  --updateonly \
  --data "$(pwd)/nvd-owasp-data"
```

The initial update can take a long time. After it completes, verify:

```bash
test -f nvd-owasp-data/odc.mv.db
```

## Import data from an extracted zip or temp folder

If a Dependency-Check data archive is produced elsewhere, extract it and copy the generated data files into this project:

```bash
mkdir -p nvd-owasp-data
cp /path/to/extracted-data/odc.mv.db nvd-owasp-data/
cp -R /path/to/extracted-data/cache nvd-owasp-data/ 2>/dev/null || true
cp /path/to/extracted-data/publishedSuppressions.xml nvd-owasp-data/ 2>/dev/null || true
cp /path/to/extracted-data/jsrepository.json* nvd-owasp-data/ 2>/dev/null || true
```

The required file is `odc.mv.db`. The cache, hosted suppressions, and RetireJS files are useful when present because they reduce network dependency and update time.

## Configure Phoenix

The simplest local configuration is:

```bash
cat > .env <<'ENV'
DEPENDENCY_CHECK_DATA_DIR=nvd-owasp-data/
DC_NO_UPDATE=1
ENV
```

You can also set an absolute path:

```bash
export DEPENDENCY_CHECK_DATA_DIR="$(pwd)/nvd-owasp-data"
```

Run a scan with the scan target flag that matches your app or source project. See the [`<scan-target-flag>` list](../README.md#scan-target-flags) for valid options.

```bash
uv run phoenix scan <scan-target-flag> path/to/target
```

## Troubleshooting

- `dependency-check: command not found`: install Dependency-Check or add its `bin` directory to `PATH`.
- Java errors: run `java -version` and confirm Java 11 or newer.
- Missing NVD database: confirm `nvd-owasp-data/odc.mv.db` exists or set `DEPENDENCY_CHECK_DATA_DIR`.
- Very slow updates or 403 responses: request an NVD API key and rerun the `--updateonly` command.
- Stale or corrupt data: run `dependency-check --purge --data "$(pwd)/nvd-owasp-data"` and refresh with `--updateonly`.

## Online references

- OWASP Dependency-Check project: https://owasp.org/www-project-dependency-check/
- Dependency-Check CLI installation: https://dependency-check.github.io/DependencyCheck/dependency-check-cli/
- Dependency-Check CLI arguments: https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html
- Dependency-Check releases: https://github.com/dependency-check/DependencyCheck/releases
- NVD API key request: https://nvd.nist.gov/developers/request-an-api-key
- NVD developer start page: https://nvd.nist.gov/developers/start-here
