# Gitleaks Setup

Gitleaks is Phoenix's static secrets scanner for source projects.

## Local Install

Install the `gitleaks` binary so it is on your `PATH`:

```bash
brew install gitleaks
```

Or install the official release binary for your platform from the Gitleaks repository.

## Configuration

Gitleaks will look for a config file in this order:

1. `GITLEAKS_CONFIG` environment variable
2. `.gitleaks.toml` in the scanned project
3. Gitleaks default rules

If you want custom rules, add a `.gitleaks.toml` file to the project root or point `GITLEAKS_CONFIG` at another file path before running Phoenix with the scan target flag that matches your source project. See the [`<scan-target-flag>` list](../README.md#scan-target-flags) for valid options.

## Verification

After setup, this should resolve:

```bash
gitleaks version
```
