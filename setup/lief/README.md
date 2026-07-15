# LIEF Setup

Phoenix uses the Python `lief` package for IPA-only Mach-O inspection during binary scans.

## Local Install

The dependency is listed in `pyproject.toml`, so the normal workflow is:

```bash
uv sync
```

If you need to install it manually into an existing environment:

```bash
uv pip install lief
```

## Phoenix Usage

Run Phoenix against an IPA file:

```bash
uv run phoenix scan --ios-binary-path path/to/app.ipa
```

The LIEF scanner skips non-IPA inputs, including APK files and source directories.

## Output

The scanner returns raw JSON output in its `ScanResult`. Configured output
adapters decide whether to print or persist that result.

## Online Reference

- LIEF project: https://lief.re/
