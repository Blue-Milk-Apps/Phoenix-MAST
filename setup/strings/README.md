# Strings Scanner Setup

AppcritIQ includes a simple strings extractor for binary scans.

## Local Install

The scanner uses the `strings` command from your local system.

Check that it is available:

```bash
strings --help
```

On Linux, `strings` is usually provided by `binutils`. On macOS, it is typically available from the system toolchain.

## AppcritIQ Usage

Strings runs automatically during binary scans:

```bash
uv run appcritiq scan --ios-binary-path path/to/app.ipa
uv run appcritiq scan --android-binary-path path/to/app.apk
```

For IPA files, AppcritIQ targets the app runner binary plus embedded framework binaries. For APK files, AppcritIQ targets extracted native `.so` libraries. The scanner writes one raw string per line into separate files under `scan-results/.../strings/`.
