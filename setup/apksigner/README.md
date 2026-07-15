# Apksigner Evidence Extractor Setup

Phoenix uses `apksigner` during APK binary scans to extract APK signing integrity, signer identity, and lightweight supply-chain provenance evidence. The extractor writes normalized JSON evidence and does not generate findings.

## Local Install

Phoenix resolves `apksigner` from the local `PATH`.

On macOS, install Android SDK Build Tools with Android Studio or the Android command-line tools. `apksigner` usually lives under:

```text
~/Library/Android/sdk/build-tools/<version>/apksigner
```

Find installed copies:

```bash
find "$HOME/Library/Android/sdk/build-tools" -name apksigner -type f | sort
```

Choose the newest stable build-tools version and add that directory to your shell `PATH`. For zsh, add lines like these to `~/.zshrc`:

```bash
export ANDROID_HOME="$HOME/Library/Android/sdk"
export PATH="$ANDROID_HOME/build-tools/35.0.0:$PATH"
```

Reload your shell:

```bash
source ~/.zshrc
```

Verify that Phoenix can resolve the same command:

```bash
which apksigner
apksigner version
```

On Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y apksigner
which apksigner
apksigner version
```

Phoenix does not use an `APKSIGNER_PATH` override. If `apksigner` is not on `PATH`, the scanner skips and reports that the tool is unavailable.

## Docker Install

For Docker scans, do not add a host Android SDK path to Phoenix. Host paths such as `/Users/.../Library/Android/sdk/...` are not available inside the container unless explicitly mounted.

The Phoenix Docker image installs `apksigner` inside the container and verifies it during image build:

```bash
docker compose build phoenix
```

Verify the container command directly:

```bash
docker compose run --rm --entrypoint apksigner phoenix version
```

## Phoenix Usage

Apksigner runs automatically during APK binary scans:

```bash
uv run phoenix scan --android-binary-path path/to/app.apk
```

The scanner skips non-APK inputs. It emits one primary document-style artifact under:

```text
scan-results/.../apksigner/signing_evidence.json
```

Raw command output is retained separately only when present:

```text
scan-results/.../apksigner/raw/apksigner_verify_stdout.txt
scan-results/.../apksigner/raw/apksigner_verify_stderr.txt
```

## Generated Evidence

`signing_evidence.json` contains normalized evidence for:

- APK identity context
- extraction metadata
- apksigner tool version
- Phoenix extractor version
- schema version
- command profile used
- verification status
- signature scheme states
- signer certificate fingerprints and identity fields
- signer public key and signature algorithm metadata
- lineage and rotation placeholders where unavailable
- lightweight trust relationships
- enrichment fields separated from direct extraction
- raw evidence references

The extractor does not infer that a valid signature means an APK is safe. It preserves evidence showing artifact integrity relative to signer identity.

## Enum Values

Allowed values for `verification.overall_status`:

- `VERIFIED`
- `FAILED`
- `PARTIAL`
- `INCONCLUSIVE`
- `TOOL_ERROR`

Allowed values for `verification.structural_integrity`:

- `VALID`
- `MALFORMED`
- `CORRUPTED`
- `TRUNCATED`
- `UNPARSEABLE`
- `UNKNOWN`

Allowed values for `signature_schemes.*.state`:

- `VERIFIED`
- `PRESENT_NOT_VERIFIED`
- `MISSING`
- `UNSUPPORTED`
- `ERROR`
- `UNKNOWN`

Allowed values for `extraction_metadata.execution_status`:

- `SUCCESS`
- `PARTIAL_SUCCESS`
- `TIMEOUT`
- `TOOL_ERROR`
- `PARSING_ERROR`
- `INTERRUPTED`
- `UNKNOWN`

Allowed values for `certificate.public_key_algorithm`:

- `RSA`
- `EC`
- `DSA`
- `UNKNOWN`

Allowed values for `certificate.signature_algorithm`:

- `SHA1_WITH_RSA`
- `SHA256_WITH_RSA`
- `SHA512_WITH_RSA`
- `SHA256_WITH_ECDSA`
- `SHA512_WITH_ECDSA`
- `UNKNOWN`

Allowed values for `enrichment.signer_classification`:

- `PRODUCTION`
- `DEBUG`
- `TEST`
- `THIRD_PARTY`
- `UNTRUSTED`
- `UNKNOWN`

Allowed values for `lineage.lineage_state`:

- `PRESENT`
- `ABSENT`
- `ROTATED`
- `UNAVAILABLE`
- `UNKNOWN`

## Extraction Philosophy

Phoenix treats `apksigner` output as signing evidence, not as policy. Downstream systems can use this evidence to generate findings such as missing modern signing schemes, debug signer usage, unexpected signer drift, broken lineage, or unknown production signer.
