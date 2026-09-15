# ipsw Scanner Setup

AppcritIQ uses `ipsw` during IPA binary scans to collect focused Apple-specific Mach-O, code-signature, and entitlement evidence from app and framework binaries. The scanner writes compact analyst-facing summaries into AppcritIQ scan artifacts and does not generate findings by itself.

## Local Install

AppcritIQ resolves `ipsw` from the local `PATH`.

On macOS, install `ipsw` with Homebrew:

```bash
brew install blacktop/tap/ipsw
```

On Linux, install `ipsw` with snap:

```bash
sudo snap install ipsw
```

If snap is not available for your Linux environment, install a release archive from the `ipsw` GitHub releases page and place the `ipsw` binary somewhere on your `PATH`.

Verify that AppcritIQ can resolve the same command:

```bash
which ipsw
ipsw version
```

AppcritIQ does not use an `IPSW_PATH` override. If `ipsw` is not on `PATH`, the scanner skips and reports that the tool is unavailable.

## Docker Install

For Docker scans, do not install `ipsw` on the host just for AppcritIQ. The AppcritIQ Docker image installs `ipsw` inside the container from a pinned GitHub release archive and verifies it during image build:

```bash
docker compose build appcritiq
```

Verify the container command directly:

```bash
docker compose run --rm --entrypoint ipsw appcritiq version
```

## AppcritIQ Usage

ipsw runs automatically during iOS binary scans:

```bash
uv run appcritiq scan --ios-binary-path path/to/app.ipa
```

The scanner skips non-IPA inputs, including APK files and source directories. It emits one JSON artifact per scanned Mach-O binary under:

```text
scan-results/.../ipsw/
```

For a typical IPA, outputs include the main app binary and embedded framework binaries:

```text
scan-results/.../ipsw/AppName.json
scan-results/.../ipsw/Frameworks/Example.framework/Example.json
```

## Output

Each JSON artifact contains:

- app metadata from `Info.plist`
- binary path and binary kind
- scanner metadata
- `ipsw version` output
- command profile metadata
- compact Mach-O summary extracted from `ipsw macho info <binary> --json`
- compact code-signature summary extracted from `ipsw macho info <binary> --sig`
- compact entitlement summary extracted from `ipsw macho info <binary> --ent`
- command execution metadata, with raw output omitted for successful commands

Raw command output is intentionally omitted on successful runs because it can be very large and often duplicates information that LIEF, plist extraction, MobSF, or Strings already capture more directly.

## Final Analysis Role

ipsw should be treated as Apple-specific binary trust and hardening evidence. It overlaps with LIEF for basic Mach-O inventory.

Recommended fields to parse for final analysis:

| Analysis signal | ipsw source | Why it matters |
| --- | --- | --- |
| Code-signing identity | `ipsw macho info <binary> --sig`; `LC_CODE_SIGNATURE.code_directories[].team_id`; `LC_CODE_SIGNATURE.code_directories[].id`; certificate chain text | Confirms Team ID, bundle identifier, signing chain, signing requirements, and whether the binary appears signed by the expected Apple chain. |
| Entitlements | `ipsw macho info <binary> --ent`; `LC_CODE_SIGNATURE.code_signature.entitlements` | Identifies privileged app capabilities such as push, keychain groups, app groups, associated domains, iCloud, private entitlements, or debug-only entitlements. |
| Build platform and SDK | `LC_BUILD_VERSION.platform`; `LC_BUILD_VERSION.min_os`; `LC_BUILD_VERSION.sdk`; `LC_BUILD_VERSION.tools[]` | Supports platform-currency checks, old SDK review, minimum OS review, and build-toolchain review. |
| Segment memory protections | `LC_SEGMENT_64.name`; `LC_SEGMENT_64.prot`; `LC_SEGMENT_64.maxprot`; section metadata | Supports binary-hardening review for unusual writable/executable memory protections or unexpected segment layout. |
| Runtime search paths | `LC_RPATH.path` | Finds unexpected runtime framework search paths that can affect dynamic loading review. |
| Dynamic library load type | `LC_LOAD_DYLIB.name`; `LC_LOAD_WEAK_DYLIB.name` | Supplements LIEF by distinguishing normal and weak-linked dependencies. |
| Encryption metadata | `LC_ENCRYPTION_INFO_64.crypt_id`; offset and size fields | Supports packaging and App Store encryption/protection review. |
| Binary identity | `LC_UUID.uuid`; Mach-O header CPU/type/flags | Gives stable binary identity and corroborates architecture/hardening signals from LIEF. |

Avoid treating ipsw as the primary source for:

- library and framework inventory: prefer LIEF's `binary.slices[].libraries`, using ipsw only for weak-link and rpath context
- URLs, IP addresses, emails, or generic identifiers: prefer Strings and MobSF
- hardcoded secrets: prefer Strings, MobSF, and source secret scanners
- tracker classification: use dependency/framework names from LIEF or SBOM sources plus a tracker knowledge base
- Android `.so` analysis: ipsw is iOS/Mach-O only

In short, LIEF should remain the canonical structured inventory source for iOS libraries/frameworks, while ipsw should provide Apple-specific signing, entitlement, load-command, and hardening evidence.

## Online Reference

- ipsw project: https://github.com/blacktop/ipsw
- ipsw installation: https://blacktop.github.io/ipsw/docs/getting-started/installation/
- ipsw Mach-O commands: https://blacktop.github.io/ipsw/docs/guides/macho/
