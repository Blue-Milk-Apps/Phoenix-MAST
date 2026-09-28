# Phoenix tool inventory

This inventory describes the tools selected by the engine and installed by the Dockerfile. A **scan** is one Phoenix run. A **tool execution** is one invocation of an adapter within that run; an adapter can issue several CLI commands. A **rule** means an OpenGrep rule. Other analysis uses detectors, signatures, extraction, normalization, or reporting. Native tool artifacts retain upstream field names such as Gitleaks `RuleID`.

## Analysis tools

| Tool | Docker version/source | Executed for | Provides | Consumption and decision |
| --- | --- | --- | --- | --- |
| OpenGrep | 1.22.0 standalone binary; `opengrep-core` alias | All targets with supplied rules | Matches, locations, execution coverage, catalog snapshots | Owns security findings and functionality in reports. Retain. |
| Gitleaks | 8.30.1 | All source targets, extracted/decoded binary resources and strings | Credential detections | Redacted detector/location summaries in reports; original evidence in `gitleaks/`. Retain. |
| TruffleHog | 3.95.2 | All source targets, extracted/decoded binary resources and strings | Credential detections and verification status | Redacted summaries in reports; original evidence in `trufflehog/`. Retain: independent detectors complement Gitleaks. Binary executions disable credential verification. |
| Syft | 1.44.0 | All source and binary targets | Package inventory, versions, ecosystems, locations, package URLs | Canonical `syft-json` in `syft/sbom.json`; all target reports include package details and inventory status. Retain. Syft does not perform vulnerability database matching. |
| aapt2 | Debian `aapt` package | APK | Package identity, manifest, components, permissions, resource facts | Primary Android identity/component inventory. JSON normalization and raw command evidence in `aapt2/`; Python review-candidate and resource-keyword classification removed. Retain; explicitly installed in Docker. |
| Apktool | 2.10.0 JAR and launcher | APK | Decoded XML, smali and resources; configuration/deep-link inventories | Decoded files in `apktool/decoded/` feed secret tools and OpenGrep. Configuration summaries feed inventory. Python smali/secret regex classification removed. Retain. |
| Apksigner | Debian package | APK | Cryptographic signature verification, signing schemes and certificate digests | Signing status in report; detailed evidence in `apksigner/`. Retain as signing authority. |
| Androguard | 4.1.3 Python API in Docker | APK | DEX strings with method references, caller/callee facts, parsed certificate details | Certificate enrichment reaches reports; DEX JSON remains inspectable and available to binary OpenGrep. Duplicate manifest, identity, permission, component and file inventory extraction removed. Retain for distinct DEX/certificate data. |
| APKiD | 3.1.0 Python distribution/CLI | APK | Compiler, packer, obfuscation and protection signature matches | Executes today. Artifacts in `apkid/` are available to binary OpenGrep; there is no dedicated APKiD PDF inventory. Retain as an executed evidence producer, not an unused installation. |
| LIEF | 0.17.2 Python API in Docker | IPA Mach-O targets | Architecture, imported functions, linked libraries, header flags and NX facts | App/binary inventory plus `lief/` evidence for OpenGrep. Retain for structured Mach-O data. Parse failures are failures, not empty successful results. |
| ipsw | 3.1.687 | IPA Mach-O targets | Signing, entitlements and Mach-O summaries | App identity and signing facts plus `ipsw/` evidence for OpenGrep. Retain for entitlement/signing data complementary to LIEF. |
| GNU Strings | Debian `binutils` | APK/IPA extracted analysis targets | Printable strings, including nested libraries | Four-character minimum. Files under `strings/` feed OpenGrep, Gitleaks, and TruffleHog. Post-processing no longer loads all strings into memory or applies Python vulnerability regexes. Retain. |

All independently installed analysis tools above have an execution path. Raw evidence availability and report integration are different: APKiD and DEX context currently add more to artifacts than to the PDF. Binary OpenGrep rules can use these inputs when supplied. iOS strings rules live in the private Phoenix-Rules repository.

## Python extraction and reporting

| Component | Purpose and boundary |
| --- | --- |
| Plist adapters / standard-library `plistlib` | Normalize plist, entitlement and privacy-manifest data and emit XML for OpenGrep. There is no bundled cross-platform plist conversion CLI to replace this. |
| Native Android source metadata | Read manifest and build identity; provide declared permissions/components. Security decisions come from OpenGrep. |
| Flutter / React Native metadata | Read application identity, declared dependencies and embedded platform configuration. Resolved dependencies come exclusively from Syft; custom npm/Yarn/pnpm/pubspec lockfile parsers were removed. |
| APKiD adapter | Normalize upstream signature families, evidence locations and follow-up hints. These are tool evidence, not additional Phoenix rules or report vulnerabilities. |
| Rule assessment/report builders | Join persisted OpenGrep catalog entries to matches, group findings, count severity and format output. No keyword or version-based vulnerability inference. |
| Exclusion workspace | Apply one root-relative path contract across tools with different exclusion interfaces. A filtered source tree is prepared once when needed, using hard links where possible and copies otherwise. Original source paths are restored before persistence. |
| Rich | Static stdout/stderr formatting, status labels, severity colors and summary tables. No animations; severity filtering affects stdout only. |
| Jinja2, MarkupSafe, WeasyPrint | Optional PDF rendering; template autoescaping is enabled and badge labels are escaped. Loaded on demand for PDF output. |
| Matplotlib, NumPy, Pillow | PDF charts and images; Pillow is also used for application icon extraction. |
| PyYAML | OpenGrep catalog metadata and Flutter manifest declarations. |

## Container support packages

| Package/tool | Why present |
| --- | --- |
| Python 3.12, pip, venv | Engine and Python tool runtime/install environment. |
| Bash | Interactive image entrypoint and Apktool launcher. |
| Git | Repository discovery used by OpenGrep and its upstream tool support. |
| CA certificates | HTTPS certificate verification by tools. |
| OpenJDK 21 runtime | Apktool and Apksigner. |
| libmagic | Androguard/APK inspection dependency. |
| Pango, PangoFT2, HarfBuzz subset, DejaVu fonts | WeasyPrint native rendering dependencies. |
| curl | Build-time downloads only; removed from the finished image. |
| `aapt` and other binutils commands | Co-packaged with aapt2 and Strings. These auxiliary commands are not invoked by Phoenix; their packages supply the required executables. |
| pytest, Ruff, pre-commit | Development dependency group; not installed by the runtime image's application install. |

Upstream Python tools also install transitive libraries and entrypoints. They are dependencies of the retained tools, not additional Phoenix analysis stages; selectively removing their declared dependencies would make those installations inconsistent.

## Removed and retained optional services

The unused mobile-analysis sidecar, adapter, environment wiring and setup instructions were removed. The standalone Gitleaks Compose service is used by its integration test and is isolated behind the `tool-tests` profile; the Phoenix workflow uses its installed Gitleaks executable. The misleading `phoenix-secrets` service, which duplicated a full scan, was removed.

## Evidence and coverage limits

Missing binary rule files produce explicit `not_evaluated` OpenGrep coverage. Inventory and tool artifacts remain available. This is not equivalent to evaluating security findings and finding none. Missing source rules and failed required tool executions fail the scan, preserving artifacts written before failure.

Exclusions apply to source files and to disposable extracted/decoded binary trees. APK-level operations such as signature verification, aapt2 and DEX analysis inspect the original archive; member exclusions do not rewrite or resign that archive. Symlink targets outside a filtered source root are skipped with a stdout explanation. These boundaries also apply to future rules consuming archive-level evidence. Excluding inputs required by a tool can make its execution incomplete and fail the scan.

The broader scan-plan/preflight redesign and shared platform-scope runner redesign remain deferred. Phoenix-Rules retains its platform/mode/category layout.

Debian's [aapt package file list](https://packages.debian.org/trixie/amd64/aapt/filelist) confirms that it supplies `/usr/bin/aapt2`.
