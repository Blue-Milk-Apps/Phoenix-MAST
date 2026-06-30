# aapt2 Evidence Extractor

AppcritIQ uses `aapt2` as an Android packaging, manifest, and resource evidence
source during APK binary scans. The integration is designed for deterministic
evidence extraction in AppSec and malware-analysis pipelines.

This integration is not a vulnerability scanner, generic APK report generator,
or reverse-engineering UI. It extracts stable facts and high-signal candidates
from Android packaging metadata so downstream systems can correlate them with
code, decoded resources, native analysis, and runtime observations.

## Extraction Philosophy

The aapt2 integration is evidence-first:

- Extract normalized, machine-readable evidence from authoritative Android
  packaging views.
- Preserve raw tool output for auditability and future re-parsing.
- Record command provenance, parser version, tool version, timings, exit codes,
  and output hashes.
- Prefer selective, high-signal resource candidates over exhaustive low-signal
  dumping.
- Emit candidate interpretations and follow-up guidance instead of findings.
- Keep extraction deterministic so release diffing and CI regression analysis
  can compare stable artifact shapes across runs.

The extractor treats `aapt2` as a packaging metadata authority. It does not try
to replace Androguard, Apktool, JADX, native analysis, or runtime
instrumentation. Its job is to produce reliable evidence that those tools can
correlate against.

## What aapt2 Extracts

AppcritIQ runs targeted `aapt2 dump` commands independently:

```bash
aapt2 dump badging <apk>
aapt2 dump permissions <apk>
aapt2 dump xmltree --file AndroidManifest.xml <apk>
aapt2 dump resources <apk>
```

These views are used for:

- APK identity metadata such as package name, version, SDK levels, labels, and
  native ABI declarations.
- Declared permissions and dangerous-permission hints.
- Manifest-derived security posture facts such as backup, cleartext traffic,
  network security config references, legacy external storage, and exported
  components.
- Application, component, provider, receiver, service, activity, and
  activity-alias declarations.
- Intent filters, app links, deep links, URI patterns, and auth-related
  entrypoint indicators.
- Resource type summaries and high-value resource follow-up candidates.
- Evidence relationships for downstream indexing and correlation.

## Operational Goals

The integration supports:

- CI/CD regression analysis for manifest and packaging drift.
- Release diffing across stable evidence objects and artifact files.
- Malware triage routing when packaging metadata suggests unusual exposure,
  native ABI presence, deep links, or suspicious resource names.
- AppSec automation where a lightweight packaging evidence source is useful
  before deeper code or runtime analysis.
- Evidence indexing across a larger AppcritIQ scan result set.
- Downstream code/resource correlation with Androguard, Apktool, JADX, native
  analysis, and runtime instrumentation.

## Availability And Version Pinning

AppcritIQ resolves `aapt2` from the local `PATH` and records:

```bash
aapt2 version
```

Install `aapt2` through Android SDK Build Tools and make the selected
build-tools directory available on `PATH`.

Typical SDK locations:

```bash
~/Library/Android/sdk/build-tools/<version>/aapt2
$ANDROID_HOME/build-tools/<version>/aapt2
```

Verify locally:

```bash
which aapt2
aapt2 version
```

Pin Android SDK Build Tools in CI images when release diffing or regression
analysis depends on stable command behavior. Tool upgrades should be explicit
because output formatting changes can affect parser coverage and evidence
comparability.

## Artifacts

AppcritIQ writes normalized evidence and raw command output separately:

```text
scan-results/.../aapt2/aapt2_evidence.json
scan-results/.../aapt2/metadata.json
scan-results/.../aapt2/execution_metadata.json
scan-results/.../aapt2/identity.json
scan-results/.../aapt2/permissions.json
scan-results/.../aapt2/manifest_security_posture.json
scan-results/.../aapt2/application.json
scan-results/.../aapt2/components.json
scan-results/.../aapt2/intent_filters.json
scan-results/.../aapt2/resource_summary.json
scan-results/.../aapt2/resource_candidates.json
scan-results/.../aapt2/evidence_relationships.json
scan-results/.../aapt2/candidate_interpretations.json
scan-results/.../aapt2/correlation_requirements.json
scan-results/.../aapt2/limitations.json
scan-results/.../aapt2/scan_index.json
scan-results/.../aapt2/raw/aapt2_badging_stdout.txt
scan-results/.../aapt2/raw/aapt2_badging_stderr.txt
scan-results/.../aapt2/raw/aapt2_permissions_stdout.txt
scan-results/.../aapt2/raw/aapt2_permissions_stderr.txt
scan-results/.../aapt2/raw/aapt2_xmltree_manifest_stdout.txt
scan-results/.../aapt2/raw/aapt2_xmltree_manifest_stderr.txt
scan-results/.../aapt2/raw/aapt2_resources_stdout.txt
scan-results/.../aapt2/raw/aapt2_resources_stderr.txt
```

Raw files are written only when the corresponding stream contains data.

The aggregate `aapt2_evidence.json` is retained for compatibility and complete
context. Focused section artifacts make the output easier to browse, index,
diff, and compare with Androguard and Apktool artifacts.

## Artifact Families

`execution_metadata.json` records extraction status, command profile, command
arguments, exit codes, timings, output hashes, parser errors, parser version,
tool version, and raw evidence references.

`identity.json` contains package identity, SDK metadata, launch activity,
labels, features, densities, locales, and native ABI declarations extracted
primarily from `dump badging`.

`permissions.json` contains declared permissions as extracted facts. Dangerous
permissions receive protection-level hints, but those hints are not behavior or
exploitability claims.

`manifest_security_posture.json` summarizes static manifest posture facts:
exported component count, declared permission count, dangerous permission count,
cleartext traffic posture, network security config references, backup posture,
legacy external storage posture, and native ABI presence.

`application.json` captures application-level manifest attributes with
provenance.

`components.json` captures activities, activity aliases, services, receivers,
and providers. Exported state and component permissions are facts from the
manifest view. They are not vulnerability conclusions.

`intent_filters.json` captures actions, categories, data declarations, URI
patterns, web links, custom schemes, and auth-related entrypoint indicators.

`resource_summary.json` contains resource type counts and documents that
resource normalization is intentionally selective.

`resource_candidates.json` contains high-signal resource follow-up candidates,
such as names or values referencing auth, tokens, network security, providers,
backup, certificates, cleartext, WebView, trust, or similar security-relevant
terms.

`evidence_relationships.json` preserves compact relationships useful for
downstream graphing and indexing.

`candidate_interpretations.json` contains review candidates and follow-up
recommendations. These are explicitly not findings.

`scan_index.json` lists generated artifacts, item counts, command status, and
partial-failure state.

## Provenance Strategy

Every normalized evidence object should be traceable to:

- the command source, such as `badging`, `permissions`, `xmltree_manifest`, or
  `resources`;
- the raw evidence reference, such as
  `raw/aapt2_xmltree_manifest_stdout.txt`;
- the AppcritIQ parser version;
- the aapt2 tool version;
- the command profile and argv shape;
- stdout/stderr hashes where output exists.

Example provenance shape:

```json
{
  "command_source": "xmltree_manifest",
  "raw_evidence_reference": "raw/aapt2_xmltree_manifest_stdout.txt",
  "parser_version": "1.0"
}
```

This allows analysts and downstream systems to audit why a normalized object
exists, compare it to the original output, and re-parse raw evidence later if
parser logic improves.

## Relationship Strategy

The extractor preserves security-relevant relationships without expanding the
entire APK into a noisy graph.

Examples:

- app declares permission
- app declares component
- component declares intent filter
- intent filter declares URI pattern
- application references resource candidate
- component requires permission

Relationship artifacts exist to support downstream correlation, release diffing,
and evidence indexing. They intentionally avoid exhaustive resource graphing and
do not try to model every drawable, layout, string, style, or compiled resource
edge.

## Candidate Vs Finding

aapt2 evidence can produce candidates, not findings.

Examples:

- An exported activity is a review candidate. It is not automatically
  vulnerable.
- A declared dangerous permission is a correlation candidate. It does not prove
  runtime use.
- A network security config reference is a follow-up candidate. The referenced
  XML must be decoded and interpreted.
- A resource named `oauth_client_id` is a resource candidate. It does not prove
  a secret is present or valid.
- A deep link with an auth-like path is an entrypoint indicator. It does not
  prove account takeover, bypass, or exploitability.

Findings should be produced only after downstream correlation with code,
configuration, runtime behavior, business context, or policy expectations.

## Evidence Interpretation Guidance

Use aapt2 evidence as a stable packaging lens:

- Treat package name, version metadata, declared components, intent filters, and
  manifest attributes as extracted facts.
- Treat protection-level hints, auth-related entrypoint indicators, and
  security-relevant resource names as review candidates.
- Treat missing data as either absent evidence or extraction failure depending
  on `execution_metadata.json` and `scan_index.json`.
- Check raw evidence and command status before drawing conclusions from an empty
  section.
- Compare stable IDs and artifact sections across releases for drift.

Operational mental model:

```text
raw aapt2 command output
  -> deterministic parser
  -> normalized evidence objects
  -> compact relationships and candidates
  -> downstream correlation
  -> possible finding outside this extractor
```

## Example Evidence Flows

Exported component review:

```text
components.json exported=true
  -> evidence_relationships.json links app -> component
  -> intent_filters.json shows action/category/data
  -> correlate with Androguard or JADX handler code
  -> validate reachability with runtime instrumentation
```

Deep link and app link review:

```text
intent_filters.json URI pattern
  -> candidate_interpretations.json entrypoint hint
  -> correlate with server asset links, auth flow code, and runtime tests
```

Network security config review:

```text
application.json network_security_config_reference
  -> resource_candidates.json matching XML candidate
  -> decode with Apktool
  -> inspect trust anchors, pinning, cleartext domains, and debug overrides
```

Permission drift review:

```text
permissions.json requested permissions
  -> compare across releases
  -> correlate dangerous permissions with DEX API usage
  -> determine whether product behavior or policy changed
```

Malware triage:

```text
identity.json native ABI presence
  -> resource_candidates.json security/token/provider names
  -> components.json exported receivers/providers
  -> correlate with APKiD, native library analysis, and sandbox behavior
```

## Partial Failure Philosophy

Each `aapt2 dump` command runs independently. A failure in one command should
not discard evidence from successful commands.

Partial extraction is represented through:

- per-command `execution_status`;
- command exit codes;
- stdout/stderr hashes;
- raw stderr preservation;
- `scan_index.json` partial-failure flags;
- aggregate extraction status.

An empty artifact is not enough to infer absence. Always inspect command status
and raw evidence references. For example, empty `components.json` after an
`xmltree_manifest` failure means component evidence was not extracted, not that
the APK has no components.

## Intentionally Omitted Data

The extractor intentionally avoids:

- exhaustive drawable extraction;
- full layout normalization;
- full style/theme normalization;
- full string table expansion as primary evidence;
- exhaustive resource graph expansion;
- low-signal resource entries that are unlikely to help security analysis;
- reverse-engineering UI views;
- vulnerability conclusions from manifest metadata.

This keeps artifacts small enough for large APK volumes, CI indexing, and
release diffing while preserving high-value evidence and raw outputs for future
analysis.

## Downstream Correlation

aapt2 output is most useful when correlated with other tools:

- JADX: map components, intent handlers, permissions, WebView code, storage
  access, and auth flows to source-level logic.
- Androguard: correlate manifest facts with DEX classes, methods, API calls,
  xrefs, strings, and certificates.
- Apktool: decode XML resources referenced by manifest attributes, including
  network security config and provider path metadata.
- Native analysis: inspect libraries when `native_abis` or native files are
  present.
- Runtime instrumentation: validate reachability, dynamic registration,
  permission use, network behavior, storage behavior, and exploitability.

The extractor is deliberately conservative so these downstream tools remain the
places where behavior and exploitability are evaluated.

## Scaling Considerations

The integration is designed for large APK volumes:

- commands are targeted and bounded;
- output is normalized into focused JSON sections;
- raw evidence is retained separately;
- low-signal resource expansion is avoided;
- stable artifact names support indexing and object storage;
- scan indexes expose counts and partial failures without loading every file;
- deterministic evidence supports release and branch diffing.

For CI, treat changes in `identity.json`, `permissions.json`,
`manifest_security_posture.json`, `components.json`, `intent_filters.json`, and
`resource_candidates.json` as review signals, not automatic failures unless a
separate policy engine defines expectations.

## Limitations

aapt2 evidence cannot:

- observe runtime behavior;
- confirm behavioral intent;
- validate exploitability;
- analyze DEX semantics;
- observe dynamic loading;
- observe dynamic component registration;
- guarantee declared permissions are used;
- guarantee exported components are vulnerable;
- confirm secrets exist or are valid;
- prove server-side app link or deep link trust behavior.

These limitations are intentional boundaries of a packaging evidence extractor.
Use aapt2 evidence as one reliable input to a broader AppSec or
malware-analysis pipeline.
