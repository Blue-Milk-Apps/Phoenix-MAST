# APKiD Environmental Intelligence Integration

AppcritIQ uses APKiD as a signature-based environmental intelligence source during Android binary evidence extraction. Its job is to describe analysis context: packers, protectors, anti-debug indicators, anti-VM indicators, runtime loaders, anti-tamper signals, compilers, and build-chain fingerprints that may affect how later tools should be routed and interpreted.

APKiD output is not treated as a vulnerability report. It is evidence about the environment in which other evidence should be collected, weighted, and correlated.

## Availability Model

AppcritIQ resolves APKiD from the process `PATH` with the `apkid` command. The scanner checks availability before execution and skips with an explicit unavailable-tool result when `apkid` cannot be found.

The AppcritIQ Docker image installs APKiD into the AppcritIQ virtual environment and verifies it during image build. Because `/opt/appcritiq-venv/bin` is on the container `PATH`, Docker-based AppcritIQ scans can resolve `apkid` without a host APKiD install. The Docker build pins APKiD through the `APKID_VERSION` build argument so upgrades are explicit.

Local scans depend on the uv-managed project environment. APKiD is declared in `pyproject.toml`, so the repeatable setup path is:

```bash
uv sync
uv run apkid --version
```

After that, `uv run appcritiq ...` resolves `apkid` from the same project environment used by AppcritIQ.

When intentionally changing the APKiD version, update the project metadata and lockfile with `uv add`:

```bash
uv add "apkid==<version>"
uv run apkid --version
```

If APKiD is not available locally, Android binary scans continue and the APKiD stage is recorded as skipped. This is intentional: APKiD enriches analysis context, but the rest of the evidence pipeline can still run.

## Docker Verification

Build the AppcritIQ image and verify that APKiD resolves inside the container:

```bash
docker compose build appcritiq
docker compose run --rm --entrypoint apkid appcritiq --version
```

## Operational Purpose

The APKiD integration enriches Android AppSec pipelines with compact context that helps downstream systems answer operational questions:

- Should static analysis confidence be reduced because code may be packed, protected, encrypted, or loaded at runtime?
- Should dynamic analysis run with anti-debug or anti-emulator bypass profiles?
- Should JADX, apktool, Androguard, Frida, or runtime instrumentation outputs be correlated before making negative assertions?
- Should evidence-correlation systems expect partial visibility from static extractors?
- Are detections only ordinary build-chain fingerprints that should remain informational?

APKiD is useful because it can identify environmental signals early and cheaply. That makes it a good routing and confidence input for CI/CD, queue-based analysis, malware triage, and asynchronous AppSec workflows.

## What APKiD Is

In AppcritIQ, APKiD is:

- a signature-based environmental intelligence tool
- a context enricher for Android binary analysis
- a routing signal source for downstream static and dynamic tools
- a confidence modifier for later evidence interpretation
- a compact source of normalized, machine-readable operational signals

## What APKiD Is Not

In AppcritIQ, APKiD is not:

- a vulnerability scanner
- a semantic analyzer
- a behavioral analysis engine
- a source-code auditing platform
- a reverse-engineering platform
- a primary finding generator

A detection such as a packer, compiler, anti-debug check, or Kotlin fingerprint does not automatically become a security finding. It becomes contextual evidence that downstream systems may use when correlating richer observations.

## Evidence Extraction Philosophy

The integration favors high-signal, bounded evidence over exhaustive dumps. APKiD can expose useful signatures, but raw signature internals and bulk output are usually poor long-term pipeline artifacts. AppcritIQ preserves the operational meaning and the relationship to source artifacts, while avoiding noisy data that makes downstream reasoning harder.

The extractor intentionally prioritizes:

- compact JSON artifacts
- deterministic output ordering
- source artifact provenance
- normalized detections
- operational interpretations
- confidence modifiers
- recommended followup actions
- explicit limitations and uncertainty
- raw evidence references separated from normalized evidence

The extractor intentionally avoids:

- giant stdout blobs inside normalized artifacts
- raw binary dumps
- full YARA match internals
- exhaustive ZIP-entry relationship mapping
- synthetic semantic graphs
- deep dependency graphs
- vulnerability inflation from informational signatures

This keeps artifacts LLM-friendly, machine-readable, auditable, and suitable for scalable evidence pipelines.

## Evidence Lifecycle

AppcritIQ separates APKiD evidence into five lifecycle stages.

1. Raw output

   Raw APKiD stdout and stderr are preserved as separate raw artifacts when present. They are audit references, not the primary evidence model.

2. Normalized detections

   APKiD matches are converted into stable detection records with a family, rule name, source artifact relationship, signal tier, priority, confidence, confidence modifier, analysis impacts, recommended followup, and uncertainty notes.

3. Operational interpretations

   Related detections are grouped into concise interpretations such as "packer", "anti_debug", or "runtime_loader". These interpretations explain expected analysis impact and recommended next actions.

4. Correlated evidence

   The APKiD artifact reserves space for downstream observations and emits correlation hints for tools such as JADX, apktool, Androguard, Frida, runtime instrumentation systems, and evidence-correlation engines.

5. Downstream findings

   APKiD does not generate downstream findings by itself. Findings should be produced only after richer evidence is correlated and interpreted by a scanner, policy engine, analyst workflow, or AppSec reasoning system.

## Signal Tiers

APKiD detections are classified by operational importance, not by vulnerability severity.

### Routing-Critical

Routing-critical detections can change the analysis path. Examples include packers, protectors, anti-debug indicators, anti-VM indicators, runtime loaders, anti-tamper controls, droppers, and strong obfuscation signals.

Typical effects:

- route to dynamic analysis or runtime artifact capture
- request hardened Frida or instrumentation profiles
- require post-unpack static analysis before drawing conclusions
- reduce confidence in default static-only results

### Analysis-Impacting

Analysis-impacting detections may affect confidence or interpretation but do not necessarily require a new route by themselves. Examples include obfuscators, shell/protection hints, and signals that suggest static visibility may be incomplete.

Typical effects:

- lower semantic confidence for static review
- require correlation with JADX, apktool, Androguard, or runtime observations
- warn downstream systems before making negative assertions

### Informational

Informational detections are context, not findings. Examples include compilers, Kotlin indicators, common framework fingerprints, ordinary libraries, and normal build-chain artifacts.

Typical effects:

- enrich the analysis context
- help explain later tool output
- remain low priority unless correlated with stronger evidence

Informational detections are intentionally not elevated into findings because doing so creates noise and weakens the evidence pipeline.

## Normalized Evidence Structure

The primary JSON artifact is designed as an operational evidence contract. It separates source identity, extraction metadata, normalized detections, interpretations, correlation hints, and raw evidence references.

Representative structure:

```json
{
  "schema_version": "1.0",
  "extractor": {
    "name": "appcritiq-apkid",
    "version": "1.0",
    "philosophy": "environmental_intelligence_not_vulnerability_scanning"
  },
  "apk": {
    "file_name": "app.apk",
    "sha256": "...",
    "size_bytes": 123456
  },
  "extraction_metadata": {
    "execution_status": "SUCCESS",
    "apkid_version": "APKiD ...",
    "rule_signature_metadata": {
      "version": null,
      "rules_sha256": null,
      "source": "not_reported_by_tool"
    },
    "partial_extraction": false,
    "parser_errors": []
  },
  "source_artifacts": [],
  "normalized_detections": [],
  "operational_interpretations": [],
  "correlated_evidence": {
    "observations": [],
    "correlation_hints": []
  },
  "downstream_findings": [],
  "limitations": [],
  "raw_evidence": {
    "stdout": "raw/apkid_stdout.json",
    "stderr": null
  }
}
```

The normalized artifact is the preferred machine-consumption surface. Raw output remains available for audit and parser troubleshooting.

## Relationship Strategy

AppcritIQ preserves meaningful shallow relationships:

- detection to source artifact
- detection to analysis impact
- detection to confidence modifier
- detection to recommended followup
- detection to correlated downstream observation

The relationship model is intentionally shallow. It records whether a detection came from the primary APK, an extracted DEX file, a native library, an asset, or another selected APK member. It does not attempt to build complete ZIP-entry maps, dependency graphs, execution graphs, or synthetic semantic relationships.

This keeps the evidence useful for routing and correlation without pretending that signature matches describe full program behavior.

## Confidence-Modifier Strategy

APKiD detections change confidence in later analysis, not the truth of later findings.

Examples:

- Packers and protectors lower confidence in static-only analysis until post-unpack or runtime evidence is collected.
- Runtime loader detections increase the need to correlate static DEX evidence with runtime-loaded modules.
- Anti-debug detections lower confidence in debugger-attached dynamic analysis unless bypasses are applied.
- Anti-VM detections lower confidence in emulator-only runtime results.
- Anti-tamper detections require integrity and instrumentation context before treating missing behavior as meaningful.
- Compiler, Kotlin, and ordinary build-chain fingerprints remain contextual enrichment only.

Confidence modifiers are deliberately explicit so downstream systems can reason about why a finding, non-finding, or missing observation should be weighted differently.

## Partial Extraction And Timeouts

The integration supports partial extraction because APKs can be malformed, protected, truncated, oversized, or hostile to static tooling.

When partial extraction occurs:

- the primary APK remains eligible for APKiD analysis
- extraction errors are recorded in metadata
- `partial_extraction` is set
- normalized evidence is emitted where possible
- downstream consumers are expected to treat coverage as incomplete

When APKiD times out:

- execution status records the timeout
- available stdout or stderr may still be preserved as raw evidence
- normalized detections are emitted only if valid output can be parsed
- downstream systems should treat the APKiD stage as incomplete, not negative

This behavior supports partial-failure recovery in CI/CD and asynchronous analysis pipelines.

## Determinism And Scalability

The APKiD artifact is designed for reproducible automation:

- stable artifact names
- deterministic JSON sorting
- bounded target selection
- compact source artifact records
- no binary dump preservation
- no unbounded graph expansion
- explicit parser and extraction errors
- raw evidence stored separately from normalized evidence

These constraints make the output suitable for AppSec pipelines, queue-based processing, evidence-correlation systems, LLM reasoning systems, dynamic-analysis orchestrators, and malware triage systems.

## Limitations And Uncertainty

APKiD is signature-based. Signatures can be stale, incomplete, broad, or overly specific. They can produce false positives and false negatives.

Static APKiD analysis may miss:

- runtime-only unpacking
- staged payload loading
- environment-gated behavior
- encrypted code or strings
- custom protection systems
- dynamically downloaded modules
- native behavior that is only visible during execution

Absence of APKiD detections does not imply:

- absence of protection
- absence of obfuscation
- absence of runtime loading
- absence of anti-debugging
- absence of anti-VM behavior
- absence of malicious behavior

The correct interpretation of no detections is limited: APKiD did not report known signatures in the analyzed artifacts.

## Downstream Correlation Expectations

APKiD evidence is most useful when correlated with other tools:

- JADX for decompiled Java/Kotlin visibility and decompiler completeness
- apktool for manifest, resource, smali, asset, and native library evidence
- Androguard for DEX metadata, strings, APIs, and shallow xrefs
- Frida and runtime instrumentation for dynamic behavior and loaded modules
- evidence-correlation engines for cross-tool confidence modeling
- malware triage systems for protection, loader, and evasion routing

Downstream consumers should treat APKiD as contextual intelligence. It can explain why other tools see less than expected, why runtime analysis needs a different profile, or why a negative static result should be considered lower confidence.

## Intentional Omissions

The integration intentionally omits:

- full YARA internals
- raw binary dumps
- giant stdout embedded in normalized JSON
- full APKiD trace or debug output
- synthetic semantic graphs
- exhaustive ZIP-entry relationship mapping
- direct vulnerability findings from informational detections

These omissions are design choices. The goal is evidence quality, operational clarity, and confidence-aware analysis rather than maximum artifact volume.
