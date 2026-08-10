"""Android APKiD adapter for compact environmental intelligence evidence."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.apk_utils import (
    ExtractedAPK,
    extract_apk,
    find_apk_in_directory,
    is_apk_file,
)


@dataclass(frozen=True)
class ApkidCommandResult:
    exit_code: int | None
    stdout: str
    stderr: str
    execution_status: str
    duration_seconds: float
    error_message: str = ""


@dataclass(frozen=True)
class ApkidArtifact:
    artifact_id: str
    path: Path
    relationship: str
    archive_path: str | None
    sha256: str
    size_bytes: int


class ApkidScanner(ScannerPort):
    """Scanner for APKiD environmental intelligence and routing signals."""

    EXTRACTOR_VERSION = "1.0"
    SCHEMA_VERSION = "1.0"
    COMMAND_PROFILE = "APKID_JSON_CONTEXT_V1"
    DEFAULT_TIMEOUT_SECONDS = 180
    MAX_TARGETS = 250

    ROUTING_CRITICAL_FAMILIES = {
        "anti_debug",
        "anti_disassembly",
        "anti_vm",
        "dropper",
        "obfuscator",
        "packer",
        "protector",
        "runtime_loader",
        "tamper",
    }
    ANALYSIS_IMPACTING_FAMILIES = {
        "anti_debug",
        "anti_disassembly",
        "anti_vm",
        "dropper",
        "obfuscator",
        "packer",
        "protector",
        "runtime_loader",
        "tamper",
        "shell",
    }
    INFORMATIONAL_FAMILIES = {
        "compiler",
        "framework",
        "kotlin",
        "language",
        "library",
    }
    FAMILY_ALIASES = {
        "anti debug": "anti_debug",
        "anti-debug": "anti_debug",
        "anti disassembly": "anti_disassembly",
        "anti vm": "anti_vm",
        "anti-vm": "anti_vm",
        "anti emu": "anti_vm",
        "anti-emulator": "anti_vm",
        "anti tamper": "tamper",
        "anti-tamper": "tamper",
        "anti_hook": "tamper",
        "loader": "runtime_loader",
        "dynamic_loading": "runtime_loader",
        "packers": "packer",
        "protectors": "protector",
        "obfuscators": "obfuscator",
        "compilers": "compiler",
    }

    @property
    def scan_type(self) -> ScanType:
        return ScanType.APKID

    @property
    def name(self) -> str:
        return "APKiD Intelligence Extractor"

    @property
    def description(self) -> str:
        return "Normalized APKiD environmental intelligence for Android analysis routing."

    def is_available(self) -> bool:
        return shutil.which("apkid") is not None

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        apk_path = self._resolve_apk_path(config.project_path)
        if apk_path is None:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="APKiD only runs on APK files.",
                )
            ]

        apkid_executable = shutil.which("apkid")
        if not apkid_executable:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="The 'apkid' command is not installed on this system.",
                )
            ]

        extracted = config.extracted_binary if isinstance(config.extracted_binary, ExtractedAPK) else None
        owns_extraction = extracted is None
        extraction_errors: list[str] = []
        if extracted is None:
            try:
                extracted = extract_apk(apk_path)
            except Exception as exc:
                extraction_errors.append(str(exc))

        try:
            artifacts = self._analysis_artifacts(apk_path, extracted)
            command_result = self._run_apkid(apkid_executable, artifacts)
            tool_version = self._apkid_version(apkid_executable)
            evidence = self._build_evidence(
                apk_path=apk_path,
                artifacts=artifacts,
                command_result=command_result,
                tool_version=tool_version,
                extraction_errors=extraction_errors,
            )
            return self._scan_results(evidence, command_result)
        finally:
            if owns_extraction and extracted is not None:
                extracted.cleanup()

    def _resolve_apk_path(self, project_path: Path) -> Path | None:
        if project_path.is_file():
            return project_path if is_apk_file(project_path) else None
        return find_apk_in_directory(project_path)

    def _analysis_artifacts(
        self,
        apk_path: Path,
        extracted: ExtractedAPK | None,
    ) -> list[ApkidArtifact]:
        artifacts = [
            ApkidArtifact(
                artifact_id="artifact-0001",
                path=apk_path,
                relationship="PRIMARY_APK",
                archive_path=None,
                sha256=self._sha256(apk_path),
                size_bytes=apk_path.stat().st_size,
            )
        ]
        if extracted is None:
            return artifacts

        seen = {apk_path.resolve()}
        for path in sorted(extracted.analysis_targets, key=lambda item: item.as_posix()):
            resolved = path.resolve()
            if resolved in seen or not path.is_file():
                continue
            if len(artifacts) >= self.MAX_TARGETS:
                break
            seen.add(resolved)
            archive_path = path.relative_to(extracted.temp_dir).as_posix()
            artifacts.append(
                ApkidArtifact(
                    artifact_id=f"artifact-{len(artifacts) + 1:04d}",
                    path=path,
                    relationship=self._artifact_relationship(archive_path),
                    archive_path=archive_path,
                    sha256=self._sha256(path),
                    size_bytes=path.stat().st_size,
                )
            )
        return artifacts

    def _artifact_relationship(self, archive_path: str) -> str:
        if archive_path.startswith("lib/") and archive_path.endswith(".so"):
            return "EXTRACTED_NATIVE_LIBRARY"
        if Path(archive_path).name.startswith("classes") and archive_path.endswith(".dex"):
            return "EXTRACTED_DEX"
        if archive_path.startswith("assets/"):
            return "EXTRACTED_ASSET"
        return "EXTRACTED_APK_MEMBER"

    def _run_apkid(
        self,
        apkid_executable: str,
        artifacts: list[ApkidArtifact],
    ) -> ApkidCommandResult:
        started = time.perf_counter()
        try:
            result = subprocess.run(
                [
                    apkid_executable,
                    "-j",
                    *[str(artifact.path) for artifact in artifacts],
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=self.DEFAULT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            return ApkidCommandResult(
                exit_code=None,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                execution_status="TIMEOUT",
                duration_seconds=time.perf_counter() - started,
                error_message="APKiD timed out.",
            )
        except KeyboardInterrupt:
            return ApkidCommandResult(
                exit_code=None,
                stdout="",
                stderr="",
                execution_status="INTERRUPTED",
                duration_seconds=time.perf_counter() - started,
                error_message="APKiD was interrupted.",
            )
        except Exception as exc:
            return ApkidCommandResult(
                exit_code=None,
                stdout="",
                stderr=str(exc),
                execution_status="TOOL_ERROR",
                duration_seconds=time.perf_counter() - started,
                error_message=str(exc),
            )

        status = "SUCCESS" if result.returncode == 0 else "PARTIAL_SUCCESS"
        if result.returncode != 0 and not (result.stdout or result.stderr):
            status = "TOOL_ERROR"
        return ApkidCommandResult(
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            execution_status=status,
            duration_seconds=time.perf_counter() - started,
        )

    def _apkid_version(self, apkid_executable: str) -> str:
        for command in ([apkid_executable, "--version"], [apkid_executable, "-v"]):
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
            except Exception:
                continue
            output = result.stdout.strip() or result.stderr.strip()
            if output:
                return output
        return ""

    def _build_evidence(
        self,
        apk_path: Path,
        artifacts: list[ApkidArtifact],
        command_result: ApkidCommandResult,
        tool_version: str,
        extraction_errors: list[str],
    ) -> dict[str, Any]:
        parser_errors: list[str] = []
        parsed_output = self._parse_json_output(command_result.stdout, parser_errors)
        normalized_detections = self._normalized_detections(parsed_output, artifacts)
        operational_interpretations = self._operational_interpretations(normalized_detections)
        execution_status = command_result.execution_status
        if execution_status == "SUCCESS" and command_result.stdout.strip() and parsed_output is None:
            execution_status = "PARSING_ERROR"

        return {
            "schema_version": self.SCHEMA_VERSION,
            "extractor": {
                "name": "phoenix-apkid",
                "version": self.EXTRACTOR_VERSION,
                "philosophy": "environmental_intelligence_not_vulnerability_scanning",
            },
            "apk": self._apk_identity(apk_path),
            "extraction_metadata": {
                "execution_status": execution_status,
                "duration_seconds": round(command_result.duration_seconds, 6),
                "apkid_version": tool_version,
                "rule_signature_metadata": self._rule_metadata(parsed_output),
                "command_profile": self.COMMAND_PROFILE,
                "tool_exit_code": command_result.exit_code,
                "timeout_seconds": self.DEFAULT_TIMEOUT_SECONDS,
                "targets_requested": len(artifacts),
                "target_limit": self.MAX_TARGETS,
                "target_limit_reached": len(artifacts) >= self.MAX_TARGETS,
                "partial_extraction": bool(extraction_errors),
                "extraction_errors": extraction_errors,
                "parser_errors": parser_errors,
            },
            "command_profile": {
                "name": self.COMMAND_PROFILE,
                "commands": [
                    {
                        "purpose": "collect_apkid_environmental_intelligence",
                        "argv": [
                            "apkid",
                            "-j",
                            "<apk-and-selected-extracted-artifacts>",
                        ],
                    }
                ],
            },
            "source_artifacts": [self._source_artifact_document(artifact) for artifact in artifacts],
            "normalized_detections": normalized_detections,
            "operational_interpretations": operational_interpretations,
            "correlated_evidence": {
                "observations": [],
                "correlation_hints": self._correlation_hints(normalized_detections),
            },
            "downstream_findings": [],
            "limitations": [
                "APKiD signatures are contextual indicators, not vulnerability findings.",
                "Static signatures may miss runtime-only unpacking, staged loading, or environment-gated behavior.",
                "Unknown or custom protection systems can produce incomplete or low-confidence context.",
                "Positive detections should modify downstream analysis confidence and routing, not inflate findings.",
            ],
            "raw_evidence": {
                "stdout": "raw/apkid_stdout.json" if command_result.stdout else None,
                "stderr": "raw/apkid_stderr.txt" if command_result.stderr else None,
            },
        }

    def _parse_json_output(
        self,
        stdout: str,
        parser_errors: list[str],
    ) -> dict[str, Any] | list[Any] | None:
        if not stdout.strip():
            return None
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as exc:
            parser_errors.append(f"APKiD JSON parsing failed: {exc}")
            return None
        if isinstance(parsed, (dict, list)):
            return parsed
        parser_errors.append("APKiD JSON root was not an object or list.")
        return None

    def _normalized_detections(
        self,
        parsed_output: dict[str, Any] | list[Any] | None,
        artifacts: list[ApkidArtifact],
    ) -> list[dict[str, Any]]:
        records = self._file_records(parsed_output)
        by_path = {str(artifact.path): artifact for artifact in artifacts}
        by_name = {artifact.path.name: artifact for artifact in artifacts}
        detections: list[dict[str, Any]] = []

        for record in records:
            if not isinstance(record, dict):
                continue
            artifact = self._record_artifact(record, by_path, by_name, artifacts)
            matches = record.get("matches") or {}
            if not isinstance(matches, dict):
                continue
            for family, values in matches.items():
                normalized_family = self._normalize_family(str(family))
                for value in self._match_values(values):
                    detection_id = self._detection_id(
                        artifact.artifact_id,
                        normalized_family,
                        value,
                    )
                    tier = self._signal_tier(normalized_family)
                    detections.append(
                        {
                            "id": detection_id,
                            "source_artifact_id": artifact.artifact_id,
                            "source_relationship": artifact.relationship,
                            "family": normalized_family,
                            "rule_name": value,
                            "signal_tier": tier,
                            "priority": self._priority(tier),
                            "confidence": self._confidence(normalized_family, value),
                            "confidence_modifier": self._confidence_modifier(normalized_family),
                            "analysis_impacts": self._analysis_impacts(normalized_family),
                            "recommended_followup": self._recommended_followup(normalized_family),
                            "uncertainty": self._uncertainty(normalized_family),
                        }
                    )

        tier_order = {
            "routing-critical": 0,
            "analysis-impacting": 1,
            "informational": 2,
        }
        return sorted(
            self._dedupe(detections),
            key=lambda item: (
                tier_order[item["signal_tier"]],
                item["family"],
                item["source_artifact_id"],
                item["rule_name"],
            ),
        )

    def _file_records(
        self,
        parsed_output: dict[str, Any] | list[Any] | None,
    ) -> list[Any]:
        if parsed_output is None:
            return []
        if isinstance(parsed_output, list):
            return parsed_output
        files = parsed_output.get("files")
        if isinstance(files, list):
            return files
        if "matches" in parsed_output:
            return [parsed_output]
        return []

    def _record_artifact(
        self,
        record: dict[str, Any],
        by_path: dict[str, ApkidArtifact],
        by_name: dict[str, ApkidArtifact],
        artifacts: list[ApkidArtifact],
    ) -> ApkidArtifact:
        filename = str(record.get("filename") or record.get("file") or record.get("path") or record.get("name") or "")
        return by_path.get(filename) or by_name.get(Path(filename).name) or artifacts[0]

    def _match_values(self, values: Any) -> list[str]:
        if isinstance(values, str):
            return [values]
        if isinstance(values, list):
            return sorted({str(item) for item in values if str(item).strip()})
        if isinstance(values, dict):
            flattened: list[str] = []
            for key, value in values.items():
                if isinstance(value, list):
                    flattened.extend(f"{key}: {item}" for item in value)
                elif value:
                    flattened.append(f"{key}: {value}")
            return sorted({item for item in flattened if item.strip()})
        return []

    def _operational_interpretations(
        self,
        detections: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for detection in detections:
            key = (detection["signal_tier"], detection["family"])
            grouped.setdefault(key, []).append(detection)

        interpretations = []
        tier_order = {
            "routing-critical": 0,
            "analysis-impacting": 1,
            "informational": 2,
        }
        sorted_groups = sorted(
            grouped.items(),
            key=lambda item: (tier_order[item[0][0]], item[0][1]),
        )
        for index, ((tier, family), items) in enumerate(sorted_groups, start=1):
            interpretations.append(
                {
                    "id": f"interpretation-{index:04d}",
                    "signal": family,
                    "signal_tier": tier,
                    "detection_ids": sorted(item["id"] for item in items),
                    "analysis_impacts": sorted({impact for item in items for impact in item["analysis_impacts"]}),
                    "confidence_modifiers": sorted(
                        {item["confidence_modifier"] for item in items if item["confidence_modifier"]}
                    ),
                    "recommended_followup": sorted(
                        {followup for item in items for followup in item["recommended_followup"]}
                    ),
                    "limitations": sorted({limit for item in items for limit in item["uncertainty"]}),
                }
            )
        return interpretations

    def _correlation_hints(
        self,
        detections: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        hints = []
        families = {detection["family"] for detection in detections}
        if families & {"packer", "protector", "runtime_loader", "tamper"}:
            hints.append(
                {
                    "tools": [
                        "JADX",
                        "apktool",
                        "Androguard",
                        "Frida",
                        "runtime_instrumentation",
                    ],
                    "purpose": "Compare static extraction completeness with runtime-loaded code and post-unpack observations.",
                    "related_families": sorted(families & {"packer", "protector", "runtime_loader", "tamper"}),
                }
            )
        if families & {"anti_debug", "anti_vm"}:
            hints.append(
                {
                    "tools": [
                        "Frida",
                        "runtime_instrumentation",
                        "evidence_correlation_engine",
                    ],
                    "purpose": "Route dynamic analysis through hardened instrumentation profiles and lower confidence in emulator-only behavior.",
                    "related_families": sorted(families & {"anti_debug", "anti_vm"}),
                }
            )
        if not hints:
            hints.append(
                {
                    "tools": ["JADX", "apktool", "Androguard"],
                    "purpose": "Use APKiD detections as contextual enrichment for downstream evidence correlation.",
                    "related_families": sorted(families),
                }
            )
        return hints

    def _rule_metadata(
        self,
        parsed_output: dict[str, Any] | list[Any] | None,
    ) -> dict[str, Any]:
        if not isinstance(parsed_output, dict):
            return {
                "version": None,
                "rules_sha256": None,
                "source": "not_reported_by_tool",
            }
        return {
            "version": parsed_output.get("rules_version") or parsed_output.get("rule_version"),
            "rules_sha256": parsed_output.get("rules_sha256") or parsed_output.get("signatures_sha256"),
            "source": "apkid_json"
            if any(
                key in parsed_output
                for key in (
                    "rules_version",
                    "rule_version",
                    "rules_sha256",
                    "signatures_sha256",
                )
            )
            else "not_reported_by_tool",
        }

    def _source_artifact_document(self, artifact: ApkidArtifact) -> dict[str, Any]:
        stable_path = str(artifact.path) if artifact.relationship == "PRIMARY_APK" else artifact.archive_path
        return {
            "id": artifact.artifact_id,
            "relationship": artifact.relationship,
            "path": stable_path,
            "archive_path": artifact.archive_path,
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
        }

    def _apk_identity(self, apk_path: Path) -> dict[str, Any]:
        return {
            "file_name": apk_path.name,
            "sha256": self._sha256(apk_path),
            "size_bytes": apk_path.stat().st_size,
            "package_name": None,
            "version_code": None,
            "version_name": None,
        }

    def _signal_tier(self, family: str) -> str:
        if family in self.ROUTING_CRITICAL_FAMILIES:
            return "routing-critical"
        if family in self.ANALYSIS_IMPACTING_FAMILIES:
            return "analysis-impacting"
        return "informational"

    def _priority(self, tier: str) -> str:
        return {
            "routing-critical": "high",
            "analysis-impacting": "medium",
            "informational": "low",
        }[tier]

    def _confidence(self, family: str, value: str) -> str:
        lowered = value.lower()
        if "possible" in lowered or "generic" in lowered or "unknown" in lowered:
            return "LOW"
        if family in self.INFORMATIONAL_FAMILIES:
            return "MEDIUM"
        return "MEDIUM_HIGH"

    def _confidence_modifier(self, family: str) -> str:
        if family in {"packer", "protector", "runtime_loader"}:
            return "lower_static_analysis_confidence_until_runtime_or_post_unpack_correlation"
        if family in {"anti_debug", "anti_vm"}:
            return "lower_dynamic_analysis_confidence_in_default_emulator_or_debugger_context"
        if family == "tamper":
            return "require_integrity_and_instrumentation_bypass_context_before_negative_assertions"
        return "contextual_enrichment_only"

    def _analysis_impacts(self, family: str) -> list[str]:
        impacts = {
            "packer": [
                "static_code_visibility_may_be_incomplete",
                "route_to_unpacking_or_runtime_collection",
            ],
            "protector": [
                "static_analysis_confidence_reduced",
                "expect_obfuscation_or_integrity_controls",
            ],
            "runtime_loader": [
                "runtime_code_loading_possible",
                "correlate_with_dex_and_native_load_observations",
            ],
            "anti_debug": [
                "debugger_attached_runtime_behavior_may_diverge",
                "use_instrumentation_bypass_profile",
            ],
            "anti_vm": [
                "emulator_runtime_behavior_may_diverge",
                "prefer_physical_device_or_hardened_runtime_profile",
            ],
            "tamper": [
                "instrumented_or_modified_app_behavior_may_diverge",
                "correlate_with_signing_and_integrity_evidence",
            ],
            "obfuscator": [
                "identifier_and_control_flow_readability_reduced",
                "lower_semantic_confidence_for_static_code_review",
            ],
        }
        return impacts.get(family, ["environmental_context_for_downstream_correlation"])

    def _recommended_followup(self, family: str) -> list[str]:
        followups = {
            "packer": [
                "run JADX and apktool completeness checks after unpacking",
                "collect runtime-loaded dex/native artifacts when possible",
            ],
            "protector": [
                "correlate with Androguard, JADX, apktool, and runtime instrumentation visibility",
                "flag downstream static findings as lower confidence if protected code is hidden",
            ],
            "runtime_loader": [
                "correlate with DexClassLoader, System.load, and native library observations",
                "capture runtime-loaded modules in dynamic analysis",
            ],
            "anti_debug": [
                "use Frida or runtime instrumentation with anti-debug bypasses",
                "avoid treating failed dynamic hooks as absence of behavior",
            ],
            "anti_vm": [
                "validate behavior on physical devices or hardened runtime profiles",
                "record runtime environment when correlating evidence",
            ],
            "tamper": [
                "correlate with apksigner integrity evidence",
                "test instrumentation with integrity checks accounted for",
            ],
        }
        return followups.get(family, ["preserve as context for evidence correlation"])

    def _uncertainty(self, family: str) -> list[str]:
        if family in self.INFORMATIONAL_FAMILIES:
            return ["informational fingerprint; no security conclusion by itself"]
        return [
            "signature-based detection can be incomplete or imprecise",
            "runtime behavior may differ from static APKiD visibility",
        ]

    def _normalize_family(self, value: str) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
        return self.FAMILY_ALIASES.get(value.strip().lower()) or self.FAMILY_ALIASES.get(normalized) or normalized

    def _detection_id(self, artifact_id: str, family: str, value: str) -> str:
        digest = hashlib.sha256(f"{artifact_id}:{family}:{value}".encode()).hexdigest()
        return f"apkid-{digest[:16]}"

    def _dedupe(self, detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_id = {detection["id"]: detection for detection in detections}
        return list(by_id.values())

    def _scan_results(
        self,
        evidence: dict[str, Any],
        command_result: ApkidCommandResult,
    ) -> list[ScanResult]:
        execution_status = evidence["extraction_metadata"]["execution_status"]
        extractor_success = execution_status not in {
            "TIMEOUT",
            "TOOL_ERROR",
            "PARSING_ERROR",
            "INTERRUPTED",
        }
        error_message = (
            ""
            if extractor_success
            else (command_result.error_message or command_result.stderr.strip() or "APKiD evidence extraction failed.")
        )
        results = [
            ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                success=extractor_success,
                error_message=error_message,
                raw_output=json.dumps(evidence, indent=2, sort_keys=True),
                relative_target_path="apkid_intelligence.json",
                description=self.description,
            )
        ]

        if command_result.stdout:
            results.append(
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=extractor_success,
                    raw_output=command_result.stdout,
                    relative_target_path="raw/apkid_stdout.json",
                    description="Raw APKiD JSON stdout.",
                )
            )
        if command_result.stderr:
            results.append(
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=extractor_success,
                    raw_output=command_result.stderr,
                    relative_target_path="raw/apkid_stderr.txt",
                    description="Raw APKiD stderr.",
                )
            )
        return results

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
