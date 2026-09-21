"""Android aapt2 adapter for packaging and manifest evidence extraction."""

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
from utilities.apk_utils import find_apk_in_directory, is_apk_file


@dataclass(frozen=True)
class Aapt2CommandSpec:
    key: str
    purpose: str
    argv_template: list[str]


@dataclass(frozen=True)
class Aapt2CommandResult:
    key: str
    purpose: str
    argv: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    execution_status: str
    duration_seconds: float
    error_message: str = ""


class Aapt2Scanner(ScannerPort):
    """Scanner for deterministic aapt2 Android package metadata evidence."""

    EXTRACTOR_VERSION = "1.0"
    PARSER_VERSION = "1.0"
    SCHEMA_VERSION = "1.0"
    COMMAND_PROFILE = "AAPT2_ANDROID_EVIDENCE_V1"
    DEFAULT_TIMEOUT_SECONDS = 180
    MAX_RESOURCE_CANDIDATES = 250

    COMMANDS = (
        Aapt2CommandSpec(
            key="badging",
            purpose="apk_identity_and_badging",
            argv_template=["aapt2", "dump", "badging", "<apk>"],
        ),
        Aapt2CommandSpec(
            key="permissions",
            purpose="declared_permissions",
            argv_template=["aapt2", "dump", "permissions", "<apk>"],
        ),
        Aapt2CommandSpec(
            key="xmltree_manifest",
            purpose="manifest_xml_tree",
            argv_template=[
                "aapt2",
                "dump",
                "xmltree",
                "--file",
                "AndroidManifest.xml",
                "<apk>",
            ],
        ),
        Aapt2CommandSpec(
            key="resources",
            purpose="resource_table_candidates",
            argv_template=["aapt2", "dump", "resources", "<apk>"],
        ),
    )

    DANGEROUS_PERMISSIONS = {
        "android.permission.ACCEPT_HANDOVER",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.BLUETOOTH_ADVERTISE",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BODY_SENSORS",
        "android.permission.CALL_PHONE",
        "android.permission.CAMERA",
        "android.permission.GET_ACCOUNTS",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.READ_CALENDAR",
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECORD_AUDIO",
        "android.permission.SEND_SMS",
        "android.permission.USE_SIP",
        "android.permission.WRITE_CALENDAR",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.WRITE_CONTACTS",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    }
    COMPONENT_TAGS = {"activity", "activity-alias", "service", "receiver", "provider"}
    SECURITY_RESOURCE_KEYWORDS = (
        "auth",
        "backup",
        "biometric",
        "cert",
        "cleartext",
        "config",
        "credential",
        "crypto",
        "deeplink",
        "domain",
        "fileprovider",
        "key",
        "network_security",
        "oauth",
        "permission",
        "pin",
        "privacy",
        "provider",
        "secret",
        "security",
        "ssl",
        "token",
        "trust",
        "webview",
    )

    @property
    def scan_type(self) -> ScanType:
        return ScanType.AAPT2

    @property
    def name(self) -> str:
        return "aapt2 Evidence Extractor"

    @property
    def description(self) -> str:
        return "Normalized Android package, manifest, and resource evidence from aapt2."

    def is_available(self) -> bool:
        return shutil.which("aapt2") is not None

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        apk_path = self._resolve_apk_path(config.project_path)
        if apk_path is None:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="aapt2 only runs on APK files.",
                )
            ]

        aapt2_executable = shutil.which("aapt2")
        if not aapt2_executable:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="The 'aapt2' command is not installed on this system.",
                )
            ]

        version = self._aapt2_version(aapt2_executable)
        command_results = [self._run_command(aapt2_executable, apk_path, command) for command in self.COMMANDS]
        evidence = self._build_evidence(apk_path, version, command_results)
        return self._scan_results(evidence, command_results)

    def _resolve_apk_path(self, project_path: Path) -> Path | None:
        if project_path.is_file():
            return project_path if is_apk_file(project_path) else None
        return find_apk_in_directory(project_path)

    def _run_command(
        self,
        aapt2_executable: str,
        apk_path: Path,
        command: Aapt2CommandSpec,
    ) -> Aapt2CommandResult:
        argv = [
            aapt2_executable if value == "aapt2" else str(apk_path) if value == "<apk>" else value
            for value in command.argv_template
        ]
        started = time.perf_counter()
        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.DEFAULT_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            return Aapt2CommandResult(
                key=command.key,
                purpose=command.purpose,
                argv=argv,
                exit_code=None,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                execution_status="TIMEOUT",
                duration_seconds=time.perf_counter() - started,
                error_message=f"aapt2 {command.key} timed out.",
            )
        except KeyboardInterrupt:
            return Aapt2CommandResult(
                key=command.key,
                purpose=command.purpose,
                argv=argv,
                exit_code=None,
                stdout="",
                stderr="",
                execution_status="INTERRUPTED",
                duration_seconds=time.perf_counter() - started,
                error_message=f"aapt2 {command.key} was interrupted.",
            )
        except Exception as exc:
            return Aapt2CommandResult(
                key=command.key,
                purpose=command.purpose,
                argv=argv,
                exit_code=None,
                stdout="",
                stderr=str(exc),
                execution_status="TOOL_ERROR",
                duration_seconds=time.perf_counter() - started,
                error_message=str(exc),
            )

        status = "SUCCESS"
        if result.returncode != 0 and (result.stdout or result.stderr):
            status = "PARTIAL_SUCCESS"
        elif result.returncode != 0:
            status = "TOOL_ERROR"

        return Aapt2CommandResult(
            key=command.key,
            purpose=command.purpose,
            argv=argv,
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            execution_status=status,
            duration_seconds=time.perf_counter() - started,
        )

    def _aapt2_version(self, aapt2_executable: str) -> str:
        try:
            result = subprocess.run(
                [aapt2_executable, "version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except Exception:
            return ""
        return result.stdout.strip() or result.stderr.strip()

    def _build_evidence(
        self,
        apk_path: Path,
        aapt2_version: str,
        command_results: list[Aapt2CommandResult],
    ) -> dict[str, Any]:
        by_key = {result.key: result for result in command_results}
        parser_errors: list[str] = []
        badging = self._parse_badging(by_key.get("badging"), parser_errors)
        permissions = self._parse_permissions(badging, by_key.get("permissions"), by_key.get("xmltree_manifest"))
        manifest = self._parse_manifest_tree(by_key.get("xmltree_manifest"), permissions, badging)
        resources = self._parse_resources(by_key.get("resources"))
        relationships = self._relationships(permissions, manifest)
        execution_status = self._overall_execution_status(command_results, parser_errors)

        return {
            "schema_version": self.SCHEMA_VERSION,
            "extractor": {
                "name": "phoenix-aapt2",
                "version": self.EXTRACTOR_VERSION,
                "parser_version": self.PARSER_VERSION,
            },
            "apk": self._apk_identity(apk_path, badging),
            "extraction_metadata": {
                "execution_status": execution_status,
                "duration_seconds": round(sum(result.duration_seconds for result in command_results), 6),
                "aapt2_version": aapt2_version,
                "command_profile": self.COMMAND_PROFILE,
                "parser_errors": parser_errors,
                "limitations": self._limitations(),
            },
            "commands": [self._command_metadata(result) for result in command_results],
            "identity": badging,
            "permissions": permissions,
            "manifest_security_posture": manifest["security_posture"],
            "application": manifest["application"],
            "components": manifest["components"],
            "intent_filters": manifest["intent_filters"],
            "resource_summary": resources["summary"],
            "resource_candidates": resources["candidates"],
            "evidence_relationships": relationships + resources["relationships"],
            "candidate_interpretations": self._candidate_interpretations(permissions, manifest, resources),
            "downstream_correlation_requirements": self._correlation_requirements(),
            "raw_evidence": {
                result.key: {
                    "stdout": f"raw/aapt2_{result.key}_stdout.txt" if result.stdout else None,
                    "stderr": f"raw/aapt2_{result.key}_stderr.txt" if result.stderr else None,
                }
                for result in command_results
            },
        }

    def _parse_badging(
        self,
        result: Aapt2CommandResult | None,
        parser_errors: list[str],
    ) -> dict[str, Any]:
        identity: dict[str, Any] = {
            "package_name": None,
            "version_code": None,
            "version_name": None,
            "compile_sdk_version": None,
            "compile_sdk_codename": None,
            "min_sdk_version": None,
            "target_sdk_version": None,
            "application_label": None,
            "launchable_activity": None,
            "uses_permissions": [],
            "native_abis": [],
            "features": [],
            "densities": [],
            "locales": [],
            "provenance": self._provenance("badging"),
        }
        if result is None or not result.stdout:
            return identity

        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("package:"):
                attrs = self._single_quoted_attributes(stripped)
                identity["package_name"] = attrs.get("name")
                identity["version_code"] = attrs.get("versionCode")
                identity["version_name"] = attrs.get("versionName")
                identity["compile_sdk_version"] = attrs.get("compileSdkVersion")
                identity["compile_sdk_codename"] = attrs.get("compileSdkVersionCodename")
            elif stripped.startswith("sdkVersion:"):
                identity["min_sdk_version"] = self._quoted_tail(stripped)
            elif stripped.startswith("targetSdkVersion:"):
                identity["target_sdk_version"] = self._quoted_tail(stripped)
            elif stripped.startswith("application-label:"):
                identity["application_label"] = self._quoted_tail(stripped)
            elif stripped.startswith("launchable-activity:"):
                attrs = self._single_quoted_attributes(stripped)
                identity["launchable_activity"] = attrs.get("name")
            elif stripped.startswith("uses-permission:"):
                attrs = self._single_quoted_attributes(stripped)
                if attrs.get("name"):
                    identity["uses_permissions"].append(attrs["name"])
            elif stripped.startswith("native-code:"):
                identity["native_abis"] = self._quoted_values(stripped)
            elif stripped.startswith("uses-feature:"):
                attrs = self._single_quoted_attributes(stripped)
                if attrs.get("name"):
                    identity["features"].append(attrs["name"])
            elif stripped.startswith("densities:"):
                identity["densities"] = self._quoted_values(stripped)
            elif stripped.startswith("locales:"):
                identity["locales"] = self._quoted_values(stripped)

        if "package:" in result.stdout and not identity["package_name"]:
            parser_errors.append("badging output contained package line but no name parsed.")
        return identity

    def _parse_permissions(
        self,
        badging: dict[str, Any],
        permissions_result: Aapt2CommandResult | None,
        manifest_result: Aapt2CommandResult | None,
    ) -> list[dict[str, Any]]:
        observed: dict[str, set[str]] = {}
        for result, source in (
            (permissions_result, "permissions"),
            (manifest_result, "xmltree_manifest"),
        ):
            if result is None:
                continue
            if source == "permissions":
                for line in result.stdout.splitlines():
                    if "permission" not in line:
                        continue
                    for permission in self._quoted_name_values(line):
                        observed.setdefault(permission, set()).add(source)
            for permission in re.findall(r"android\.permission\.[A-Z0-9_]+", result.stdout):
                observed.setdefault(permission, set()).add(source)
        for permission in badging.get("uses_permissions", []):
            observed.setdefault(permission, set()).add("badging")

        return [
            {
                "id": self._evidence_id("permission", name),
                "name": name,
                "protection_level_hint": "dangerous" if name in self.DANGEROUS_PERMISSIONS else "unknown_or_normal",
                "fact_type": "declared_permission",
                "confidence": "high",
                "provenance": self._multi_provenance(sorted(sources)),
                "interpretation_hints": [
                    "declared permission is an extracted fact",
                    "runtime permission use requires downstream code or runtime correlation",
                ],
                "follow_up": [
                    "correlate with DEX API usage",
                    "compare permission drift across releases",
                ],
            }
            for name, sources in sorted(observed.items())
        ]

    def _parse_manifest_tree(
        self,
        result: Aapt2CommandResult | None,
        permissions: list[dict[str, Any]],
        badging: dict[str, Any],
    ) -> dict[str, Any]:
        application = self._empty_application()
        components: list[dict[str, Any]] = []
        intent_filters: list[dict[str, Any]] = []
        if result is not None and result.stdout:
            stack: list[dict[str, Any]] = []
            current_component_id: str | None = None
            current_filter: dict[str, Any] | None = None

            for line in result.stdout.splitlines():
                element = self._xmltree_element(line)
                if element:
                    depth, tag = element
                    while stack and stack[-1]["depth"] >= depth:
                        popped = stack.pop()
                        if popped["tag"] == "intent-filter" and current_filter is not None:
                            intent_filters.append(current_filter)
                            current_filter = None
                        if popped["tag"] in self.COMPONENT_TAGS:
                            current_component_id = self._nearest_component_id(stack)
                    node = {"depth": depth, "tag": tag}
                    stack.append(node)
                    if tag == "application":
                        node["object"] = application
                    elif tag in self.COMPONENT_TAGS:
                        component = self._empty_component(tag, len(components) + 1)
                        components.append(component)
                        node["object"] = component
                        current_component_id = component["id"]
                    elif tag == "intent-filter":
                        current_filter = self._empty_intent_filter(
                            len(intent_filters) + 1,
                            current_component_id,
                        )
                        node["object"] = current_filter
                        component = self._nearest_component(stack)
                        if component is not None:
                            component["intent_filter_ids"].append(current_filter["id"])
                    continue

                attr = self._xmltree_attribute(line)
                if not attr:
                    continue
                name, value = attr
                target = self._current_object(stack)
                if target is not None:
                    self._apply_manifest_attribute(target, name, value)
                self._apply_intent_attribute(current_filter, stack, name, value)

            if current_filter is not None:
                intent_filters.append(current_filter)

        components = [self._finalize_component(component) for component in components]
        intent_filters = [self._finalize_intent_filter(item) for item in intent_filters]
        security_posture = self._security_posture(application, components, permissions, badging)
        return {
            "application": application,
            "components": components,
            "intent_filters": intent_filters,
            "security_posture": security_posture,
        }

    def _parse_resources(
        self,
        result: Aapt2CommandResult | None,
    ) -> dict[str, Any]:
        candidates: list[dict[str, Any]] = []
        type_counts: dict[str, int] = {}
        if result is not None:
            for line in result.stdout.splitlines():
                parsed = self._resource_line(line)
                if parsed is None:
                    continue
                resource_type = parsed["resource_type"]
                type_counts[resource_type] = type_counts.get(resource_type, 0) + 1
                haystack = f"{parsed['name']} {parsed.get('value') or ''}".lower()
                if not any(keyword in haystack for keyword in self.SECURITY_RESOURCE_KEYWORDS):
                    continue
                if len(candidates) >= self.MAX_RESOURCE_CANDIDATES:
                    continue
                candidate_id = self._evidence_id("resource", parsed["resource_id"], parsed["name"])
                candidates.append(
                    {
                        "id": candidate_id,
                        "resource_id": parsed["resource_id"],
                        "resource_type": resource_type,
                        "name": parsed["name"],
                        "value_hint": parsed.get("value"),
                        "confidence": "medium",
                        "fact_type": "resource_follow_up_candidate",
                        "provenance": self._provenance("resources"),
                        "interpretation_hints": [
                            "resource name or value suggests security relevance",
                            "candidate requires decoded resource or code correlation",
                        ],
                        "follow_up": [
                            "correlate resource id with manifest references",
                            "inspect decoded resource content when available",
                        ],
                    }
                )

        relationships = [
            {
                "relationship_type": "application_resource_reference_candidate",
                "id": self._evidence_id(
                    "relationship",
                    "application_resource_reference_candidate",
                    "app",
                    candidate["id"],
                ),
                "source_id": "app",
                "target_id": candidate["id"],
                "confidence": "medium",
                "provenance": self._provenance("resources"),
            }
            for candidate in candidates
            if candidate["resource_type"] in {"xml", "string", "array", "bool"}
        ]
        return {
            "summary": {
                "resource_type_counts": dict(sorted(type_counts.items())),
                "candidate_count": len(candidates),
                "candidate_limit": self.MAX_RESOURCE_CANDIDATES,
                "exhaustive_normalization": False,
                "provenance": self._provenance("resources"),
            },
            "candidates": candidates,
            "relationships": relationships,
        }

    def _security_posture(
        self,
        application: dict[str, Any],
        components: list[dict[str, Any]],
        permissions: list[dict[str, Any]],
        badging: dict[str, Any],
    ) -> dict[str, Any]:
        exported = [component for component in components if component["exported"] is True]
        native_abis = badging.get("native_abis", [])
        return {
            "exported_component_count": len(exported),
            "declared_permission_count": len(permissions),
            "dangerous_permission_count": sum(
                1 for item in permissions if item["protection_level_hint"] == "dangerous"
            ),
            "cleartext_traffic_permitted": application["uses_cleartext_traffic"],
            "network_security_config_reference": application["network_security_config_reference"],
            "backup_allowed": application["allow_backup"],
            "full_backup_content_reference": application["full_backup_content_reference"],
            "request_legacy_external_storage": application["request_legacy_external_storage"],
            "native_abi_presence": bool(native_abis),
            "native_abis": native_abis,
            "deep_link_intent_filter_count": sum(
                1 for component in components for _ in component.get("intent_filter_ids", [])
            ),
            "posture_kind": "extracted_facts_and_candidates",
            "interpretation_hints": [
                "manifest attributes are static evidence, not exploitability findings",
                "exported components and permissions require downstream behavioral correlation",
            ],
        }

    def _candidate_interpretations(
        self,
        permissions: list[dict[str, Any]],
        manifest: dict[str, Any],
        resources: dict[str, Any],
    ) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        for component in manifest["components"]:
            if component["exported"] is True:
                candidates.append(
                    self._candidate(
                        "exported_component_review",
                        component["id"],
                        "Exported component is externally addressable evidence.",
                        "high",
                        ["correlate with intent filters, permissions, and DEX handlers"],
                    )
                )
            if component["component_type"] == "provider" and self._is_file_provider(component):
                candidates.append(
                    self._candidate(
                        "fileprovider_posture_review",
                        component["id"],
                        "Provider metadata/name suggests FileProvider posture review.",
                        "medium",
                        ["inspect provider authorities and paths XML"],
                    )
                )
        for permission in permissions:
            if permission["protection_level_hint"] == "dangerous":
                candidates.append(
                    self._candidate(
                        "dangerous_permission_correlation",
                        permission["id"],
                        "Dangerous permission is declared.",
                        "high",
                        ["correlate with runtime API usage and user-facing feature need"],
                    )
                )
        application = manifest["application"]
        if application["uses_cleartext_traffic"] is True:
            candidates.append(
                self._candidate(
                    "cleartext_traffic_posture_review",
                    "app",
                    "Application allows cleartext traffic by manifest attribute.",
                    "high",
                    ["correlate with network security config and endpoint evidence"],
                )
            )
        if application["network_security_config_reference"]:
            candidates.append(
                self._candidate(
                    "network_security_config_follow_up",
                    "app",
                    "Application references a network security config resource.",
                    "high",
                    ["decode and inspect referenced XML resource"],
                )
            )
        if application["allow_backup"] is True:
            candidates.append(
                self._candidate(
                    "backup_posture_review",
                    "app",
                    "Application permits Android backup by manifest attribute.",
                    "medium",
                    ["correlate with backup rules and sensitive local storage usage"],
                )
            )
        if resources["candidates"]:
            candidates.append(
                self._candidate(
                    "security_resource_follow_up",
                    "app",
                    "Security-relevant resource names were observed.",
                    "medium",
                    ["correlate resource ids with manifest and code references"],
                )
            )
        return candidates

    def _relationships(
        self,
        permissions: list[dict[str, Any]],
        manifest: dict[str, Any],
    ) -> list[dict[str, Any]]:
        relationships: list[dict[str, Any]] = []
        for permission in permissions:
            relationships.append(self._relationship("app_declares_permission", "app", permission["id"]))
        for component in manifest["components"]:
            relationships.append(self._relationship("app_declares_component", "app", component["id"]))
            if component["permission"]:
                relationships.append(
                    self._relationship(
                        "component_requires_permission",
                        component["id"],
                        self._evidence_id("permission", component["permission"]),
                    )
                )
            for filter_id in component.get("intent_filter_ids", []):
                relationships.append(self._relationship("component_declares_intent_filter", component["id"], filter_id))
        for intent_filter in manifest["intent_filters"]:
            for uri in intent_filter["uri_patterns"]:
                relationships.append(
                    {
                        **self._relationship(
                            "intent_filter_declares_uri_pattern",
                            intent_filter["id"],
                            self._evidence_id("uri", uri["normalized"]),
                        ),
                        "target": uri,
                    }
                )
        return relationships

    def _scan_results(
        self,
        evidence: dict[str, Any],
        command_results: list[Aapt2CommandResult],
    ) -> list[ScanResult]:
        execution_status = evidence["extraction_metadata"]["execution_status"]
        extractor_success = execution_status not in {
            "TIMEOUT",
            "TOOL_ERROR",
            "PARSING_ERROR",
            "INTERRUPTED",
        }
        error_message = "" if extractor_success else "aapt2 evidence extraction failed."
        artifacts = self._section_artifacts(evidence, command_results)
        results = []
        for relative_target_path, value in artifacts.items():
            results.append(
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=extractor_success,
                    error_message=error_message if relative_target_path == "aapt2_evidence.json" else "",
                    raw_output=json.dumps(value, indent=2, sort_keys=True),
                    relative_target_path=relative_target_path,
                    description=self.description,
                )
            )
        for command_result in command_results:
            if command_result.stdout:
                results.append(
                    ScanResult(
                        scanner_name=self.name,
                        scan_type=self.scan_type,
                        success=extractor_success,
                        raw_output=command_result.stdout,
                        relative_target_path=f"raw/aapt2_{command_result.key}_stdout.txt",
                        description=f"Raw aapt2 {command_result.key} stdout.",
                    )
                )
            if command_result.stderr:
                results.append(
                    ScanResult(
                        scanner_name=self.name,
                        scan_type=self.scan_type,
                        success=extractor_success,
                        raw_output=command_result.stderr,
                        relative_target_path=f"raw/aapt2_{command_result.key}_stderr.txt",
                        description=f"Raw aapt2 {command_result.key} stderr.",
                    )
                )
        return results

    def _section_artifacts(
        self,
        evidence: dict[str, Any],
        command_results: list[Aapt2CommandResult],
    ) -> dict[str, Any]:
        command_status = {command.key: command.execution_status for command in command_results}
        artifacts = {
            "aapt2_evidence.json": evidence,
            "metadata.json": {
                "apk": evidence["apk"],
                "identity": {
                    "package_name": evidence["identity"]["package_name"],
                    "version_code": evidence["identity"]["version_code"],
                    "version_name": evidence["identity"]["version_name"],
                    "min_sdk_version": evidence["identity"]["min_sdk_version"],
                    "target_sdk_version": evidence["identity"]["target_sdk_version"],
                    "compile_sdk_version": evidence["identity"]["compile_sdk_version"],
                    "application_label": evidence["identity"]["application_label"],
                    "launchable_activity": evidence["identity"]["launchable_activity"],
                },
                "extractor": evidence["extractor"],
            },
            "execution_metadata.json": {
                "extraction_metadata": evidence["extraction_metadata"],
                "commands": evidence["commands"],
                "raw_evidence": evidence["raw_evidence"],
            },
            "identity.json": evidence["identity"],
            "permissions.json": {
                "permissions": evidence["permissions"],
                "requested": [item["name"] for item in evidence["permissions"]],
            },
            "manifest_security_posture.json": evidence["manifest_security_posture"],
            "application.json": evidence["application"],
            "components.json": {
                "components": evidence["components"],
                "activities": self._components_by_type(evidence["components"], "activity"),
                "activity_aliases": self._components_by_type(evidence["components"], "activity-alias"),
                "services": self._components_by_type(evidence["components"], "service"),
                "receivers": self._components_by_type(evidence["components"], "receiver"),
                "providers": self._components_by_type(evidence["components"], "provider"),
            },
            "intent_filters.json": {
                "intent_filters": evidence["intent_filters"],
                "deep_links": [item for item in evidence["intent_filters"] if item.get("uri_patterns")],
            },
            "resource_summary.json": evidence["resource_summary"],
            "resource_candidates.json": {"resource_candidates": evidence["resource_candidates"]},
            "evidence_relationships.json": {"relationships": evidence["evidence_relationships"]},
            "candidate_interpretations.json": {"candidate_interpretations": evidence["candidate_interpretations"]},
            "correlation_requirements.json": {
                "downstream_correlation_requirements": evidence["downstream_correlation_requirements"]
            },
            "limitations.json": {"limitations": evidence["extraction_metadata"]["limitations"]},
        }
        artifacts["scan_index.json"] = self._scan_index(artifacts, command_status)
        return artifacts

    def _components_by_type(
        self,
        components: list[dict[str, Any]],
        component_type: str,
    ) -> list[dict[str, Any]]:
        return [component for component in components if component.get("component_type") == component_type]

    def _scan_index(
        self,
        artifacts: dict[str, Any],
        command_status: dict[str, str],
    ) -> dict[str, Any]:
        command_by_artifact = {
            "identity.json": "badging",
            "metadata.json": "badging",
            "permissions.json": "permissions",
            "manifest_security_posture.json": "xmltree_manifest",
            "application.json": "xmltree_manifest",
            "components.json": "xmltree_manifest",
            "intent_filters.json": "xmltree_manifest",
            "resource_summary.json": "resources",
            "resource_candidates.json": "resources",
        }
        return {
            "artifacts": [
                {
                    "name": name,
                    "item_count": self._artifact_item_count(name, value),
                    "partial_failure": command_status.get(command_by_artifact.get(name, ""), "SUCCESS")
                    not in {"SUCCESS"},
                }
                for name, value in artifacts.items()
                if name != "scan_index.json"
            ],
            "command_status": command_status,
        }

    def _artifact_item_count(self, name: str, value: Any) -> int:
        if name == "components.json":
            return len(value["components"])
        if name == "intent_filters.json":
            return len(value["intent_filters"])
        if name == "permissions.json":
            return len(value["permissions"])
        if name == "resource_candidates.json":
            return len(value["resource_candidates"])
        if name == "evidence_relationships.json":
            return len(value["relationships"])
        if name == "candidate_interpretations.json":
            return len(value["candidate_interpretations"])
        if isinstance(value, list):
            return len(value)
        return 0

    def _overall_execution_status(
        self,
        command_results: list[Aapt2CommandResult],
        parser_errors: list[str],
    ) -> str:
        statuses = {result.execution_status for result in command_results}
        successful_outputs = [
            result
            for result in command_results
            if result.execution_status in {"SUCCESS", "PARTIAL_SUCCESS"} and result.stdout
        ]
        if not successful_outputs:
            if "TIMEOUT" in statuses:
                return "TIMEOUT"
            if "INTERRUPTED" in statuses:
                return "INTERRUPTED"
            return "TOOL_ERROR"
        if parser_errors:
            return "PARTIAL_SUCCESS"
        if statuses == {"SUCCESS"}:
            return "SUCCESS"
        return "PARTIAL_SUCCESS"

    def _command_metadata(self, result: Aapt2CommandResult) -> dict[str, Any]:
        return {
            "key": result.key,
            "purpose": result.purpose,
            "argv": [
                "aapt2" if index == 0 else "<apk>" if value.endswith(".apk") else value
                for index, value in enumerate(result.argv)
            ],
            "tool_exit_code": result.exit_code,
            "execution_status": result.execution_status,
            "duration_seconds": round(result.duration_seconds, 6),
            "stdout_sha256": self._sha256_text(result.stdout) if result.stdout else None,
            "stderr_sha256": self._sha256_text(result.stderr) if result.stderr else None,
        }

    def _apk_identity(self, apk_path: Path, badging: dict[str, Any]) -> dict[str, Any]:
        return {
            "file_name": apk_path.name,
            "sha256": self._sha256_file(apk_path),
            "size_bytes": apk_path.stat().st_size,
            "package_name": badging.get("package_name"),
            "version_code": badging.get("version_code"),
            "version_name": badging.get("version_name"),
        }

    def _empty_application(self) -> dict[str, Any]:
        return {
            "id": "app",
            "name": None,
            "label_reference": None,
            "debuggable": None,
            "allow_backup": None,
            "full_backup_content_reference": None,
            "uses_cleartext_traffic": None,
            "network_security_config_reference": None,
            "request_legacy_external_storage": None,
            "extract_native_libs": None,
            "provenance": self._provenance("xmltree_manifest"),
        }

    def _empty_component(self, tag: str, index: int) -> dict[str, Any]:
        return {
            "id": f"component-{index:04d}",
            "component_type": tag,
            "name": None,
            "exported": None,
            "enabled": None,
            "permission": None,
            "authorities": None,
            "process": None,
            "task_affinity": None,
            "metadata": [],
            "intent_filter_ids": [],
            "confidence": "high",
            "fact_type": "manifest_component",
            "provenance": self._provenance("xmltree_manifest"),
            "interpretation_hints": [
                "component declaration is static manifest evidence",
                "exploitability requires downstream behavioral validation",
            ],
        }

    def _empty_intent_filter(
        self,
        index: int,
        component_id: str | None,
    ) -> dict[str, Any]:
        intent_filter_id = f"intent-filter-{index:04d}"
        return {
            "id": intent_filter_id,
            "component_id": component_id,
            "actions": [],
            "categories": [],
            "data": [],
            "uri_patterns": [],
            "auth_related_entrypoint_indicator": False,
            "confidence": "high",
            "fact_type": "manifest_intent_filter",
            "provenance": self._provenance("xmltree_manifest"),
        }

    def _apply_manifest_attribute(
        self,
        target: dict[str, Any],
        name: str,
        value: str,
    ) -> None:
        normalized = self._android_name(name)
        if target.get("id") == "app":
            mapping = {
                "name": "name",
                "label": "label_reference",
                "debuggable": "debuggable",
                "allowBackup": "allow_backup",
                "fullBackupContent": "full_backup_content_reference",
                "usesCleartextTraffic": "uses_cleartext_traffic",
                "networkSecurityConfig": "network_security_config_reference",
                "requestLegacyExternalStorage": "request_legacy_external_storage",
                "extractNativeLibs": "extract_native_libs",
            }
            field = mapping.get(normalized)
            if field:
                target[field] = self._manifest_value(value)
        elif target.get("component_type"):
            mapping = {
                "name": "name",
                "exported": "exported",
                "enabled": "enabled",
                "permission": "permission",
                "authorities": "authorities",
                "process": "process",
                "taskAffinity": "task_affinity",
            }
            field = mapping.get(normalized)
            if field:
                target[field] = self._manifest_value(value)

    def _apply_intent_attribute(
        self,
        current_filter: dict[str, Any] | None,
        stack: list[dict[str, Any]],
        name: str,
        value: str,
    ) -> None:
        if current_filter is None or not stack:
            return
        current_tag = stack[-1]["tag"]
        normalized = self._android_name(name)
        manifest_value = self._manifest_value(value)
        if current_tag == "action" and normalized == "name":
            current_filter["actions"].append(manifest_value)
        elif current_tag == "category" and normalized == "name":
            current_filter["categories"].append(manifest_value)
        elif current_tag == "data":
            current_filter["data"].append({normalized: manifest_value})

    def _finalize_component(self, component: dict[str, Any]) -> dict[str, Any]:
        component["follow_up"] = [
            "correlate component handlers with DEX code paths",
            "validate runtime reachability before deriving findings",
        ]
        return component

    def _finalize_intent_filter(self, item: dict[str, Any]) -> dict[str, Any]:
        item["actions"] = sorted(set(filter(None, item["actions"])))
        item["categories"] = sorted(set(filter(None, item["categories"])))
        merged: dict[str, str] = {}
        for entry in item["data"]:
            merged.update({key: value for key, value in entry.items() if value is not None})
        if merged:
            item["uri_patterns"] = [self._uri_pattern(merged)]
        auth_terms = ("login", "oauth", "sso", "callback", "auth", "token")
        haystack = " ".join(item["actions"] + item["categories"] + list(merged.values())).lower()
        item["auth_related_entrypoint_indicator"] = any(term in haystack for term in auth_terms)
        return item

    def _uri_pattern(self, data: dict[str, str]) -> dict[str, Any]:
        scheme = data.get("scheme")
        host = data.get("host")
        port = data.get("port")
        path = data.get("path") or data.get("pathPrefix") or data.get("pathPattern") or data.get("pathAdvancedPattern")
        normalized = ""
        if scheme:
            normalized += f"{scheme}://"
        if host:
            normalized += host
        if port:
            normalized += f":{port}"
        if path:
            normalized += path
        return {
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
            "normalized": normalized or json.dumps(data, sort_keys=True),
            "is_web_link": scheme in {"http", "https"},
            "is_custom_scheme": bool(scheme and scheme not in {"http", "https"}),
        }

    def _current_object(self, stack: list[dict[str, Any]]) -> dict[str, Any] | None:
        for item in reversed(stack):
            if "object" in item and item["tag"] in self.COMPONENT_TAGS | {"application"}:
                return item["object"]
        return None

    def _nearest_component_id(self, stack: list[dict[str, Any]]) -> str | None:
        component = self._nearest_component(stack)
        return component["id"] if component is not None else None

    def _nearest_component(self, stack: list[dict[str, Any]]) -> dict[str, Any] | None:
        for item in reversed(stack):
            if item["tag"] in self.COMPONENT_TAGS and "object" in item:
                return item["object"]
        return None

    def _xmltree_element(self, line: str) -> tuple[int, str] | None:
        match = re.match(r"(?P<indent>\s*)E:\s+(?P<tag>[\w.-]+)", line)
        if not match:
            return None
        return len(match.group("indent")), match.group("tag")

    def _xmltree_attribute(self, line: str) -> tuple[str, str] | None:
        match = re.match(r"\s*A:\s+(?P<name>[^=\s(]+)(?:\([^)]+\))?=(?P<value>.+)", line)
        if not match:
            return None
        return match.group("name"), match.group("value").strip()

    def _resource_line(self, line: str) -> dict[str, str] | None:
        match = re.search(
            r"resource\s+(?P<id>0x[0-9a-fA-F]+)\s+"
            r"(?P<package>[^:\s]+):(?P<type>[^/\s]+)/(?P<name>[^:\s]+)",
            line,
        )
        if not match:
            return None
        value_match = re.search(r'"(?P<value>[^"]+)"', line)
        return {
            "resource_id": match.group("id"),
            "package": match.group("package"),
            "resource_type": match.group("type"),
            "name": match.group("name"),
            "value": value_match.group("value") if value_match else "",
        }

    def _single_quoted_attributes(self, line: str) -> dict[str, str]:
        return dict(re.findall(r"([A-Za-z0-9_]+)='([^']*)'", line))

    def _quoted_tail(self, line: str) -> str | None:
        values = self._quoted_values(line)
        return values[0] if values else None

    def _quoted_values(self, line: str) -> list[str]:
        return re.findall(r"'([^']*)'", line)

    def _quoted_name_values(self, line: str) -> list[str]:
        return re.findall(r"name='([^']+)'", line)

    def _manifest_value(self, raw_value: str) -> Any:
        raw_value = raw_value.strip()
        raw_match = re.search(r'\(Raw:\s+"(?P<raw>[^"]*)"\)', raw_value)
        if raw_match:
            return raw_match.group("raw")
        quoted = re.search(r'"(?P<quoted>[^"]*)"', raw_value)
        if quoted:
            return quoted.group("quoted")
        if raw_value.endswith("0xffffffff"):
            return True
        if raw_value.endswith("0x00000000"):
            return False
        resource = re.search(r"@0x[0-9a-fA-F]+", raw_value)
        if resource:
            return resource.group(0)
        return raw_value

    def _android_name(self, name: str) -> str:
        return name.split(":", 1)[-1]

    def _is_file_provider(self, component: dict[str, Any]) -> bool:
        haystack = " ".join(
            str(value)
            for value in (
                component.get("name"),
                component.get("authorities"),
                component.get("permission"),
            )
            if value
        ).lower()
        return "fileprovider" in haystack or "file.provider" in haystack

    def _candidate(
        self,
        candidate_type: str,
        evidence_id: str,
        hint: str,
        confidence: str,
        follow_up: list[str],
    ) -> dict[str, Any]:
        return {
            "id": self._evidence_id("candidate", candidate_type, evidence_id),
            "candidate_type": candidate_type,
            "related_evidence_id": evidence_id,
            "confidence": confidence,
            "interpretation_hint": hint,
            "follow_up": follow_up,
            "not_a_finding": True,
        }

    def _relationship(
        self,
        relationship_type: str,
        source_id: str,
        target_id: str,
    ) -> dict[str, Any]:
        return {
            "id": self._evidence_id("relationship", relationship_type, source_id, target_id),
            "relationship_type": relationship_type,
            "source_id": source_id,
            "target_id": target_id,
            "confidence": "high",
            "provenance": self._provenance("xmltree_manifest"),
        }

    def _provenance(self, command_key: str) -> dict[str, Any]:
        return {
            "command_source": command_key,
            "raw_evidence_reference": f"raw/aapt2_{command_key}_stdout.txt",
            "parser_version": self.PARSER_VERSION,
        }

    def _multi_provenance(self, command_keys: list[str]) -> dict[str, Any]:
        return {
            "command_sources": command_keys,
            "raw_evidence_references": [f"raw/aapt2_{command_key}_stdout.txt" for command_key in command_keys],
            "parser_version": self.PARSER_VERSION,
        }

    def _evidence_id(self, *parts: object) -> str:
        digest = hashlib.sha256(":".join(str(part) for part in parts).encode()).hexdigest()
        return f"aapt2-{digest[:16]}"

    def _sha256_text(self, value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def _sha256_file(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _limitations(self) -> list[str]:
        return [
            "does not observe runtime behavior",
            "does not validate exploitability",
            "does not confirm permission usage",
            "does not analyze DEX semantics",
            "does not observe dynamic loading or dynamic component registration",
            "does not confirm secret validity",
        ]

    def _correlation_requirements(self) -> list[str]:
        return [
            "correlate exported components with DEX handlers and runtime reachability",
            "correlate declared permissions with API usage and runtime permission requests",
            "decode referenced XML resources for network security and provider path details",
            "compare stable evidence ids across releases for regression analysis",
            "correlate deep links with server-side app link verification and auth flows",
        ]
