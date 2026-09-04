"""Build normalized React Native source report sections."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION as ANDROID_RULES
from domain.post_scan.ios.rule_registry import REPORT_RULE_IDS_BY_SECTION as IOS_RULES
from domain.post_scan.react_native.endpoints import ReactNativeEndpoints
from domain.post_scan.react_native.functionality import ReactNativeFunctionality
from domain.post_scan.react_native.opengrep_assessment import ReactNativeOpenGrepAssessment
from domain.post_scan.react_native.rule_registry import (
    REACT_NATIVE_RULE_REGISTRY,
    ReactNativeRuleDisposition,
)
from domain.post_scan.react_native.rule_registry import (
    REPORT_RULE_IDS_BY_SECTION as REACT_NATIVE_RULES,
)
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext
from domain.post_scan.react_native.security_evidence import (
    ReactNativeEvidenceEntry,
    combine_evidence_entries,
    derived_evidence,
    scope_catalog_applicable,
)


def build_report_sections(context: ReactNativeScanExtractionContext) -> dict[str, Any]:
    identity = context.identity
    android_identity = context.mapping(context.android_metadata.get("identity"))
    ios_identity = context.mapping(context.ios_metadata.get("identity"))
    project_path = context.project_path
    app_name = context.first_non_empty(
        identity.get("display_name"),
        android_identity.get("app_name"),
        ios_identity.get("display_name"),
        identity.get("package_name"),
        project_path.name,
    )
    version_name = context.first_non_empty(
        identity.get("version"), android_identity.get("version_name"), ios_identity.get("version")
    )
    version_code = context.first_non_empty(android_identity.get("version_code"), ios_identity.get("build"))

    sections: dict[str, Any] = {
        "meta": {
            "app_display_name": app_name,
            "file_name": project_path.name,
            "package_name": context.first_non_empty(identity.get("package_name"), android_identity.get("package_name")),
            "platform": "React Native",
            "reviewer_org": "Phoenix Security Report",
            "scan_date": context.scan_date,
            "target_type": context.first_non_empty(context.scan_metadata.get("target_type"), "SOURCE").upper(),
            "version_code": version_code,
            "version_name": version_name,
        },
        "file_info": {"filename": project_path.name, "size": "", "md5": "", "sha1": "", "sha256": ""},
        "app_info": {
            "icon_path": "",
            "name": app_name,
            "package_name": context.first_non_empty(android_identity.get("package_name"), identity.get("package_name")),
            "main_activity": context.first_non_empty(android_identity.get("main_activity")),
            "target_sdk": context.first_non_empty(android_identity.get("target_sdk")),
            "min_sdk": context.first_non_empty(android_identity.get("min_sdk"), ios_identity.get("minimum_os")),
            "max_sdk": "",
            "version_name": version_name,
            "app_store_id": "",
            "developer": "",
            "categories": "",
            "trackers_detected": "",
        },
        "platform_inventory": _platform_inventory(context),
        "dependency_inventory": _dependency_inventory(context),
        "application": context.mapping(context.android_metadata.get("application")),
        "app_components": _component_counts(context),
        "permissions": _permissions(context),
        "deep_links": context.mapping_list(context.android_metadata.get("deep_links")),
        "url_schemes": context.mapping(context.ios_metadata.get("url_schemes")).get("declared", []),
    }

    for section, output_key in (
        ("Code", "code_evidence"),
        ("Network", "network_evidence"),
        ("Data Storage", "data_storage_evidence"),
        ("Resilience", "resilience_evidence"),
    ):
        evidence = _evidence_section(context, section)
        if evidence:
            sections[output_key] = evidence

    endpoints = ReactNativeEndpoints(context)
    hardcoded = _hardcoded_values(context)
    hardcoded["urls"] = endpoints.urls
    if hardcoded["assessed"] or hardcoded["secrets"] or endpoints.assessed or endpoints.items:
        sections["hardcoded_values"] = {key: hardcoded[key] for key in ("urls", "emails", "secrets")}
        sections["endpoints"] = endpoints.items
    functionality = ReactNativeFunctionality(context)
    if functionality.applicable or functionality.assessed:
        sections["functionality"] = functionality.items
    manual_review = _manual_review(context)
    if manual_review["assessed"] or manual_review["findings"]:
        sections["manual_review"] = manual_review
    return sections


def _platform_inventory(context: ReactNativeScanExtractionContext) -> dict[str, Any]:
    return {
        "source_metadata_assessed": bool(context.source_metadata),
        "runtime": context.runtime,
        "android": {
            "detected": context.platforms["android"],
            "metadata_assessed": bool(context.android_metadata),
            **context.mapping(context.android_metadata.get("identity")),
        },
        "ios": {
            "detected": context.platforms["ios"],
            "metadata_assessed": bool(context.ios_metadata),
            **context.mapping(context.ios_metadata.get("identity")),
        },
        "warnings": context.warnings,
    }


def _dependency_inventory(context: ReactNativeScanExtractionContext) -> dict[str, Any]:
    dependencies = context.dependencies
    return {
        "metadata_assessed": bool(context.source_metadata.get("dependencies")),
        "sbom_assessed": context.syft_assessed,
        "declared": dependencies["declared"],
        "resolved": dependencies["resolved"],
        "sbom_packages": context.syft_packages,
    }


def _component_counts(context: ReactNativeScanExtractionContext) -> dict[str, int | None]:
    components = context.mapping(context.android_metadata.get("components"))
    result: dict[str, int | None] = {}
    for key in ("activities", "services", "receivers", "providers"):
        values = components.get(key)
        records = [item for item in values if isinstance(item, dict)] if isinstance(values, list) else None
        result[key] = len(records) if records is not None else None
        result[f"exported_{key}"] = (
            sum(item.get("exported") is True for item in records) if records is not None else None
        )
    return result


def _permissions(context: ReactNativeScanExtractionContext) -> list[dict[str, str]]:
    permissions: list[dict[str, str]] = []
    for item in context.mapping_list(context.android_metadata.get("permissions")):
        name = context.first_non_empty(item.get("name"))
        if name:
            permissions.append(
                {
                    "platform": "Android",
                    "permission": name,
                    "status": "",
                    "info": "",
                    "usage_description": "",
                    "general_description": "",
                }
            )
    for item in context.mapping_list(context.ios_metadata.get("permissions")):
        name = context.first_non_empty(item.get("key"))
        if name:
            permissions.append(
                {
                    "platform": "iOS",
                    "permission": name,
                    "status": "",
                    "info": "",
                    "usage_description": context.first_non_empty(item.get("purpose")),
                    "general_description": "",
                }
            )
    return permissions


def _evidence_section(context: ReactNativeScanExtractionContext, section: str) -> dict[str, dict[str, Any]]:
    assessment = ReactNativeOpenGrepAssessment(context)
    registries = {"react_native": REACT_NATIVE_RULES, "android": ANDROID_RULES, "ios": IOS_RULES}
    preferred_sections = {
        evidence_key: report_section for report_section, groups in REACT_NATIVE_RULES.items() for evidence_key in groups
    }
    scoped_groups: dict[str, dict[str, frozenset[str]]] = {}
    for scope, registry in registries.items():
        groups: dict[str, frozenset[str]] = {}
        for registry_section, registry_groups in registry.items():
            for evidence_key, rule_ids in registry_groups.items():
                if preferred_sections.get(evidence_key, registry_section) == section:
                    groups[evidence_key] = groups.get(evidence_key, frozenset()) | rule_ids
        scoped_groups[scope] = groups

    keys = set().union(*(groups for groups in scoped_groups.values()))
    output: dict[str, dict[str, Any]] = {}
    for key in sorted(keys):
        entries = [
            assessment.assess(scope, groups[key], key)
            for scope, groups in scoped_groups.items()
            if key in groups and scope_catalog_applicable(context, scope)
        ]
        if not entries:
            continue
        present = (
            True
            if any(item.present is True for item in entries)
            else False
            if entries and all(item.present is False for item in entries)
            else None
        )
        details = list(dict.fromkeys(detail for item in entries for detail in item.details))
        evidence = "; ".join(item.evidence for item in entries if item.evidence)
        output[key] = asdict(ReactNativeEvidenceEntry(present, evidence, details))

    for key, derived in derived_evidence(context, section).items():
        existing = output.get(key)
        if existing is None:
            output[key] = asdict(derived)
            continue
        if derived.present is None:
            continue
        combined = combine_evidence_entries(
            [
                ReactNativeEvidenceEntry(
                    existing.get("present"),
                    str(existing.get("evidence") or ""),
                    [str(item) for item in existing.get("details") or []],
                ),
                derived,
            ],
            absent_evidence=f"no_{key}_hits",
        )
        output[key] = asdict(combined)
    return output


def _hardcoded_values(context: ReactNativeScanExtractionContext) -> dict[str, Any]:
    secrets: list[dict[str, str]] = []
    for finding in context.gitleaks_findings:
        label = context.first_non_empty(finding.get("Description"), finding.get("RuleID"), "Gitleaks finding")
        location = _location(context, finding.get("File"), finding.get("StartLine"))
        secrets.append({"value": f"{label} credential (redacted)", "location": location})
    for finding in context.trufflehog_findings:
        label = context.first_non_empty(finding.get("DetectorName"), "TruffleHog finding")
        source = context.mapping(context.mapping(finding.get("SourceMetadata")).get("Data"))
        filesystem = context.mapping(source.get("Filesystem"))
        secrets.append(
            {
                "value": f"{label} credential (redacted)",
                "location": _location(context, filesystem.get("file"), filesystem.get("line")),
            }
        )
    unique = {(item["value"], item["location"]): item for item in secrets}
    return {
        "urls": [],
        "emails": [],
        "secrets": list(unique.values()),
        "assessed": context.gitleaks_assessed or context.trufflehog_assessed,
    }


def _manual_review(context: ReactNativeScanExtractionContext) -> dict[str, Any]:
    raw_rules = {
        rule_id: mapping
        for rule_id, mapping in REACT_NATIVE_RULE_REGISTRY.items()
        if mapping.disposition is ReactNativeRuleDisposition.RAW_ONLY
    }
    assessed = context.opengrep_scope_assessed("react_native", frozenset(raw_rules))
    findings = []
    for finding in context.opengrep_results_for_scope("react_native"):
        rule_id = context.first_non_empty(finding.get("check_id"))
        mapping = raw_rules.get(rule_id)
        if mapping:
            findings.append(
                {
                    "rule_id": rule_id,
                    "scope": "react_native",
                    "severity": mapping.severity,
                    "reason": mapping.reason,
                    "location": _location(
                        context, finding.get("path"), context.mapping(finding.get("start")).get("line")
                    ),
                    "message": context.first_non_empty(context.mapping(finding.get("extra")).get("message"), rule_id),
                }
            )
    return {
        "findings": findings,
        "assessed_scopes": ["react_native"] if assessed else [],
        "assessed": assessed,
        "fully_assessed": assessed,
    }


def _location(context: ReactNativeScanExtractionContext, raw_path: object, line: object) -> str:
    text = context.first_non_empty(raw_path)
    if text:
        path = Path(text)
        if path.is_absolute():
            try:
                text = path.relative_to(context.project_path).as_posix()
            except ValueError:
                text = path.as_posix()
    return f"{text}:{line}" if text and line not in (None, "") else text
