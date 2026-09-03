"""Explicit classification of Phoenix React Native OpenGrep rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ReactNativeRuleDisposition(StrEnum):
    REPORT_VULNERABILITY = "report_vulnerability"
    RAW_ONLY = "raw_only"


@dataclass(frozen=True)
class ReactNativeRuleMapping:
    disposition: ReactNativeRuleDisposition
    section: str
    severity: str
    evidence_key: str = ""
    reason: str = ""
    applies_to: frozenset[str] = frozenset({"SOURCE"})


REPORT_RULE_IDS_BY_SECTION: dict[str, dict[str, frozenset[str]]] = {
    "Code": {
        "contains_potential_sql_injection": frozenset({"react-native.source.sql-injection"}),
        "encodes_data_using_insecure_cryptography": frozenset({"react-native.source.weak-hash"}),
        "utilizes_insecure_cryptography": frozenset({"react-native.source.weak-cipher"}),
        "uses_dynamic_code_execution": frozenset({"react-native.source.dynamic-code-execution"}),
        "writes_sensitive_information_to_system_log": frozenset({"react-native.source.sensitive-log"}),
    },
    "Network": {
        "insecure_webview_configuration": frozenset(
            {
                "react-native.source.webview-mixed-content",
                "react-native.source.webview-wildcard-origin",
            }
        ),
        "sensitive_information_unencrypted_in_transit": frozenset({"react-native.source.cleartext-http"}),
        "weak_certificate_validation_enables_mitm": frozenset({"react-native.source.reject-unauthorized-disabled"}),
    },
    "Data Storage": {
        "copies_sensitive_information_into_clipboard_without_user_consent": frozenset(
            {"react-native.source.sensitive-clipboard"}
        ),
        "sensitive_values_stored_insecurely": frozenset(
            {
                "react-native.source.sensitive-async-storage",
                "react-native.source.sensitive-file-write",
            }
        ),
    },
    "Resilience": {},
}

RULE_SEVERITIES: dict[str, str] = {
    "react-native.source.cleartext-http": "High",
    "react-native.source.dynamic-code-execution": "High",
    "react-native.source.insecure-randomness": "Medium",
    "react-native.source.reject-unauthorized-disabled": "High",
    "react-native.source.sensitive-async-storage": "High",
    "react-native.source.sensitive-clipboard": "High",
    "react-native.source.sensitive-file-write": "High",
    "react-native.source.sensitive-log": "Medium",
    "react-native.source.sensitive-native-module-call": "Medium",
    "react-native.source.sql-injection": "High",
    "react-native.source.weak-cipher": "High",
    "react-native.source.weak-hash": "High",
    "react-native.source.webview-message-bridge": "Medium",
    "react-native.source.webview-mixed-content": "High",
    "react-native.source.webview-wildcard-origin": "High",
}

RAW_ONLY_RULE_REASONS: dict[str, str] = {
    "react-native.source.insecure-randomness": (
        "Math.random requires manual review because the surrounding value may not be security-sensitive."
    ),
    "react-native.source.sensitive-native-module-call": (
        "Native module calls cross a trust boundary, but their native implementation determines whether they are unsafe."
    ),
    "react-native.source.webview-message-bridge": (
        "WebView message bridges require origin, validation, and handler review before they can be classified as unsafe."
    ),
}


def _report_mappings() -> dict[str, ReactNativeRuleMapping]:
    mappings: dict[str, ReactNativeRuleMapping] = {}
    for section, evidence_groups in REPORT_RULE_IDS_BY_SECTION.items():
        for evidence_key, rule_ids in evidence_groups.items():
            for rule_id in rule_ids:
                mappings[rule_id] = ReactNativeRuleMapping(
                    disposition=ReactNativeRuleDisposition.REPORT_VULNERABILITY,
                    section=section,
                    severity=RULE_SEVERITIES[rule_id],
                    evidence_key=evidence_key,
                )
    return mappings


def _build_registry() -> dict[str, ReactNativeRuleMapping]:
    registry = _report_mappings()
    registry.update(
        {
            rule_id: ReactNativeRuleMapping(
                disposition=ReactNativeRuleDisposition.RAW_ONLY,
                section="Raw",
                severity=RULE_SEVERITIES[rule_id],
                reason=reason,
            )
            for rule_id, reason in RAW_ONLY_RULE_REASONS.items()
        }
    )
    return registry


REACT_NATIVE_RULE_REGISTRY = _build_registry()
REACT_NATIVE_RULE_IDS = frozenset(REACT_NATIVE_RULE_REGISTRY)


def unclassified_react_native_rule_ids(rule_ids: set[str] | frozenset[str]) -> set[str]:
    """Return React Native rule IDs without an explicit report disposition."""

    return set(rule_ids) - set(REACT_NATIVE_RULE_IDS)
