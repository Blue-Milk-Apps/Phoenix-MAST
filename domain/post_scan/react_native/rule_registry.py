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
        "writes_sensitive_information_to_system_log": frozenset({"react-native.source.sensitive-log"}),
    },
    "Network": {
        "sensitive_information_unencrypted_in_transit": frozenset({"react-native.source.cleartext-http"}),
        "weak_certificate_validation_enables_mitm": frozenset({"react-native.source.disabled-tls-validation"}),
    },
    "Data Storage": {
        "sensitive_values_stored_insecurely": frozenset({"react-native.source.sensitive-async-storage"}),
    },
    "Resilience": {},
}

RULE_SEVERITIES: dict[str, str] = {
    "react-native.source.cleartext-http": "High",
    "react-native.source.disabled-tls-validation": "High",
    "react-native.source.sensitive-async-storage": "High",
    "react-native.source.sensitive-log": "Medium",
    "react-native.source.sql-injection": "High",
    "react-native.source.weak-cipher": "High",
    "react-native.source.weak-hash": "High",
}


def _build_registry() -> dict[str, ReactNativeRuleMapping]:
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


REACT_NATIVE_RULE_REGISTRY = _build_registry()
REACT_NATIVE_RULE_IDS = frozenset(REACT_NATIVE_RULE_REGISTRY)


def unclassified_react_native_rule_ids(rule_ids: set[str] | frozenset[str]) -> set[str]:
    """Return bundled React Native rule IDs without an explicit disposition."""

    return set(rule_ids) - set(REACT_NATIVE_RULE_IDS)
