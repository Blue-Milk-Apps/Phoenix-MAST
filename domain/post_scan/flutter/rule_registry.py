"""Explicit classification of Phoenix Flutter OpenGrep rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class FlutterRuleDisposition(StrEnum):
    REPORT_VULNERABILITY = "report_vulnerability"
    RAW_ONLY = "raw_only"


@dataclass(frozen=True)
class FlutterRuleMapping:
    disposition: FlutterRuleDisposition
    section: str
    severity: str
    evidence_key: str = ""
    reason: str = ""
    applies_to: frozenset[str] = frozenset({"SOURCE"})


REPORT_RULE_IDS_BY_SECTION: dict[str, dict[str, frozenset[str]]] = {
    "Code": {
        "contains_potential_sql_injection": frozenset({"flutter.source.sql-injection"}),
        "encodes_data_using_insecure_cryptography": frozenset({"flutter.source.weak-hash"}),
        "utilizes_insecure_cryptography": frozenset({"flutter.source.weak-cipher"}),
        "writes_sensitive_information_to_system_log": frozenset({"flutter.source.sensitive-log"}),
    },
    "Network": {
        "sensitive_information_unencrypted_in_transit": frozenset({"flutter.source.cleartext-http"}),
        "weak_certificate_validation_enables_mitm": frozenset(
            {
                "flutter.source.bad-certificate-callback",
                "flutter.source.webview-ssl-bypass",
            }
        ),
    },
    "Data Storage": {
        "sensitive_values_stored_insecurely": frozenset(
            {
                "flutter.source.sensitive-hive-storage",
                "flutter.source.sensitive-shared-preferences",
            }
        ),
    },
    "Resilience": {},
}

RULE_SEVERITIES: dict[str, str] = {
    "flutter.source.bad-certificate-callback": "High",
    "flutter.source.cleartext-http": "High",
    "flutter.source.sensitive-hive-storage": "High",
    "flutter.source.sensitive-log": "Medium",
    "flutter.source.sensitive-shared-preferences": "High",
    "flutter.source.sql-injection": "High",
    "flutter.source.unsafe-platform-channel": "Medium",
    "flutter.source.weak-cipher": "High",
    "flutter.source.weak-hash": "High",
    "flutter.source.webview-ssl-bypass": "High",
}

RAW_ONLY_RULE_REASONS: dict[str, str] = {
    "flutter.source.unsafe-platform-channel": (
        "Platform-channel handling is retained for manual review until a pattern can establish an unsafe privileged "
        "operation rather than channel usage alone."
    ),
}


def _report_mappings() -> dict[str, FlutterRuleMapping]:
    mappings: dict[str, FlutterRuleMapping] = {}
    for section, evidence_groups in REPORT_RULE_IDS_BY_SECTION.items():
        for evidence_key, rule_ids in evidence_groups.items():
            for rule_id in rule_ids:
                mappings[rule_id] = FlutterRuleMapping(
                    disposition=FlutterRuleDisposition.REPORT_VULNERABILITY,
                    section=section,
                    severity=RULE_SEVERITIES[rule_id],
                    evidence_key=evidence_key,
                )
    return mappings


def _build_registry() -> dict[str, FlutterRuleMapping]:
    registry = _report_mappings()
    registry.update(
        {
            rule_id: FlutterRuleMapping(
                disposition=FlutterRuleDisposition.RAW_ONLY,
                section="Raw",
                severity=RULE_SEVERITIES[rule_id],
                reason=reason,
            )
            for rule_id, reason in RAW_ONLY_RULE_REASONS.items()
        }
    )
    return registry


FLUTTER_RULE_REGISTRY = _build_registry()
FLUTTER_RULE_IDS = frozenset(FLUTTER_RULE_REGISTRY)


def unclassified_flutter_rule_ids(rule_ids: set[str] | frozenset[str]) -> set[str]:
    """Return bundled Flutter rule IDs without an explicit disposition."""

    return set(rule_ids) - set(FLUTTER_RULE_IDS)
