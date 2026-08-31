"""Contract tests for the Flutter OpenGrep rule registry."""

from __future__ import annotations

from pathlib import Path

import yaml

from domain.post_scan.flutter.rule_registry import (
    FLUTTER_RULE_IDS,
    FLUTTER_RULE_REGISTRY,
    RAW_ONLY_RULE_REASONS,
    REPORT_RULE_IDS_BY_SECTION,
    RULE_SEVERITIES,
    FlutterRuleDisposition,
    unclassified_flutter_rule_ids,
)


def test_flutter_rule_contract_classifies_every_planned_rule() -> None:
    assert FLUTTER_RULE_IDS == frozenset(
        {
            "flutter.source.bad-certificate-callback",
            "flutter.source.cleartext-http",
            "flutter.source.sensitive-hive-storage",
            "flutter.source.sensitive-log",
            "flutter.source.sensitive-shared-preferences",
            "flutter.source.sql-injection",
            "flutter.source.unsafe-platform-channel",
            "flutter.source.weak-cipher",
            "flutter.source.weak-hash",
            "flutter.source.webview-ssl-bypass",
        }
    )
    assert set(RULE_SEVERITIES) == set(FLUTTER_RULE_IDS)
    assert unclassified_flutter_rule_ids(FLUTTER_RULE_IDS) == set()


def test_reportable_flutter_rules_have_sections_evidence_keys_and_supported_severities() -> None:
    reportable_rule_ids = {
        rule_id
        for section in REPORT_RULE_IDS_BY_SECTION.values()
        for rule_ids in section.values()
        for rule_id in rule_ids
    }

    assert reportable_rule_ids == set(FLUTTER_RULE_IDS) - set(RAW_ONLY_RULE_REASONS)
    for rule_id in reportable_rule_ids:
        mapping = FLUTTER_RULE_REGISTRY[rule_id]
        assert mapping.disposition is FlutterRuleDisposition.REPORT_VULNERABILITY
        assert mapping.section in {"Code", "Network", "Data Storage", "Resilience"}
        assert mapping.evidence_key
        assert mapping.severity in {"High", "Medium", "Low", "Info"}
        assert mapping.applies_to == frozenset({"SOURCE"})


def test_unsafe_platform_channel_rule_remains_manual_review_only() -> None:
    mapping = FLUTTER_RULE_REGISTRY["flutter.source.unsafe-platform-channel"]

    assert mapping.disposition is FlutterRuleDisposition.RAW_ONLY
    assert mapping.section == "Raw"
    assert mapping.severity == "Medium"
    assert mapping.evidence_key == ""
    assert "manual review" in mapping.reason


def test_bundled_flutter_rules_match_the_registry_contract() -> None:
    rules_root = Path(__file__).parents[3] / "rules" / "flutter"
    bundled_rules: dict[str, dict[str, object]] = {}
    for rules_path in sorted(rules_root.glob("*.yml")):
        document = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
        for rule in document["rules"]:
            rule_id = str(rule["id"])
            assert rule_id not in bundled_rules
            bundled_rules[rule_id] = rule

    assert set(bundled_rules) == set(FLUTTER_RULE_IDS)
    for rule_id, mapping in FLUTTER_RULE_REGISTRY.items():
        phoenix = bundled_rules[rule_id]["metadata"]["phoenix"]
        assert phoenix["severity"] == mapping.severity
        assert phoenix["report_section"] == mapping.section
        if mapping.disposition is FlutterRuleDisposition.REPORT_VULNERABILITY:
            assert phoenix["evidence_key"] == mapping.evidence_key
        else:
            assert phoenix["disposition"] == mapping.disposition.value
