"""Tests for the React Native rule-to-report contract."""

from __future__ import annotations

from pathlib import Path

import yaml

from domain.post_scan.react_native import (
    REACT_NATIVE_RULE_IDS,
    REACT_NATIVE_RULE_REGISTRY,
    ReactNativeRuleDisposition,
    unclassified_react_native_rule_ids,
)


def test_every_bundled_react_native_rule_is_classified() -> None:
    root = Path(__file__).parents[3]
    bundled_rule_ids: set[str] = set()
    for path in sorted((root / "rules" / "react_native").glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        bundled_rule_ids.update(rule["id"] for rule in document["rules"])

    assert bundled_rule_ids == set(REACT_NATIVE_RULE_IDS)
    assert unclassified_react_native_rule_ids(bundled_rule_ids) == set()


def test_all_current_react_native_rules_are_report_vulnerabilities() -> None:
    assert REACT_NATIVE_RULE_REGISTRY
    assert all(
        mapping.disposition is ReactNativeRuleDisposition.REPORT_VULNERABILITY
        and mapping.section in {"Code", "Network", "Data Storage", "Resilience"}
        and mapping.evidence_key
        and mapping.severity in {"Low", "Medium", "High"}
        for mapping in REACT_NATIVE_RULE_REGISTRY.values()
    )
