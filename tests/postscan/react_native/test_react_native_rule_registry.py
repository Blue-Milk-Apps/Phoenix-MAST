from domain.post_scan.react_native import ReactNativeFunctionality
from domain.post_scan.react_native.rule_registry import (
    FUNCTIONALITY_RULE_ID_TO_KEY,
    REACT_NATIVE_RULE_IDS,
    REACT_NATIVE_RULE_REGISTRY,
    RULE_SEVERITIES,
    ReactNativeRuleDisposition,
    unclassified_react_native_rule_ids,
)


def test_every_registered_rule_has_a_severity_and_disposition() -> None:
    assert REACT_NATIVE_RULE_IDS == frozenset(RULE_SEVERITIES)
    assert all(mapping.severity for mapping in REACT_NATIVE_RULE_REGISTRY.values())
    assert all(mapping.disposition for mapping in REACT_NATIVE_RULE_REGISTRY.values())


def test_raw_only_rules_explain_why_manual_review_is_required() -> None:
    raw_only = [
        mapping
        for mapping in REACT_NATIVE_RULE_REGISTRY.values()
        if mapping.disposition is ReactNativeRuleDisposition.RAW_ONLY
    ]

    assert raw_only
    assert all(mapping.section == "Raw" and mapping.reason for mapping in raw_only)


def test_unclassified_rule_ids_are_reported() -> None:
    assert unclassified_react_native_rule_ids(REACT_NATIVE_RULE_IDS | {"react-native.source.unclassified"}) == {
        "react-native.source.unclassified"
    }


def test_functionality_rules_map_to_mobile_capabilities() -> None:
    assert FUNCTIONALITY_RULE_ID_TO_KEY
    assert set(FUNCTIONALITY_RULE_ID_TO_KEY.values()) <= set(ReactNativeFunctionality.CAPABILITIES)
    assert all(
        REACT_NATIVE_RULE_REGISTRY[rule_id].disposition is ReactNativeRuleDisposition.FUNCTIONALITY
        for rule_id in FUNCTIONALITY_RULE_ID_TO_KEY
    )
