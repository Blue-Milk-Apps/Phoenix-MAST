import re
from collections import Counter
from dataclasses import fields
from pathlib import Path

import pytest

from adapters.output.phoenix_report.generate_report import (
    IOS_CODE_EVIDENCE_KEY_BY_CHECK,
    IOS_DATA_STORAGE_EVIDENCE_KEY_BY_CHECK,
    IOS_NETWORK_EVIDENCE_KEY_BY_CHECK,
    IOS_RESILIENCE_EVIDENCE_KEY_BY_CHECK,
)
from domain.post_scan.ios.binary.code_evidence import IOSCodeEvidence
from domain.post_scan.ios.binary.resilience_evidence import IOSResilienceEvidence
from domain.post_scan.ios.common.data_storage_evidence import IOSDataStorageEvidence
from domain.post_scan.ios.common.functionality import IOSFunctionality
from domain.post_scan.ios.common.network_evidence import IOSNetworkEvidence
from domain.post_scan.ios.common.permissions import PERMISSION_DETAILS, IOSPermissions
from domain.post_scan.ios.native.code_evidence import NativeIOSCodeEvidence
from domain.post_scan.ios.rule_registry import (
    FUNCTIONALITY_RULE_ID_TO_KEY,
    IOS_RULE_IDS,
    IOS_RULE_REGISTRY,
    PERMISSION_RULE_ID_TO_KEYS,
    RAW_ONLY_RULE_REASONS,
    REPORT_RULE_IDS_BY_SECTION,
    IOSRuleDisposition,
    unclassified_ios_rule_ids,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
RULE_ID_PATTERN = re.compile(r"^\s*-\s+id:\s*([^\s#]+)", re.MULTILINE)


def test_ios_rule_registry_classifies_every_rule_once() -> None:
    assert len(IOS_RULE_REGISTRY) == 87
    assert Counter(mapping.disposition for mapping in IOS_RULE_REGISTRY.values()) == {
        IOSRuleDisposition.REPORT_VULNERABILITY: 48,
        IOSRuleDisposition.FUNCTIONALITY: 20,
        IOSRuleDisposition.POSITIVE_INFORMATIONAL: 8,
        IOSRuleDisposition.RAW_ONLY: 11,
    }
    assert not unclassified_ios_rule_ids(IOS_RULE_IDS)
    assert all(mapping.applies_to for mapping in IOS_RULE_REGISTRY.values())
    assert all(
        mapping.reason for mapping in IOS_RULE_REGISTRY.values() if mapping.disposition is IOSRuleDisposition.RAW_ONLY
    )
    assert set(RAW_ONLY_RULE_REASONS) == {
        rule_id for rule_id, mapping in IOS_RULE_REGISTRY.items() if mapping.disposition is IOSRuleDisposition.RAW_ONLY
    }


def test_ios_rule_registry_flags_an_unclassified_new_rule() -> None:
    assert unclassified_ios_rule_ids(set(IOS_RULE_IDS) | {"ios.new.reportable-rule"}) == {"ios.new.reportable-rule"}


def test_ios_report_rule_evidence_keys_are_consumed_by_models_and_report() -> None:
    report_keys = {
        "Code": set(IOS_CODE_EVIDENCE_KEY_BY_CHECK.values()),
        "Network": set(IOS_NETWORK_EVIDENCE_KEY_BY_CHECK.values()),
        "Data Storage": set(IOS_DATA_STORAGE_EVIDENCE_KEY_BY_CHECK.values()),
        "Resilience": set(IOS_RESILIENCE_EVIDENCE_KEY_BY_CHECK.values()),
    }
    model_keys = {
        "Code": set(field.name for field in fields(NativeIOSCodeEvidence))
        & set(field.name for field in fields(IOSCodeEvidence)),
        "Network": {field.name for field in fields(IOSNetworkEvidence)},
        "Data Storage": {field.name for field in fields(IOSDataStorageEvidence)},
        "Resilience": {field.name for field in fields(IOSResilienceEvidence)},
    }

    for section, evidence_groups in REPORT_RULE_IDS_BY_SECTION.items():
        assert set(evidence_groups) <= report_keys[section]
        assert set(evidence_groups) <= model_keys[section]
        for evidence_key, rule_ids in evidence_groups.items():
            assert rule_ids
            assert all(IOS_RULE_REGISTRY[rule_id].evidence_key == evidence_key for rule_id in rule_ids)


def test_ios_functionality_and_permission_rule_consumers_are_valid() -> None:
    functionality_fields = {field.name for field in fields(IOSFunctionality)}
    assert {
        capability.replace(" ", "_") for capability in FUNCTIONALITY_RULE_ID_TO_KEY.values()
    } <= functionality_fields
    assert all(rule_id in IOS_RULE_IDS for rule_id in FUNCTIONALITY_RULE_ID_TO_KEY)
    assert all(rule_id in IOS_RULE_IDS for rule_id in PERMISSION_RULE_ID_TO_KEYS)
    assert all(
        permission_key in PERMISSION_DETAILS
        for permission_keys in PERMISSION_RULE_ID_TO_KEYS.values()
        for permission_key in permission_keys
    )


def test_explicit_rule_ids_populate_functionality_permissions_and_network_evidence() -> None:
    loaded_outputs = {
        "opengrep": {
            "results": [
                {
                    "check_id": "cam-lowlevel-usage",
                    "extra": {"metadata": {"phoenix": {"description": "Camera API detected."}}},
                },
                {
                    "check_id": "network-local-desc",
                    "extra": {"lines": "<key>NSLocalNetworkUsageDescription</key>"},
                },
                {
                    "check_id": "ats-disabled-usage",
                    "path": "Info.plist",
                    "extra": {"lines": "<key>NSAllowsArbitraryLoads</key><true/>"},
                },
            ]
        }
    }

    functionality = IOSFunctionality(loaded_outputs)
    assert functionality.Camera.present is True
    assert functionality.Camera.explanation == "Camera API detected."
    assert functionality.Networking.present is True

    permissions = IOSPermissions(loaded_outputs).items
    assert [item["permission"] for item in permissions] == ["NSLocalNetworkUsageDescription"]

    network_evidence = IOSNetworkEvidence(loaded_outputs)
    assert network_evidence.ats_disabled.present is True
    assert network_evidence.ats_disabled.evidence == ("Info.plist: <key>NSAllowsArbitraryLoads</key><true/>")


def test_installed_ios_rule_bundle_matches_tracked_registry() -> None:
    rule_files = sorted((REPOSITORY_ROOT / "rules" / "ios").glob("*.yml"))
    if not rule_files:
        pytest.skip("The external iOS OpenGrep rule bundle is not installed.")

    rule_ids = [
        match.group(1)
        for rule_file in rule_files
        for match in RULE_ID_PATTERN.finditer(rule_file.read_text(encoding="utf-8"))
    ]
    assert len(rule_ids) == len(set(rule_ids)), "The installed iOS rule bundle contains duplicate IDs."
    assert set(rule_ids) == set(IOS_RULE_IDS)
