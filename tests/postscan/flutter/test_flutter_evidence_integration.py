"""Registry coverage and cross-model tests for Flutter evidence."""

from __future__ import annotations

import json
from dataclasses import asdict, fields

import domain.post_scan.flutter as flutter_models
from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION as ANDROID_REPORT_RULES
from domain.post_scan.flutter import (
    FlutterCodeEvidence,
    FlutterDataStorageEvidence,
    FlutterFunctionality,
    FlutterManualReviewInventory,
    FlutterNetworkEvidence,
    FlutterResilienceEvidence,
    FlutterScanExtractionContext,
)
from domain.post_scan.flutter.rule_registry import (
    FLUTTER_RULE_REGISTRY,
    FlutterRuleDisposition,
)
from domain.post_scan.flutter.rule_registry import (
    REPORT_RULE_IDS_BY_SECTION as FLUTTER_REPORT_RULES,
)
from domain.post_scan.ios.rule_registry import (
    IOS_RULE_REGISTRY,
    POSITIVE_INFORMATIONAL_RULE_IDS,
    IOSRuleDisposition,
)
from domain.post_scan.ios.rule_registry import (
    REPORT_RULE_IDS_BY_SECTION as IOS_REPORT_RULES,
)


def test_every_registered_report_evidence_key_has_a_flutter_model_consumer() -> None:
    model_keys = {
        "Code": {field.name for field in fields(FlutterCodeEvidence)},
        "Network": {field.name for field in fields(FlutterNetworkEvidence)},
        "Data Storage": {field.name for field in fields(FlutterDataStorageEvidence)},
        "Resilience": {field.name for field in fields(FlutterResilienceEvidence)},
    }

    for registry in (FLUTTER_REPORT_RULES, ANDROID_REPORT_RULES, IOS_REPORT_RULES):
        for section, evidence_groups in registry.items():
            assert set(evidence_groups) <= model_keys[section]
            assert all(rule_ids for rule_ids in evidence_groups.values())


def test_partial_multiplatform_scan_preserves_positives_and_unknowns() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/app"},
            "source_metadata": {
                "platforms": {"android": True, "ios": True},
                "android": {
                    "available": True,
                    "metadata": {
                        "application": {"debuggable": False},
                        "permissions": [{"name": "android.permission.CAMERA"}],
                    },
                },
                "ios": {
                    "available": True,
                    "metadata": {
                        "permissions": [{"key": "NSMicrophoneUsageDescription", "purpose": "Record audio"}],
                    },
                },
            },
            "gitleaks_outputs": {"gitleaks_report.json": []},
            "opengrep": {
                "results": [
                    {
                        "check_id": "flutter.source.sql-injection",
                        "phoenix_scope": "flutter",
                        "path": "/workspace/app/lib/database.dart",
                        "start": {"line": 7},
                    },
                    {
                        "check_id": "flutter.source.unsafe-platform-channel",
                        "phoenix_scope": "flutter",
                        "path": "/workspace/app/lib/channel.dart",
                        "start": {"line": 11},
                    },
                    {
                        "check_id": "android.source.unsafe-biometric-auth",
                        "phoenix_scope": "android",
                        "path": "/workspace/app/android/app/Auth.kt",
                        "start": {"line": 18},
                    },
                    {
                        "check_id": "ios-weak-crypto-md5",
                        "phoenix_scope": "ios",
                        "path": "/workspace/app/ios/Runner/Crypto.swift",
                        "start": {"line": 23},
                    },
                    {
                        "check_id": "private-api-usage-dynamic",
                        "phoenix_scope": "ios",
                        "path": "/workspace/app/ios/Runner/Bridge.swift",
                        "start": {"line": 29},
                    },
                ],
                "scan_metadata": {
                    "scopes": {
                        "flutter": {
                            "status": "success",
                            "configured_rule_ids": [
                                "flutter.source.sql-injection",
                                "flutter.source.unsafe-platform-channel",
                            ],
                        },
                        "android": {"status": "failed", "configured_rule_ids": []},
                        "ios": {
                            "status": "success",
                            "configured_rule_ids": [
                                "ios-weak-crypto-md5",
                                "private-api-usage-dynamic",
                            ],
                        },
                    }
                },
            },
        }
    )

    code = FlutterCodeEvidence(context)
    network = FlutterNetworkEvidence(context)
    storage = FlutterDataStorageEvidence(context)
    resilience = FlutterResilienceEvidence(context)
    functionality = FlutterFunctionality(context)
    manual_review = FlutterManualReviewInventory(context)

    assert code.contains_potential_sql_injection.present is True
    assert code.encodes_data_using_insecure_cryptography.present is True
    assert code.writes_sensitive_information_to_system_log.present is None
    assert network.sensitive_information_unencrypted_in_transit.present is None
    assert storage.sensitive_values_stored_insecurely.present is None
    assert resilience.biometric_local_authentication_bypass_possible.present is True
    assert functionality.items["Camera"]["present"] is True
    assert functionality.items["Microphone"]["present"] is True
    assert functionality.items["SMS"]["present"] is None
    assert [finding.rule_id for finding in manual_review.findings] == [
        "flutter.source.unsafe-platform-channel",
        "private-api-usage-dynamic",
    ]
    assert manual_review.assessed_scopes == ["flutter"]
    assert manual_review.fully_assessed is False

    json.dumps(
        {
            "code": asdict(code),
            "network": asdict(network),
            "storage": asdict(storage),
            "resilience": asdict(resilience),
            "functionality": asdict(functionality),
            "manual_review": asdict(manual_review),
        }
    )


def test_raw_and_positive_informational_rules_cannot_enter_vulnerability_models() -> None:
    flutter_raw_ids = {
        rule_id
        for rule_id, mapping in FLUTTER_RULE_REGISTRY.items()
        if mapping.disposition is FlutterRuleDisposition.RAW_ONLY
    }
    ios_raw_ids = {
        rule_id for rule_id, mapping in IOS_RULE_REGISTRY.items() if mapping.disposition is IOSRuleDisposition.RAW_ONLY
    }
    results = [
        {
            "check_id": rule_id,
            "phoenix_scope": scope,
            "path": f"{scope}/{index}.source",
        }
        for scope, rule_ids in (("flutter", flutter_raw_ids), ("ios", ios_raw_ids))
        for index, rule_id in enumerate(sorted(rule_ids))
    ]
    results.extend(
        {
            "check_id": rule_id,
            "phoenix_scope": "ios",
            "path": f"ios/positive-{index}.swift",
        }
        for index, rule_id in enumerate(sorted(POSITIVE_INFORMATIONAL_RULE_IDS))
    )
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"ios": True},
                "ios": {"available": True, "metadata": {}},
            },
            "opengrep": {
                "results": results,
                "scan_metadata": {
                    "scopes": {
                        "flutter": {
                            "status": "success",
                            "configured_rule_ids": sorted(flutter_raw_ids),
                        },
                        "ios": {
                            "status": "success",
                            "configured_rule_ids": sorted(ios_raw_ids | set(POSITIVE_INFORMATIONAL_RULE_IDS)),
                        },
                    }
                },
            },
        }
    )

    vulnerability_output = json.dumps(
        {
            "code": asdict(FlutterCodeEvidence(context)),
            "network": asdict(FlutterNetworkEvidence(context)),
            "storage": asdict(FlutterDataStorageEvidence(context)),
            "resilience": asdict(FlutterResilienceEvidence(context)),
        }
    )
    manual_review = FlutterManualReviewInventory(context)

    assert not any(rule_id in vulnerability_output for rule_id in flutter_raw_ids | ios_raw_ids)
    assert not any(rule_id in vulnerability_output for rule_id in POSITIVE_INFORMATIONAL_RULE_IDS)
    assert {finding.rule_id for finding in manual_review.findings} == flutter_raw_ids | ios_raw_ids


def test_step_four_models_are_public_flutter_exports() -> None:
    expected_exports = {
        "FlutterCodeEvidence",
        "FlutterDataStorageEvidence",
        "FlutterEvidenceEntry",
        "FlutterFunctionality",
        "FlutterHardcodedValues",
        "FlutterManualReviewFinding",
        "FlutterManualReviewInventory",
        "FlutterNetworkEvidence",
        "FlutterResilienceEvidence",
    }

    assert expected_exports <= set(flutter_models.__all__)
    assert all(hasattr(flutter_models, name) for name in expected_exports)
