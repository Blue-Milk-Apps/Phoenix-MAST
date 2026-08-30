"""Tests for Flutter data-storage evidence across Dart and embedded platforms."""

from __future__ import annotations

from domain.post_scan.flutter import FlutterDataStorageEvidence, FlutterScanExtractionContext
from domain.post_scan.ios.rule_registry import (
    COMPLETE_FILE_PROTECTION_RULE_IDS,
    DATA_STORAGE_RULE_IDS_BY_EVIDENCE_KEY,
)


def test_combines_flutter_android_and_ios_storage_findings() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/app"},
            "source_metadata": {
                "platforms": {"android": True, "ios": True},
                "android": {"available": True, "metadata": {}},
                "ios": {"available": True, "metadata": {}},
            },
            "opengrep": {
                "results": [
                    {
                        "check_id": "flutter.source.sensitive-hive-storage",
                        "phoenix_scope": "flutter",
                        "path": "/workspace/app/lib/storage.dart",
                        "start": {"line": 12},
                    },
                    {
                        "check_id": "android.source.sensitive-external-storage",
                        "phoenix_scope": "android",
                        "path": "/workspace/app/android/app/Storage.kt",
                        "start": {"line": 20},
                    },
                    {
                        "check_id": "ios.storage.deprecated-keychain-accessibility",
                        "phoenix_scope": "ios",
                        "path": "/workspace/app/ios/Runner/Keychain.swift",
                        "start": {"line": 28},
                    },
                ],
                "scan_metadata": {"scopes": {}},
            },
        }
    )

    evidence = FlutterDataStorageEvidence(context)

    assert evidence.assessed is True
    assert evidence.sensitive_values_stored_insecurely.details == ["lib/storage.dart:12"]
    assert evidence.sensitive_information_stored_in_external_storage.details == ["android/app/Storage.kt:20"]
    assert evidence.deprecated_keychain_attributes.details == ["ios/Runner/Keychain.swift:28"]


def test_shared_flutter_and_ios_storage_result_requires_both_scopes() -> None:
    complete = FlutterDataStorageEvidence(_sensitive_values_context(ios_rule_configured=True))
    incomplete = FlutterDataStorageEvidence(_sensitive_values_context(ios_rule_configured=False))

    assert complete.sensitive_values_stored_insecurely.present is False
    assert incomplete.sensitive_values_stored_insecurely.present is None


def test_builds_android_external_storage_permission_evidence() -> None:
    positive = FlutterDataStorageEvidence(
        _android_permissions_context(
            [
                {"name": "android.permission.CAMERA"},
                {"name": "android.permission.READ_MEDIA_IMAGES"},
            ]
        )
    )
    negative = FlutterDataStorageEvidence(_android_permissions_context([]))
    unknown = FlutterDataStorageEvidence(_android_permissions_context(None))

    assert positive.accesses_external_storage.present is True
    assert positive.accesses_external_storage.details == ["android.permission.READ_MEDIA_IMAGES"]
    assert negative.accesses_external_storage.present is False
    assert negative.accesses_external_storage.evidence == "no_external_storage_permissions"
    assert unknown.accesses_external_storage.present is None


def test_positive_file_protection_rules_do_not_become_vulnerabilities() -> None:
    weak_rule_ids = DATA_STORAGE_RULE_IDS_BY_EVIDENCE_KEY["weak_file_protection"]
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"ios": True},
                "ios": {"available": True, "metadata": {}},
            },
            "opengrep": {
                "results": [
                    {
                        "check_id": next(iter(COMPLETE_FILE_PROTECTION_RULE_IDS)),
                        "phoenix_scope": "ios",
                        "path": "ios/Runner/SecureStorage.swift",
                    }
                ],
                "scan_metadata": {
                    "scopes": {
                        "ios": {
                            "status": "success",
                            "configured_rule_ids": [
                                *sorted(weak_rule_ids),
                                *sorted(COMPLETE_FILE_PROTECTION_RULE_IDS),
                            ],
                        }
                    }
                },
            },
        }
    )

    evidence = FlutterDataStorageEvidence(context)

    assert evidence.weak_file_protection.present is False
    assert "SecureStorage.swift" not in str(evidence.weak_file_protection)


def test_missing_storage_inputs_remain_unassessed() -> None:
    evidence = FlutterDataStorageEvidence(FlutterScanExtractionContext({}))

    assert evidence.assessed is False
    assert all(entry.present is None for name, entry in vars(evidence).items() if name != "assessed")


def _sensitive_values_context(*, ios_rule_configured: bool) -> FlutterScanExtractionContext:
    ios_rules = ["ios.storage.sensitive-value-insecure-storage"] if ios_rule_configured else []
    return FlutterScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"ios": True},
                "ios": {"available": True, "metadata": {}},
            },
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "flutter": {
                            "status": "success",
                            "configured_rule_ids": [
                                "flutter.source.sensitive-hive-storage",
                                "flutter.source.sensitive-shared-preferences",
                            ],
                        },
                        "ios": {"status": "success", "configured_rule_ids": ios_rules},
                    }
                },
            },
        }
    )


def _android_permissions_context(permissions: object) -> FlutterScanExtractionContext:
    return FlutterScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"android": True},
                "android": {
                    "available": True,
                    "metadata": {"permissions": permissions},
                },
            }
        }
    )
