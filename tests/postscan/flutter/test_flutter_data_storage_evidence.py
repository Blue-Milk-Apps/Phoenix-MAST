"""Tests for Flutter data-storage evidence across Dart and embedded platforms."""

from __future__ import annotations

from domain.post_scan.flutter import FlutterDataStorageEvidence, FlutterScanExtractionContext


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
    assert not hasattr(evidence, "deprecated_keychain_attributes")


def test_flutter_storage_result_is_independent_of_ios_rule_coverage() -> None:
    complete = FlutterDataStorageEvidence(_sensitive_values_context(ios_rule_configured=True))
    incomplete = FlutterDataStorageEvidence(_sensitive_values_context(ios_rule_configured=False))

    assert complete.sensitive_values_stored_insecurely.present is False
    assert incomplete.sensitive_values_stored_insecurely.present is False


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
