"""Tests for normalized Flutter post-scan artifact access."""

from __future__ import annotations

from pathlib import Path

from domain.post_scan.flutter import FlutterScanExtractionContext


def test_exposes_flutter_and_embedded_platform_metadata() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_output_path": "/results/SAST_flutter_source_2026-08-30_12-34-56",
            "scan_metadata": {
                "project_path": "/workspace/example",
                "stack": "FLUTTER",
                "target_type": "SOURCE",
            },
            "source_metadata": {
                "extraction": {"status": "partial", "warnings": ["first", "first", "second"]},
                "project": {"project_path": "/metadata/fallback"},
                "identity": {"package_name": "example_app", "version": "1.2.3+42"},
                "sdk": {"dart_constraint": ">=3.3.0", "flutter_constraint": ">=3.22.0"},
                "platforms": {"android": True, "ios": True, "web": False, "invalid": "yes"},
                "dependencies": {
                    "direct": [{"name": "http", "constraint": "^1.2.0"}, "invalid"],
                    "development": [{"name": "test"}],
                    "resolved": [{"name": "http", "version": "1.2.0"}],
                },
                "android": {
                    "available": True,
                    "metadata": {
                        "identity": {"package_name": "com.example.android"},
                        "application": {"debuggable": False},
                        "permissions": [{"name": "android.permission.CAMERA"}],
                        "components": {
                            "activities": [{"name": "com.example.MainActivity"}],
                            "services": [],
                        },
                        "deep_links": [{"scheme": "example"}],
                    },
                },
                "ios": {
                    "available": True,
                    "metadata": {
                        "identity": {"bundle_identifier": "com.example.ios"},
                        "permissions": [{"key": "NSCameraUsageDescription", "purpose": "Take photos"}],
                        "app_transport_security": {"allows_arbitrary_loads": False},
                        "url_schemes": {"declared_schemes": ["example"]},
                        "background_modes": ["fetch", "fetch"],
                        "entitlements": [{"path": "Runner.entitlements", "metadata": {}}],
                        "privacy_manifests": [{"path": "PrivacyInfo.xcprivacy", "metadata": {}}],
                    },
                },
            },
        }
    )

    assert context.project_path == Path("/workspace/example")
    assert context.identity == {"package_name": "example_app", "version": "1.2.3+42"}
    assert context.sdk == {"dart_constraint": ">=3.3.0", "flutter_constraint": ">=3.22.0"}
    assert context.platforms == {"android": True, "ios": True, "web": False}
    assert context.dependencies == {
        "direct": [{"name": "http", "constraint": "^1.2.0"}],
        "development": [{"name": "test"}],
        "resolved": [{"name": "http", "version": "1.2.0"}],
    }
    assert context.warnings == ["first", "second"]
    assert context.source_metadata_assessed is True
    assert context.android_available is True
    assert context.android_identity == {"package_name": "com.example.android"}
    assert context.android_application == {"debuggable": False}
    assert context.android_permissions == [{"name": "android.permission.CAMERA"}]
    assert context.android_components == {
        "activities": [{"name": "com.example.MainActivity"}],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    assert context.android_deep_links == [{"scheme": "example"}]
    assert context.ios_available is True
    assert context.ios_identity == {"bundle_identifier": "com.example.ios"}
    assert context.ios_permissions == [{"key": "NSCameraUsageDescription", "purpose": "Take photos"}]
    assert context.ios_app_transport_security == {"allows_arbitrary_loads": False}
    assert context.ios_url_schemes == {"declared_schemes": ["example"]}
    assert context.ios_background_modes == ["fetch"]
    assert context.ios_entitlements == [{"path": "Runner.entitlements", "metadata": {}}]
    assert context.ios_privacy_manifests == [{"path": "PrivacyInfo.xcprivacy", "metadata": {}}]
    assert context.scan_date == "2026-08-30 12:34:56"


def test_exposes_plist_documents_by_index_role() -> None:
    context = FlutterScanExtractionContext(
        {
            "plist_outputs": {
                "Runner/Info.json": {"app_meta": {"bundle_identifier": "com.example"}},
                "Runner/Runner.entitlements.json": {"entitlements": {"aps_environment": "development"}},
                "Runner/PrivacyInfo.xcprivacy.json": {"privacy_manifest": {"tracking": False}},
                "Malformed.json": None,
            },
            "plist_index": {
                "plists": [
                    {"output_path": "Runner/Info.json", "role": "app"},
                    {"output_path": "Runner/Runner.entitlements.json", "role": "entitlements"},
                    {"output_path": "Runner/PrivacyInfo.xcprivacy.json", "role": "privacy_manifest"},
                    "invalid",
                ]
            },
        }
    )

    assert set(context.plist_outputs) == {
        "Runner/Info.json",
        "Runner/Runner.entitlements.json",
        "Runner/PrivacyInfo.xcprivacy.json",
    }
    assert context.plist_outputs_for_role("app") == {
        "Runner/Info.json": {"app_meta": {"bundle_identifier": "com.example"}}
    }
    assert context.plist_outputs_for_role("entitlements") == {
        "Runner/Runner.entitlements.json": {"entitlements": {"aps_environment": "development"}}
    }
    assert context.plist_assessed is True


def test_filters_opengrep_findings_and_inventory_by_scope() -> None:
    context = FlutterScanExtractionContext(
        {
            "opengrep": {
                "success": True,
                "results": [
                    {"check_id": "flutter.source.sql-injection", "phoenix_scope": "flutter"},
                    {"check_id": "android.source.sha1", "phoenix_scope": "android"},
                    {"check_id": "ios-weak-crypto-md5", "phoenix_scope": "ios"},
                    {"check_id": "flutter.source.weak-hash"},
                    "invalid",
                ],
                "scan_metadata": {
                    "scopes": {
                        "flutter": {
                            "status": "success",
                            "configured_rule_ids": [
                                "flutter.source.sql-injection",
                                "flutter.source.weak-hash",
                                "flutter.source.weak-hash",
                            ],
                        },
                        "android": {"status": "failed", "configured_rule_ids": []},
                        "ios": {"status": "skipped"},
                        "invalid": "scope",
                    }
                },
            }
        }
    )

    assert context.opengrep_scope_completed("flutter") is True
    assert context.opengrep_scope_assessed("flutter") is True
    assert context.opengrep_scope_completed("android") is False
    assert context.opengrep_scope_assessed("android") is False
    assert context.opengrep_scope_completed("ios") is False
    assert context.opengrep_configured_rule_ids("flutter") == frozenset(
        {"flutter.source.sql-injection", "flutter.source.weak-hash"}
    )
    assert [item["check_id"] for item in context.opengrep_results_for_scope("flutter")] == [
        "flutter.source.sql-injection",
        "flutter.source.weak-hash",
    ]
    assert [item["check_id"] for item in context.opengrep_results_for_scope("android")] == ["android.source.sha1"]
    assert [item["check_id"] for item in context.opengrep_results_for_scope("ios")] == ["ios-weak-crypto-md5"]


def test_exposes_secret_findings_and_deduplicated_syft_packages() -> None:
    context = FlutterScanExtractionContext(
        {
            "gitleaks_outputs": {"gitleaks_report.json": [{"RuleID": "generic-api-key"}, "invalid"]},
            "trufflehog_outputs": {"trufflehog_results.json": {"findings": [{"DetectorName": "AWS"}]}},
            "syft_outputs": {
                "sbom.json": {
                    "artifacts": [
                        {"name": "http", "version": "1.2.0"},
                        {"name": "http", "version": "1.2.0"},
                    ],
                    "components": [{"name": "flutter", "version": "3.22.0"}],
                }
            },
        }
    )

    assert context.gitleaks_assessed is True
    assert context.trufflehog_assessed is False
    assert context.gitleaks_findings == [{"RuleID": "generic-api-key"}]
    assert context.trufflehog_findings == [{"DetectorName": "AWS"}]
    assert context.syft_packages == [
        ("sbom.json", "flutter", "3.22.0"),
        ("sbom.json", "http", "1.2.0"),
    ]
    assert context.syft_assessed is True


def test_missing_or_malformed_outputs_remain_unassessed() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": None,
            "source_metadata": None,
            "opengrep": None,
            "plist_outputs": {"Malformed.json": None},
            "gitleaks_outputs": {"gitleaks_report.json": None},
            "trufflehog_outputs": {},
            "syft_outputs": {"sbom.json": None},
        }
    )

    assert context.identity == {}
    assert context.source_metadata_assessed is False
    assert context.dependencies == {"direct": [], "development": [], "resolved": []}
    assert context.android_available is False
    assert context.ios_available is False
    assert context.plist_outputs == {}
    assert context.plist_assessed is False
    assert context.opengrep_results == []
    assert context.opengrep_scope_completed("flutter") is False
    assert context.opengrep_scope_assessed("flutter") is False
    assert context.opengrep_configured_rule_ids("flutter") == frozenset()
    assert context.gitleaks_assessed is False
    assert context.trufflehog_assessed is False
    assert context.gitleaks_findings == []
    assert context.trufflehog_findings == []
    assert context.syft_packages == []
    assert context.syft_assessed is False
    assert context.scan_date == ""
