"""Tests for Flutter code evidence across Dart and embedded platforms."""

from __future__ import annotations

from domain.post_scan.flutter import FlutterCodeEvidence, FlutterScanExtractionContext


def test_combines_flutter_android_and_ios_code_findings_by_evidence_key() -> None:
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
                        "check_id": "flutter.source.sql-injection",
                        "phoenix_scope": "flutter",
                        "path": "/workspace/app/lib/database.dart",
                        "start": {"line": 14},
                    },
                    {
                        "check_id": "android.source.sensitive-log",
                        "phoenix_scope": "android",
                        "path": "/workspace/app/android/app/Logger.kt",
                        "start": {"line": 9},
                    },
                    {
                        "check_id": "ios-weak-crypto-md5",
                        "phoenix_scope": "ios",
                        "path": "/workspace/app/ios/Runner/Crypto.swift",
                        "start": {"line": 22},
                    },
                ],
                "scan_metadata": {"scopes": {}},
            },
        }
    )

    evidence = FlutterCodeEvidence(context)

    assert evidence.assessed is True
    assert evidence.contains_potential_sql_injection.present is True
    assert evidence.contains_potential_sql_injection.details == ["lib/database.dart:14"]
    assert evidence.writes_sensitive_information_to_system_log.present is True
    assert evidence.writes_sensitive_information_to_system_log.details == ["android/app/Logger.kt:9"]
    assert evidence.encodes_data_using_insecure_cryptography.present is True
    assert evidence.encodes_data_using_insecure_cryptography.details == ["ios/Runner/Crypto.swift:22"]


def test_shared_rule_is_clean_only_when_every_applicable_scope_was_assessed() -> None:
    complete = FlutterCodeEvidence(_logging_context(android_rule_configured=True))
    incomplete = FlutterCodeEvidence(_logging_context(android_rule_configured=False))

    assert complete.writes_sensitive_information_to_system_log.present is False
    assert complete.writes_sensitive_information_to_system_log.evidence == (
        "no_writes_sensitive_information_to_system_log_hits"
    )
    assert incomplete.writes_sensitive_information_to_system_log.present is None


def test_builds_android_manifest_code_evidence_without_overstating_unknowns() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"android": True},
                "android": {
                    "available": True,
                    "metadata": {
                        "application": {"debuggable": False, "allow_backup": True},
                        "components": {
                            "activities": [
                                {"name": "com.example.MainActivity", "exported": True},
                                {"name": "com.example.InternalActivity", "exported": False},
                            ],
                            "services": [],
                            "receivers": [{"name": "com.example.UnknownReceiver"}],
                        },
                        "deep_links": [{"scheme": "example", "host": "open"}],
                    },
                },
            }
        }
    )

    evidence = FlutterCodeEvidence(context)

    assert evidence.app_is_debuggable.present is False
    assert evidence.application_data_can_be_backed_up.present is True
    assert evidence.activities_accessible_to_other_apps.details == ["com.example.MainActivity"]
    assert evidence.services_accessible_to_other_apps.present is False
    assert evidence.receivers_accessible_to_other_apps.present is None
    assert evidence.application_uses_custom_url_schemes_or_deep_links.details == ["example://open"]


def test_builds_redacted_secret_sbom_and_entitlement_code_evidence() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/app"},
            "source_metadata": {
                "platforms": {"ios": True},
                "ios": {"available": True, "metadata": {}},
            },
            "gitleaks_outputs": {
                "gitleaks_report.json": [
                    {
                        "Description": "Generic API key",
                        "File": "/workspace/app/lib/config.dart",
                        "StartLine": 4,
                        "Secret": "must-not-appear",  # pragma: allowlist secret
                    },
                    {
                        "Description": "Database password",
                        "File": "/workspace/app/lib/database.dart",
                        "StartLine": 8,
                        "Secret": "also-must-not-appear",  # pragma: allowlist secret
                    },
                ]
            },
            "syft_outputs": {"sbom.json": {"artifacts": [{"name": "nanopb", "version": "1.0.0"}]}},
            "plist_index": {"plists": [{"role": "entitlements", "output_path": "Runner/Runner.entitlements.json"}]},
            "plist_outputs": {
                "Runner/Runner.entitlements.json": {
                    "plist": {
                        "get-task-allow": True,
                        "com.apple.private.security.no-container": True,
                    }
                }
            },
        }
    )

    evidence = FlutterCodeEvidence(context)

    assert evidence.contains_hard_coded_cryptographic_key.details == ["lib/config.dart:4"]
    assert evidence.contains_potential_hard_coded_password.details == ["lib/database.dart:8"]
    assert evidence.hardcoded_api_keys_in_bundle.details == ["lib/config.dart:4"]
    assert evidence.insecure_nanopb_library.present is True
    assert evidence.insecure_nanopb_library.details == ["sbom.json: nanopb@1.0.0"]
    assert evidence.insecure_entitlements.present is True
    assert evidence.insecure_entitlements.details == [
        "com.apple.private.security.no-container",
        "get-task-allow",
    ]
    assert "must-not-appear" not in str(evidence)


def test_missing_code_inputs_remain_unassessed() -> None:
    evidence = FlutterCodeEvidence(FlutterScanExtractionContext({}))

    assert evidence.assessed is False
    assert all(entry.present is None for name, entry in vars(evidence).items() if name != "assessed")


def _logging_context(*, android_rule_configured: bool) -> FlutterScanExtractionContext:
    android_rules = ["android.source.sensitive-log"] if android_rule_configured else []
    return FlutterScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"android": True},
                "android": {"available": True, "metadata": None},
            },
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "flutter": {
                            "status": "success",
                            "configured_rule_ids": ["flutter.source.sensitive-log"],
                        },
                        "android": {
                            "status": "success",
                            "configured_rule_ids": android_rules,
                        },
                    }
                },
            },
        }
    )
