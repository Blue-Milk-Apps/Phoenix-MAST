"""Tests for Flutter network evidence across Dart and embedded platforms."""

from __future__ import annotations

from domain.post_scan.flutter import FlutterNetworkEvidence, FlutterScanExtractionContext


def test_combines_flutter_android_and_ios_network_findings() -> None:
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
                        "check_id": "flutter.source.cleartext-http",
                        "phoenix_scope": "flutter",
                        "path": "/workspace/app/lib/client.dart",
                        "start": {"line": 10},
                    },
                    {
                        "check_id": "android.source.listening-socket",
                        "phoenix_scope": "android",
                        "path": "/workspace/app/android/app/Server.kt",
                        "start": {"line": 18},
                    },
                    {
                        "check_id": "ios.network.cookie-missing-secure-flag",
                        "phoenix_scope": "ios",
                        "path": "/workspace/app/ios/Runner/Cookies.swift",
                        "start": {"line": 24},
                    },
                ],
                "scan_metadata": {"scopes": {}},
            },
        }
    )

    evidence = FlutterNetworkEvidence(context)

    assert evidence.assessed is True
    assert evidence.sensitive_information_unencrypted_in_transit.details == ["lib/client.dart:10"]
    assert evidence.opens_listening_port.details == ["android/app/Server.kt:18"]
    assert evidence.cookie_missing_secure_flag.details == ["ios/Runner/Cookies.swift:24"]


def test_shared_cleartext_result_requires_every_applicable_scope() -> None:
    complete = FlutterNetworkEvidence(_cleartext_context(android_rule_configured=True))
    incomplete = FlutterNetworkEvidence(_cleartext_context(android_rule_configured=False))

    assert complete.sensitive_information_unencrypted_in_transit.present is False
    assert incomplete.sensitive_information_unencrypted_in_transit.present is None


def test_aggregates_flutter_and_android_certificate_validation_rules() -> None:
    complete = FlutterNetworkEvidence(_certificate_context(android_trust_rule_configured=True))
    incomplete = FlutterNetworkEvidence(_certificate_context(android_trust_rule_configured=False))

    assert complete.contains_hostname_verifier_accepts_all.present is False
    assert complete.contains_x509_trust_manager_accepts_all.present is False
    assert complete.weak_certificate_validation_enables_mitm.present is False
    assert incomplete.weak_certificate_validation_enables_mitm.present is None


def test_builds_android_cleartext_and_ios_ats_metadata_evidence() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"android": True, "ios": True},
                "android": {
                    "available": True,
                    "metadata": {"application": {"uses_cleartext_traffic": True}},
                },
                "ios": {
                    "available": True,
                    "metadata": {
                        "app_transport_security": {
                            "allows_arbitrary_loads": True,
                            "allows_arbitrary_loads_for_media": False,
                            "allows_arbitrary_loads_in_web_content": True,
                            "exception_domains": [
                                {
                                    "domain": "legacy.example.com",
                                    "allows_insecure_http_loads": True,
                                    "minimum_tls_version": "TLSv1.1",
                                    "requires_forward_secrecy": False,
                                }
                            ],
                        }
                    },
                },
            }
        }
    )

    evidence = FlutterNetworkEvidence(context)

    assert evidence.allows_cleartext_traffic_for_all_domains.present is True
    assert evidence.ats_disabled.present is True
    assert evidence.ats_disabled.details == ["NSAllowsArbitraryLoads"]
    assert evidence.ats_exceptions_configured.present is True
    assert evidence.ats_exceptions_configured.details == [
        "NSAllowsArbitraryLoadsInWebContent=true",
        "legacy.example.com: allows_insecure_http_loads=true",
        "legacy.example.com: minimum_tls_version=TLSv1.1",
        "legacy.example.com: requires_forward_secrecy=false",
    ]


def test_safe_ats_metadata_still_requires_registered_ios_rules_for_clean_result() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"ios": True},
                "ios": {"available": True, "metadata": {"app_transport_security": {}}},
            },
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "ios": {
                            "status": "success",
                            "configured_rule_ids": ["ats-disabled-usage", "ats-exceptions-usage"],
                        }
                    }
                },
            },
        }
    )

    evidence = FlutterNetworkEvidence(context)

    assert evidence.ats_disabled.present is False
    assert evidence.ats_exceptions_configured.present is False


def test_missing_network_inputs_remain_unassessed() -> None:
    evidence = FlutterNetworkEvidence(FlutterScanExtractionContext({}))

    assert evidence.assessed is False
    assert all(entry.present is None for name, entry in vars(evidence).items() if name != "assessed")


def _cleartext_context(*, android_rule_configured: bool) -> FlutterScanExtractionContext:
    android_rules = ["android.source.cleartext-http"] if android_rule_configured else []
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
                            "configured_rule_ids": ["flutter.source.cleartext-http"],
                        },
                        "android": {"status": "success", "configured_rule_ids": android_rules},
                    }
                },
            },
        }
    )


def _certificate_context(*, android_trust_rule_configured: bool) -> FlutterScanExtractionContext:
    android_rules = ["android.source.accept-all-hostname-verifier"]
    if android_trust_rule_configured:
        android_rules.append("android.source.accept-all-trust-manager")
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
                            "configured_rule_ids": [
                                "flutter.source.bad-certificate-callback",
                                "flutter.source.webview-ssl-bypass",
                            ],
                        },
                        "android": {"status": "success", "configured_rule_ids": android_rules},
                    }
                },
            },
        }
    )
