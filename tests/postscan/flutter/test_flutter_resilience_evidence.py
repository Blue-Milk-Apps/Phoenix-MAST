"""Tests for Flutter resilience evidence assessment."""

from __future__ import annotations

from domain.post_scan.flutter import FlutterResilienceEvidence, FlutterScanExtractionContext


def test_reports_android_biometric_bypass_finding() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/app"},
            "source_metadata": {
                "platforms": {"android": True},
                "android": {"available": True, "metadata": {}},
            },
            "opengrep": {
                "results": [
                    {
                        "check_id": "android.source.unsafe-biometric-auth",
                        "phoenix_scope": "android",
                        "path": "/workspace/app/android/app/Auth.kt",
                        "start": {"line": 31},
                        "extra": {"message": "Biometric result is not validated"},
                    }
                ],
                "scan_metadata": {"scopes": {"android": {"status": "failed"}}},
            },
        }
    )

    evidence = FlutterResilienceEvidence(context)

    assert evidence.assessed is True
    assert evidence.biometric_local_authentication_bypass_possible.present is True
    assert evidence.biometric_local_authentication_bypass_possible.details == [
        "android/app/Auth.kt:31: Biometric result is not validated"
    ]


def test_reports_clean_only_when_android_resilience_rule_completed() -> None:
    context = _android_context(
        status="success",
        configured_rule_ids=["android.source.unsafe-biometric-auth"],
    )

    evidence = FlutterResilienceEvidence(context)

    assert evidence.assessed is True
    assert evidence.biometric_local_authentication_bypass_possible.present is False
    assert evidence.biometric_local_authentication_bypass_possible.evidence == (
        "no_biometric_local_authentication_bypass_possible_hits"
    )


def test_missing_android_rule_inventory_remains_unassessed() -> None:
    context = _android_context(status="success", configured_rule_ids=[])

    evidence = FlutterResilienceEvidence(context)

    assert evidence.assessed is False
    assert evidence.biometric_local_authentication_bypass_possible.present is None


def test_flutter_and_ios_scans_do_not_imply_resilience_assessment() -> None:
    context = FlutterScanExtractionContext(
        {
            "source_metadata": {
                "platforms": {"ios": True},
                "ios": {"available": True, "metadata": {}},
            },
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "flutter": {"status": "success", "configured_rule_ids": []},
                        "ios": {"status": "success", "configured_rule_ids": []},
                    }
                },
            },
        }
    )

    evidence = FlutterResilienceEvidence(context)

    assert evidence.assessed is False
    assert evidence.biometric_local_authentication_bypass_possible.present is None


def test_missing_resilience_inputs_remain_unassessed() -> None:
    evidence = FlutterResilienceEvidence(FlutterScanExtractionContext({}))

    assert evidence.assessed is False
    assert evidence.biometric_local_authentication_bypass_possible.present is None


def _android_context(*, status: str, configured_rule_ids: list[str]) -> FlutterScanExtractionContext:
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
                        "android": {
                            "status": status,
                            "configured_rule_ids": configured_rule_ids,
                        }
                    }
                },
            },
        }
    )
