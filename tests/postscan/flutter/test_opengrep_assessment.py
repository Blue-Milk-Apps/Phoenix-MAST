from __future__ import annotations

from domain.post_scan.flutter import FlutterOpenGrepAssessment


def test_positive_finding_is_present_with_relative_evidence() -> None:
    assessment = FlutterOpenGrepAssessment(
        _report(
            configured_rule_ids=["flutter.source.cleartext-http"],
            findings=[
                {
                    "check_id": "flutter.source.cleartext-http",
                    "phoenix_scope": "flutter",
                    "path": "/workspace/example/lib/api.dart",
                    "start": {"line": 12},
                    "extra": {"message": "Cleartext HTTP endpoint."},
                }
            ],
        )
    ).assess_evidence("Network", "sensitive_information_unencrypted_in_transit")

    assert assessment.present is True
    assert assessment.evidence == "lib/api.dart:12: Cleartext HTTP endpoint."
    assert assessment.details == ["lib/api.dart:12: Cleartext HTTP endpoint."]


def test_absent_finding_requires_every_rule_mapped_to_the_evidence() -> None:
    complete = FlutterOpenGrepAssessment(
        _report(
            configured_rule_ids=[
                "flutter.source.bad-certificate-callback",
                "flutter.source.webview-ssl-bypass",
            ]
        )
    ).assess_evidence("Network", "weak_certificate_validation_enables_mitm")
    incomplete = FlutterOpenGrepAssessment(
        _report(configured_rule_ids=["flutter.source.bad-certificate-callback"])
    ).assess_evidence("Network", "weak_certificate_validation_enables_mitm")

    assert complete.present is False
    assert complete.evidence == "no_weak_certificate_validation_enables_mitm_hits"
    assert incomplete.present is None


def test_failed_or_missing_scope_is_not_evaluated() -> None:
    failed = FlutterOpenGrepAssessment(
        _report(
            configured_rule_ids=["flutter.source.sql-injection"],
            scope_status="failed",
        )
    ).assess_evidence("Code", "contains_potential_sql_injection")
    legacy = FlutterOpenGrepAssessment(
        {
            "success": True,
            "results": [],
            "scan_metadata": {"configured_rule_ids": ["flutter.source.sql-injection"]},
        }
    ).assess_evidence("Code", "contains_potential_sql_injection")

    assert failed.present is None
    assert legacy.present is None


def _report(
    *,
    configured_rule_ids: list[str],
    findings: list[dict[str, object]] | None = None,
    scope_status: str = "success",
) -> dict[str, object]:
    return {
        "success": scope_status == "success",
        "results": findings or [],
        "scan_metadata": {
            "project_path": "/workspace/example",
            "scopes": {
                "flutter": {
                    "status": scope_status,
                    "configured_rule_ids": configured_rule_ids,
                }
            },
        },
    }
