import pytest

from adapters.output.phoenix_report.builders.flutter import FlutterReportDataBuilder
from domain.report import (
    AssessmentStatus,
    CheckSeverity,
    ReportMetadata,
    ReportPlatform,
    ReportStack,
    ReportTarget,
    ReportTargetKind,
    ReportTargetType,
    RiskLevel,
)


def _metadata(kind: ReportTargetKind = ReportTargetKind.FLUTTER_SOURCE) -> ReportMetadata:
    return ReportMetadata(
        target=ReportTarget(
            target_kind=kind,
            platform=ReportPlatform.FLUTTER,
            target_type=ReportTargetType.SOURCE,
            stack=ReportStack.FLUTTER,
        ),
        app_display_name="Example",
    )


def test_builds_all_sections_and_preserves_finding_metadata() -> None:
    report = FlutterReportDataBuilder().build(
        {
            "code_evidence": {
                "insecure api": {
                    "present": True,
                    "severity": "high",
                    "evidence": "lib/main.dart:4",
                    "compliance": "MASVS-CODE",
                    "remediation_link": "https://example.test/fix",
                    "explanation": "Unsafe API usage detected.",
                }
            },
            "network_evidence": {"cleartext": {"present": False, "severity": "medium"}},
        },
        _metadata(),
    )

    assert [section.name for section in report.vulnerability_sections] == [
        "Code",
        "Network",
        "Data Storage",
        "Resilience",
    ]
    check = report.vulnerability_sections[0].checks[0]
    assert check.result == AssessmentStatus.PRESENT
    assert check.severity == CheckSeverity.HIGH
    assert check.evidence == "lib/main.dart:4"
    assert check.compliance == "MASVS-CODE"
    assert check.remediation_link == "https://example.test/fix"
    assert report.findings_severity.high == 1
    assert report.risk_summary[0].risk_level == RiskLevel.HIGH
    details = report.platform_details
    assert details.package_name == ""


def test_maps_flutter_metadata_and_dependencies() -> None:
    report = FlutterReportDataBuilder().build(
        {
            "identity": {"package_name": "com.example.app", "version_name": "1.2.3"},
            "sdk": {"dart_constraint": ">=3.3.0", "flutter_constraint": ">=3.22.0"},
            "platforms": {"android": True, "ios": True, "web": False},
            "dependency_inventory": {"declared": [{"name": "http"}], "resolved": [{"name": "path"}]},
        },
        _metadata(),
    )
    details = report.platform_details
    assert details.package_name == "com.example.app"
    assert details.dart_constraint == ">=3.3.0"
    assert details.supported_platforms == ("android", "ios")
    assert tuple(item.name for item in details.dependencies) == ("http", "path")


def test_maps_flutter_inventories() -> None:
    report = FlutterReportDataBuilder().build(
        {
            "functionality": {"Camera": {"present": True, "explanation": "Detected"}},
            "permissions": [{"permission": "camera", "status": "requested"}],
            "hardcoded_values": {
                "urls": [{"url": "https://example.test", "country": "US"}],
                "emails": ["security@example.test"],
                "secrets": [{"value": "secret-value"}],
            },
            "endpoints": [{"endpoint": "https://api.example.test", "country": "US"}],
        },
        _metadata(),
    )
    details = report.platform_details
    assert details.functionality[0].name == "Camera"
    assert details.permissions[0].permission == "camera"
    assert details.hardcoded_values.urls[0].url == "https://example.test"
    assert details.hardcoded_values.secrets[0].value == "secret-value"
    assert details.endpoints[0].endpoint == "https://api.example.test"


def test_partial_evidence_produces_empty_sections_and_not_evaluated_risk() -> None:
    report = FlutterReportDataBuilder().build({}, _metadata())

    assert all(not section.checks for section in report.vulnerability_sections)
    assert all(summary.risk_level == RiskLevel.NOT_EVALUATED for summary in report.risk_summary)


def test_rejects_incompatible_target_kind() -> None:
    with pytest.raises(ValueError, match="flutter_source"):
        FlutterReportDataBuilder().build({}, _metadata(ReportTargetKind.IOS_BINARY))
