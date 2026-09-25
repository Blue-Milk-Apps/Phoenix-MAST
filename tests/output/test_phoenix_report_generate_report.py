from adapters.output.phoenix_report.builders.android import NativeAndroidReportDataBuilder
from adapters.output.phoenix_report.pdf_report import PdfReportGenerator
from adapters.output.phoenix_report.pdf_report.common import build_charts
from application.report_generation_service import ReportGenerationService
from domain.post_scan.rule_assessment import rule_assessments
from tests.rule_fixtures import assessment_payload, rule


def _android_source_report(data: dict) -> object:
    payload = {
        "target_information": {
            "target_kind": "native_android_source",
            "platform": "android",
            "target_type": "source",
            "stack": "native_android",
        },
        **data,
    }
    return ReportGenerationService([NativeAndroidReportDataBuilder()]).build_report_data(payload)


def test_modular_report_data_contains_canonical_android_sections() -> None:
    report = _android_source_report(
        {
            "app_info": {"package_name": "com.example", "target_sdk": "35"},
            "application": {"allow_backup": True},
            "app_components": {"activities": 1, "exported_activities": 1},
            "rule_assessments": rule_assessments(
                assessment_payload(
                    rule("example.exported", title="Exported component", finding_type="review"),
                    platform="android",
                    category="code",
                    results=[{"check_id": "example.exported", "path": "AndroidManifest.xml"}],
                )
            ),
            "functionality": {"Camera": {"present": None}},
        }
    )

    code = next(section for section in report.vulnerability_sections if section.name == "Code")
    activities = next(check for check in code.checks if check.name == "Exported component")
    assert activities.result.value == "present"
    assert activities.severity.value == "high"
    assert activities.compliance
    assert activities.finding_type == "review"
    assert report.findings_severity.high == 0
    assert [section.name for section in report.vulnerability_sections] == ["Code"]
    assert report.platform_details.app_components.exported_activities == 1


def test_pdf_presentation_maps_android_details_and_charts() -> None:
    report = _android_source_report(
        {
            "app_info": {"package_name": "com.example", "version_name": "1.0"},
            "application": {"debuggable": False},
            "app_components": {"activities": 2, "exported_activities": 1},
            "functionality": {"Camera": {"present": True, "explanation": "Camera detected."}},
            "permissions": [{"name": "android.permission.CAMERA", "general_description": "Camera access."}],
        }
    )

    presentation = PdfReportGenerator._presentation_data(report)
    assert presentation["application"]["debuggable"] is False
    assert presentation["app_components"]["activities"] == 2
    assert presentation["functionality"]["Camera"]["present"] is True
    assert presentation["permissions"][0]["general_description"] == "Camera access."
    assert build_charts(presentation)["overall_risk_polar"]
