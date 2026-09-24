import json

import pytest

from adapters.output.phoenix_report.builders.ios import NativeIOSReportDataBuilder
from adapters.output.phoenix_report.pdf_report.pdf_report_generator import PdfReportGenerator
from application.report_generation_service import ReportGenerationService
from domain.post_scan.rule_assessment import rule_assessments
from domain.report.models import AssessmentStatus
from tests.rule_fixtures import assessment_payload, rule


def build(output):
    data = {
        "target_information": {
            "target_kind": "native_ios_source",
            "target_type": "source",
            "platform": "ios",
            "stack": "native_ios",
        },
        "rule_assessments": rule_assessments(output),
    }
    return ReportGenerationService([NativeIOSReportDataBuilder()]).build_report_data(data)


def test_new_id_and_custom_category_need_no_python_registration():
    report = build(
        assessment_payload(
            rule("brand-new-id", title="Title from YAML"),
            results=[{"check_id": "brand-new-id", "path": "Example.swift", "start": {"line": 5}}],
        )
    )
    section = report.vulnerability_sections[-1]
    check = section.checks[0]
    assert section.name == "iOS / Custom"
    assert check.name == "Title from YAML"
    assert check.rule_id == "brand-new-id"
    assert check.result == AssessmentStatus.PRESENT
    assert check.scope == "matched_code"
    assert check.remediation == "Remove the example marker."
    assert "A1 (review_context)" in check.compliance
    assert "Example.swift:5" in check.evidence
    assert report.findings_severity.high == 1


@pytest.mark.parametrize("finding_type", ["review", "control", "observation"])
def test_nonweakness_matches_never_increase_vulnerability_counts(finding_type):
    report = build(assessment_payload(rule(finding_type=finding_type), results=[{"check_id": "example.check"}]))
    assert report.vulnerability_sections[-1].checks[0].finding_type == finding_type
    assert report.findings_severity.high == 0
    assert report.overall_evaluation[-1].risk_level.value == "not_evaluated"


def test_snapshot_is_sufficient_for_later_report_generation():
    output = json.loads(json.dumps(assessment_payload(rule(title="Saved title"))))
    report = build(output)
    assert report.vulnerability_sections[-1].checks[0].name == "Saved title"
    assert report.vulnerability_sections[-1].checks[0].result == AssessmentStatus.NOT_PRESENT
    assert "No matches" in report.vulnerability_sections[-1].checks[0].explanation


def test_failed_rules_and_partial_matches_remain_distinct():
    output = assessment_payload(
        rule("example.match"), rule("example.unknown"), status="failed", results=[{"check_id": "example.match"}]
    )
    checks = build(output).vulnerability_sections[-1].checks
    assert checks[0].result == AssessmentStatus.PRESENT
    assert "incomplete scan" in checks[0].explanation
    assert checks[1].result == AssessmentStatus.NOT_EVALUATED


def test_scoped_catalog_preserves_ios_platform_and_outcomes():
    output = assessment_payload(rule(), results=[{"check_id": "example.check", "phoenix_scope": "ios"}])
    ios = output["scan_metadata"]
    output["scan_metadata"] = {"status": "partial", "scopes": {"ios": ios, "flutter": {"status": "failed"}}}
    item = rule_assessments(output)["rules"][0]
    assert item["platform"] == "ios"
    assert item["status"] == "present"


def test_pdf_projection_keeps_metadata_and_dynamic_categories():
    report = build(assessment_payload(rule(finding_type="review"), results=[{"check_id": "example.check"}]))
    data = PdfReportGenerator._merged_presentation_data(report)
    check = data["vulnerability_sections"][-1]["checks"][0]
    assert check["finding_type"] == "review"
    assert check["scope"] == "matched_code"
    assert "iOS / Custom" in data["risk_summary"]
    assert data["rule_status"] == "success"
