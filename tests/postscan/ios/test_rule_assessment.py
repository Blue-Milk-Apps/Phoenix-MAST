import json

import pytest

from adapters.output.phoenix_report.builders.ios import NativeIOSReportDataBuilder
from adapters.output.phoenix_report.pdf_report.pdf_report_generator import PdfReportGenerator
from application.report_generation_service import ReportGenerationService
from domain.post_scan.rule_assessment import rule_assessments
from domain.report.models import AssessmentStatus
from tests.rule_fixtures import assessment_payload, rule


def build(output, **additional_data):
    data = {
        "target_information": {
            "target_kind": "native_ios_source",
            "target_type": "source",
            "platform": "ios",
            "stack": "native_ios",
        },
        "rule_assessments": rule_assessments(output),
        **additional_data,
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
    assert section.name == "Custom"
    assert check.name == "Title from YAML"
    assert check.rule_id == "brand-new-id"
    assert check.result == AssessmentStatus.PRESENT
    assert check.scope == "matched_code"
    assert check.remediation == "Remove the example marker."
    assert check.compliance == "EXAMPLE STANDARD: A1"
    assert "Example.swift:5" in check.evidence
    assert report.findings_severity.high == 1


@pytest.mark.parametrize("finding_type", ["review", "control", "observation"])
def test_nonweakness_matches_never_increase_vulnerability_counts(finding_type):
    report = build(assessment_payload(rule(finding_type=finding_type), results=[{"check_id": "example.check"}]))
    assert report.vulnerability_sections[-1].checks[0].finding_type == finding_type
    assert report.findings_severity.high == 0
    assert report.overall_evaluation[-1].risk_level.value == "not_evaluated"


def test_snapshot_is_sufficient_for_later_report_generation():
    output = json.loads(
        json.dumps(assessment_payload(rule(title="Saved title"), results=[{"check_id": "example.check"}]))
    )
    report = build(output)
    assert report.vulnerability_sections[-1].checks[0].name == "Saved title"
    assert report.vulnerability_sections[-1].checks[0].result == AssessmentStatus.PRESENT


def test_failed_rules_and_partial_matches_remain_distinct():
    output = assessment_payload(
        rule("example.match"), rule("example.unknown"), status="failed", results=[{"check_id": "example.match"}]
    )
    checks = build(output).vulnerability_sections[-1].checks
    assert checks[0].result == AssessmentStatus.PRESENT
    assert "incomplete scan" in checks[0].explanation
    assert len(checks) == 1
    assert build(output).rule_status == "failed"


def test_scoped_catalog_preserves_ios_platform_and_outcomes():
    output = assessment_payload(rule(), results=[{"check_id": "example.check", "phoenix_scope": "ios"}])
    ios = output["scan_metadata"]
    output["scan_metadata"] = {"status": "partial", "scopes": {"ios": ios, "flutter": {"status": "failed"}}}
    item = rule_assessments(output)["rules"][0]
    assert item["platform"] == "ios"
    assert item["status"] == "present"


def test_pdf_projection_keeps_metadata_and_dynamic_categories():
    report = build(
        assessment_payload(rule(finding_type="review"), results=[{"check_id": "example.check"}]),
        functionality={"Camera": {"present": False, "explanation": "No camera capability recorded."}},
    )
    data = PdfReportGenerator._merged_presentation_data(report)
    check = data["vulnerability_sections"][-1]["checks"][0]
    assert check["finding_type"] == "review"
    assert check["scope"] == "matched_code"
    assert "Custom" in data["risk_summary"]
    assert data["rule_status"] == "success"

    from dataclasses import asdict
    from pathlib import Path

    from jinja2 import Environment, FileSystemLoader

    from adapters.output.phoenix_report.common import assessment_badge, result_badge, risk_badge
    from adapters.output.phoenix_report.pdf_report.presentation import PdfPresentation

    templates = Path(__file__).resolve().parents[3] / "adapters/output/phoenix_report/templates"
    environment = Environment(loader=FileSystemLoader(str(templates)))
    environment.globals.update(assessment_badge=assessment_badge, result_badge=result_badge, risk_badge=risk_badge)
    html = environment.get_template("report.html.jinja").render(
        data=data, charts={}, presentation=asdict(PdfPresentation.for_target_kind(report.metadata.target.target_kind))
    )
    table = html.split('<table class="findings-table">')[1].split("</table>")[0]
    assert all(
        f">{column}</th>" in table
        for column in ("Check", "Severity", "Finding Type", "Explanation", "Compliance", "Evidence")
    )
    assert table.index(">Severity</th>") < table.index(">Finding Type</th>") < table.index(">Explanation</th>")
    assert ">Result</th>" not in table
    assert "Example check" in table
    assert 'class="rule-check"' not in html
    assert "No camera capability recorded." in html
    assert "Application Functionality" in html
    assert "Custom URL Schemes" in html
    assert "Hard-Coded Values Found" not in html
    assert "Hardcoded Secrets" in html
    assert "Secret-scanner results were not included" in html
    assert "Rule Coverage" not in html
    assert 'class="section checks-section"' in html
    assert "Endpoint Connections" in html


def test_only_hits_are_merged_into_one_table_per_category():
    output = assessment_payload(rule(), rule("example.no-match"), results=[{"check_id": "example.check"}])
    for definition in output["scan_metadata"]["rule_catalog"]:
        definition["category"] = "code"
    report = build(
        output,
        code_evidence={
            "hardcoded_api_keys_in_bundle": {"present": True, "evidence": "secrets.json"},
            "insecure_nanopb_library": {"present": False},
        },
    )
    assert [section.name for section in report.vulnerability_sections] == ["Code"]
    assert [check.name for check in report.vulnerability_sections[0].checks] == [
        "Hardcoded API Keys within the Application Bundle",
        "Example check",
    ]
    assert [evaluation.area for evaluation in report.overall_evaluation] == ["Code"]
    assert report.findings_severity.high == 2


def test_no_hits_omit_check_tables_but_keep_security_categories_in_summary():
    output = assessment_payload(rule())
    report = build(output)
    assert report.vulnerability_sections == ()
    assert report.overall_evaluation[-1].area == "Custom"
    assert report.overall_evaluation[-1].risk_level.value == "low"
    assert report.rule_coverage
    assert report.rule_status == "success"


def test_summary_includes_unmatched_crypto_and_excludes_functionality():
    output = assessment_payload(
        rule("crypto.check"),
        rule("functionality.check", finding_type="observation", severity="INFO"),
        results=[{"check_id": "functionality.check"}],
    )
    for definition in output["scan_metadata"]["rule_catalog"]:
        definition["category"] = definition["rule_id"].split(".")[0]
    report = build(output)
    assert [section.name for section in report.vulnerability_sections] == ["Functionality"]
    assert {row.area: row.risk_level.value for row in report.overall_evaluation} == {
        "Code": "not_evaluated",
        "Crypto": "low",
    }
    assert {row.area for row in report.risk_summary} == {"Code", "Crypto"}
