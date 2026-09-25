"""Framework checks consume the same persisted YAML contract as native checks."""

import json

import pytest

from adapters.output.phoenix_report.builders.flutter import FlutterReportDataBuilder
from adapters.output.phoenix_report.builders.react_native import ReactNativeReportDataBuilder
from application.report_generation_service import ReportGenerationService
from domain.post_scan.rule_assessment import rule_assessments
from tests.rule_fixtures import assessment_payload, rule, scoped_payload


def _build(framework, payload):
    return ReportGenerationService([FlutterReportDataBuilder(), ReactNativeReportDataBuilder()]).build_report_data(
        {
            "target_information": {
                "target_kind": framework + "_source",
                "target_type": "source",
                "platform": framework,
                "stack": framework,
            },
            "rule_assessments": rule_assessments(json.loads(json.dumps(payload))),
        }
    )


@pytest.mark.parametrize("framework", ["flutter", "react_native"])
def test_arbitrary_rule_ids_categories_and_metadata_need_no_python_registration(framework):
    definition = rule("example.custom", title="Customer supplied title", severity="MEDIUM")
    payload = scoped_payload(
        **{
            framework: assessment_payload(
                definition,
                category="new_category",
                results=[{"check_id": "example.custom", "path": "source.file", "start": {"line": 7}}],
            )
        }
    )
    report = _build(framework, payload)
    check = report.vulnerability_sections[0].checks[0]
    assert report.vulnerability_sections[0].name == "New Category"
    assert check.name == "Customer supplied title"
    assert check.severity.value == "medium"
    assert check.evidence == "source.file:7"
    assert check.remediation == definition["metadata"]["remediation"]["guidance"]
    assert check.compliance == "EXAMPLE STANDARD: A1"
    assert report.findings_severity.medium == 1


@pytest.mark.parametrize("framework", ["flutter", "react_native"])
def test_scoped_snapshots_preserve_positives_and_unknowns(framework):
    payload = scoped_payload(
        **{
            framework: assessment_payload(rule("example.shared"), category="crypto"),
            "android": assessment_payload(
                rule("example.shared"), category="crypto", results=[{"check_id": "example.shared"}]
            ),
            "ios": assessment_payload(rule("example.shared"), category="crypto", status="failed"),
        }
    )
    report = _build(framework, payload)
    assert {r.area: r.risk_level.value for r in report.risk_summary} == {
        "Crypto": "low",
        "Android / Crypto": "high",
        "iOS / Crypto": "not_evaluated",
    }
    assert [s.name for s in report.vulnerability_sections] == ["Android / Crypto"]
    assert report.findings_severity.high == 1
    assert report.rule_status == "failed"


@pytest.mark.parametrize("framework", ["flutter", "react_native"])
def test_reviews_and_observations_do_not_inflate_vulnerability_counts(framework):
    payload = scoped_payload(
        **{
            framework: assessment_payload(
                rule("example.review", finding_type="review"),
                rule("example.control", finding_type="control"),
                category="crypto",
                results=[{"check_id": "example.review"}, {"check_id": "example.control"}],
            )
        }
    )
    report = _build(framework, payload)
    assert len(report.vulnerability_sections[0].checks) == 2
    assert report.findings_severity.high == 0
    assert report.risk_summary[0].risk_level.value == "not_evaluated"


@pytest.mark.parametrize("framework", ["flutter", "react_native"])
def test_unconfigured_categories_and_legacy_evidence_do_not_create_checks(framework):
    report = _build(framework, scoped_payload(**{framework: assessment_payload(rule(), category="crypto")}))
    assert report.vulnerability_sections == ()
    assert [r.area for r in report.risk_summary] == ["Crypto"]
