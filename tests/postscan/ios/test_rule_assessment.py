import json

import pytest

from adapters.output.phoenix_report.builders.ios import NativeIOSReportDataBuilder
from adapters.output.phoenix_report.pdf_report.pdf_report_generator import PdfReportGenerator
from adapters.post_scan.ios.native.scan_detail_extractor import NativeIOSScanDetailExtractor
from adapters.post_scan.ios.native.scan_output_loader import NativeIOSScanOutputLoader
from application.post_scan_processing_service import PostScanProcessingService
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
        url_schemes=[{"url_name": "Example App", "schemes": ["dontdothis"]}],
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
    scheme_section = html.split('<div class="url-schemes">')[1].split("</div>")[0]
    assert "dontdothis" in scheme_section
    assert "No custom URL schemes" not in scheme_section
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
    report = build(output, functionality={"Camera": {"present": True}})
    assert report.vulnerability_sections == ()
    assert PdfReportGenerator._presentation_data(report)["functionality"]["Camera"]["present"] is True
    assert {row.area: row.risk_level.value for row in report.overall_evaluation} == {
        "Code": "not_evaluated",
        "Crypto": "low",
    }
    assert {row.area for row in report.risk_summary} == {"Code", "Crypto"}


def source_scan_report(tmp_path, artifacts):
    """Exercise persisted scanner artifacts through aggregation and PDF projection."""
    for relative_path, payload in artifacts.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    sections = PostScanProcessingService(NativeIOSScanOutputLoader(), NativeIOSScanDetailExtractor()).process(tmp_path)
    # The workflow persists this snapshot before building the report.
    sections = json.loads(json.dumps(sections))
    report = build(None, **sections)
    return sections, report, PdfReportGenerator._merged_presentation_data(report)


@pytest.fixture
def completed_source_artifacts():
    return {
        "syft/sbom.json": {"artifacts": []},
        "gitleaks/gitleaks_report.json": [],
        "trufflehog/trufflehog_results.json": [],
        "plist_source/App.entitlements.json": {"plist": {"get-task-allow": False}},
        "plist_source/scan_index.json": {
            "parse_failures": 0,
            "plist_count": 1,
            "plists": [
                {
                    "output_path": "App.entitlements.json",
                    "parse_status": "success",
                    "role": "entitlements",
                    "skipped": False,
                }
            ],
        },
    }


@pytest.mark.parametrize(
    "payload",
    [None, {}, {"success": False, "error": "Failed"}, {"skipped": True, "error": "Unavailable"}, "invalid output"],
)
def test_missing_or_failed_source_evidence_cannot_produce_low_risk(tmp_path, payload):
    sections, report, presentation = source_scan_report(
        tmp_path,
        {
            "syft/sbom.json": payload,
            "gitleaks/gitleaks_report.json": payload,
            "trufflehog/trufflehog_results.json": payload,
            "plist_source/App.entitlements.json": payload,
            "plist_source/scan_index.json": payload,
        },
    )
    assert all(item["present"] is None for item in sections["code_evidence"].values())
    assert all(item["not_evaluated_reason"] for item in sections["code_evidence"].values())
    assert report.vulnerability_sections == ()
    assert report.findings_severity.high == report.findings_severity.medium == 0
    assert presentation["risk_summary"]["Code"] == "not_evaluated"
    assert "incomplete" in presentation["overall_evaluation"][0]["summary_findings"][0]


def test_absent_source_artifacts_are_not_evaluated(tmp_path):
    sections, _, presentation = source_scan_report(tmp_path, {})
    assert all(item["present"] is None for item in sections["code_evidence"].values())
    assert presentation["risk_summary"]["Code"] == "not_evaluated"


def test_completed_source_scans_without_hits_remain_distinct(tmp_path, completed_source_artifacts):
    sections, report, presentation = source_scan_report(tmp_path, completed_source_artifacts)
    assert all(item["present"] is False for item in sections["code_evidence"].values())
    assert all(item["execution_status"] == "success" for item in sections["code_evidence"].values())
    assert report.vulnerability_sections == ()
    assert presentation["risk_summary"]["Code"] == "low"


@pytest.mark.parametrize(
    "path,payload,check",
    [
        ("syft/sbom.json", {"artifacts": [None]}, "insecure_nanopb_library"),
        ("syft/sbom.json", {"artifacts": {}}, "insecure_nanopb_library"),
        ("syft/sbom.json", {"unexpected_format": []}, "insecure_nanopb_library"),
        ("gitleaks/gitleaks_report.json", [None], "hardcoded_api_keys_in_bundle"),
        ("gitleaks/gitleaks_report.json", [{"RuleID": 42}], "hardcoded_api_keys_in_bundle"),
        ("trufflehog/trufflehog_results.json", None, "hardcoded_api_keys_in_bundle"),
        ("plist_source/App.entitlements.json", None, "insecure_entitlements"),
        ("plist_source/scan_index.json", {"plists": []}, "insecure_entitlements"),
    ],
)
def test_one_incomplete_input_prevents_clean_code_summary(tmp_path, completed_source_artifacts, path, payload, check):
    completed_source_artifacts[path] = payload
    sections, _, presentation = source_scan_report(tmp_path, completed_source_artifacts)
    assert sections["code_evidence"][check]["present"] is None
    assert presentation["risk_summary"]["Code"] == "not_evaluated"


def test_partial_source_scans_retain_positive_findings(tmp_path, completed_source_artifacts):
    completed_source_artifacts.update(
        {
            "syft/sbom.json": {
                "success": False,
                "error": "Scan interrupted",
                "raw_output": {"artifacts": [{"name": "nanopb", "version": "1.0.0"}]},
            },
            "gitleaks/gitleaks_report.json": {
                "success": False,
                "error": "Scan interrupted",
                "raw_output": [{"RuleID": "generic-api-key", "File": "Config.swift", "StartLine": 7}],
            },
            "plist_source/App.entitlements.json": {"plist": {"get-task-allow": True}},
            "plist_source/Broken.entitlements.json": {"success": False, "error": "Invalid plist"},
        }
    )
    index = completed_source_artifacts["plist_source/scan_index.json"]
    index.update(parse_failures=1, plist_count=2)
    index["plists"].append({"output_path": "Broken.entitlements.json", "parse_status": "failed"})

    sections, report, presentation = source_scan_report(tmp_path, completed_source_artifacts)

    assert all(item["present"] is True for item in sections["code_evidence"].values())
    assert all(item["execution_status"] == "partial" for item in sections["code_evidence"].values())
    checks = report.vulnerability_sections[0].checks
    assert len(checks) == 3
    assert all(check.result == AssessmentStatus.PRESENT and check.execution_status == "partial" for check in checks)
    assert all("incomplete scan" in check.explanation for check in checks)
    assert report.findings_severity.high == 2
    assert report.findings_severity.medium == 1
    assert presentation["risk_summary"]["Code"] == "high"


def test_secret_scanner_error_text_is_not_a_finding(tmp_path, completed_source_artifacts):
    completed_source_artifacts["gitleaks/gitleaks_report.json"] = {
        "success": False,
        "error": "generic-api-key detector failed to initialize",
    }
    sections, report, _ = source_scan_report(tmp_path, completed_source_artifacts)
    assert sections["code_evidence"]["hardcoded_api_keys_in_bundle"]["present"] is None
    assert report.vulnerability_sections == ()


@pytest.mark.parametrize("partial", [False, True])
def test_api_key_finding_descriptions_are_retained(tmp_path, completed_source_artifacts, partial):
    findings = [{"RuleID": "vendor-credential", "Description": "Vendor API Key", "File": "Config.swift"}]
    completed_source_artifacts["gitleaks/gitleaks_report.json"] = (
        {"success": False, "error": "Scan interrupted", "raw_output": findings} if partial else findings
    )
    sections, report, _ = source_scan_report(tmp_path, completed_source_artifacts)
    evidence = sections["code_evidence"]["hardcoded_api_keys_in_bundle"]
    assert evidence["present"] is True
    assert evidence["execution_status"] == ("partial" if partial else "success")
    assert report.findings_severity.high == 1


@pytest.mark.parametrize("content", [b'{"artifacts":', b"\xff\xfe"])
def test_corrupt_json_is_not_a_clean_scan(tmp_path, completed_source_artifacts, content):
    source_scan_report(tmp_path, completed_source_artifacts)
    (tmp_path / "syft/sbom.json").write_bytes(content)
    sections, _, presentation = source_scan_report(tmp_path, {})
    assert sections["code_evidence"]["insecure_nanopb_library"]["present"] is None
    assert presentation["risk_summary"]["Code"] == "not_evaluated"


@pytest.mark.parametrize("path", ["Missing.entitlements.json", ["invalid path"]])
def test_incomplete_plist_index_cannot_establish_absence(tmp_path, completed_source_artifacts, path):
    completed_source_artifacts["plist_source/scan_index.json"]["plists"][0]["output_path"] = path
    sections, _, presentation = source_scan_report(tmp_path, completed_source_artifacts)
    assert sections["code_evidence"]["insecure_entitlements"]["present"] is None
    assert presentation["risk_summary"]["Code"] == "not_evaluated"


def test_completed_source_scans_retain_positive_findings(tmp_path, completed_source_artifacts):
    completed_source_artifacts["syft/sbom.json"] = {"components": [{"name": "nanopb", "version": "1.0.0"}]}
    completed_source_artifacts["gitleaks/gitleaks_report.json"] = [
        {"RuleID": "generic-api-key", "File": "Config.swift", "StartLine": 7}
    ]
    completed_source_artifacts["plist_source/App.entitlements.json"] = {"plist": {"get-task-allow": True}}
    sections, report, presentation = source_scan_report(tmp_path, completed_source_artifacts)
    assert all(item["present"] is True for item in sections["code_evidence"].values())
    assert all(item["execution_status"] == "success" for item in sections["code_evidence"].values())
    assert all("incomplete" not in check.explanation for check in report.vulnerability_sections[0].checks)
    assert presentation["risk_summary"]["Code"] == "high"
