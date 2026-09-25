import json

from adapters.output.file_output import FileScanOutput
from adapters.output.phoenix_report.builders.android import NativeAndroidReportDataBuilder
from adapters.output.phoenix_report.pdf_report import PdfReportGenerator
from adapters.output.phoenix_report.pdf_report.common import build_charts
from adapters.post_scan import NativeAndroidScanDetailExtractor
from adapters.post_scan.android.native.scan_output_loader import NativeAndroidScanOutputLoader
from adapters.scanners.common.opengrep_scanner import OpenGrepScanner, validate_rule_inventory
from application.mobile_analysis_workflow_service import MobileAnalysisWorkflowService
from application.post_scan_processing_service import PostScanProcessingService
from application.report_generation_service import ReportGenerationService
from domain.models import ScanConfig, ScanResult, ScanType
from tests.rule_fixtures import private_rules, rule, write_rules


def _report(sections: dict) -> object:
    payload = {
        **sections,
        "target_information": {
            "target_kind": "native_android_source",
            "platform": "android",
            "target_type": "source",
            "stack": "native_android",
        },
    }
    return ReportGenerationService([NativeAndroidReportDataBuilder()]).build_report_data(payload)


def test_all_bundled_android_rules_are_explicitly_classified() -> None:
    inventory = validate_rule_inventory(private_rules("android"))
    assert {item.category for item in inventory.files} == {
        "code",
        "network",
        "data_storage",
        "resilience",
        "functionality",
    }
    for definition in inventory.catalog:
        assert definition["metadata"]["finding_type"] in {"weakness", "review", "control", "observation"}
        assert not {"evidence_key", "report_section", "capability_type", "category"} & definition["metadata"].keys()


def test_source_security_report_uses_persisted_rules_without_python_registration(tmp_path, monkeypatch) -> None:
    rules = tmp_path / "rules" / "android" / "source"
    matched = rule("example.new-android-check", title="Title supplied by YAML")
    matched["metadata"]["impact"] = "Impact supplied by YAML"
    path = write_rules(rules / "code.yml", matched, rule("example.no-match"))
    permission = rule("example.new-permission", finding_type="observation", severity="INFO")
    permission["metadata"].update(scope="app_declaration", functionality="Custom Capability")
    permission_path = write_rules(rules / "functionality.yml", permission)
    config = ScanConfig(
        tmp_path, tmp_path / "out", platform="ANDROID", stack="NATIVE_ANDROID", opengrep_rules_path=rules
    )
    output = FileScanOutput(config.output_path)
    output.write_scan_metadata(config)
    raw = json.dumps(
        {
            "results": [
                {
                    "check_id": "example.new-android-check",
                    "path": "app/src/main/Crypto.kt",
                    "start": {"line": 18},
                    "extra": {"lines": "EXAMPLE_MARKER"},
                },
                {
                    "check_id": "example.new-permission",
                    "path": "app/src/main/AndroidManifest.xml",
                    "start": {"line": 3},
                    "extra": {"metavars": {"$PERMISSION": {"abstract_content": "example.permission.CUSTOM"}}},
                },
            ],
            "errors": [],
        }
    )
    monkeypatch.setattr(OpenGrepScanner, "is_available", lambda self: True)
    monkeypatch.setattr(
        OpenGrepScanner, "scan", lambda self, config: [ScanResult(self.name, ScanType.OPENGREP_SOURCE, raw_output=raw)]
    )
    result = MobileAnalysisWorkflowService()._perform_opengrep_scan(config, output)[0]
    assert result.success
    path.unlink()
    permission_path.unlink()
    sections = PostScanProcessingService(NativeAndroidScanOutputLoader(), NativeAndroidScanDetailExtractor()).process(
        config.output_path
    )
    assessments = {item["rule_id"]: item for item in sections["rule_assessments"]["rules"]}
    assert assessments["example.new-android-check"]["status"] == "present"
    assert assessments["example.no-match"]["status"] == "not_present"
    assert sections["functionality"]["Custom Capability"]["present"] is True
    assert sections["permissions"][0]["permission"] == "example.permission.CUSTOM"
    report = _report(sections)
    code = next(section for section in report.vulnerability_sections if section.name == "Code")
    assert len(code.checks) == 1
    check = code.checks[0]
    assert check.name == "Title supplied by YAML"
    assert check.rule_id == "example.new-android-check"
    assert check.impact == "Impact supplied by YAML"
    assert check.remediation == matched["metadata"]["remediation"]["guidance"]
    assert check.references == ("https://example.test/guide",)
    assert check.platform_assessments[0].platform.value == "android"
    assert "app/src/main/Crypto.kt:18" in check.evidence
    assert report.findings_severity.high == 1
    assert report.rule_coverage[0]["platform"] == "android"


def test_missing_security_scanner_omits_unmatched_checks_from_report() -> None:
    sections = NativeAndroidScanDetailExtractor().extract_sections(
        {
            "scan_metadata": {"project_path": "/workspace/Example", "target_type": "SOURCE"},
            "source_metadata": {"application": {"debuggable": False, "allow_backup": False}},
        }
    )

    report = _report(sections)
    assert not report.vulnerability_sections
    assert sections["code_evidence"]["app_is_debuggable"]["present"] is False
    assert "contains_potential_sql_injection" not in sections["code_evidence"]
    assert report.findings_severity.high == 0
    assert report.findings_severity.info == 0


def test_report_presentation_contains_risk_chart() -> None:
    report = _report(NativeAndroidScanDetailExtractor().extract_sections({}))
    presentation = PdfReportGenerator._presentation_data(report)
    assert build_charts(presentation)["overall_risk_polar"]
