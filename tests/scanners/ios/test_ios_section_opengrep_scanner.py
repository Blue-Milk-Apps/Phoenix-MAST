import json

from adapters.scanners.ios import section_opengrep_scanner as module
from domain.models import ScanConfig, ScanResult, ScanType
from domain.post_scan.rule_assessment import rule_assessments
from tests.rule_fixtures import rule, write_rules


def run_scan(tmp_path, monkeypatch, reports):
    root = tmp_path / "source"
    for category in reports:
        write_rules(root / f"{category}.yml", rule(f"example.{category}"))

    class FakeScanner:
        def __init__(self, rules_path, scan_paths):
            self.category = rules_path.stem

        def scan(self, config):
            success, payload = reports[self.category]
            return [ScanResult("OpenGrep", ScanType.OPENGREP_SOURCE, success=success, raw_output=json.dumps(payload))]

    monkeypatch.setattr(module, "OpenGrepScanner", FakeScanner)
    result = module.IOSSectionOpenGrepScanner(root).scan(ScanConfig(tmp_path, tmp_path / "out", platform="IOS"))[0]
    return json.loads(result.raw_output)


def test_code_and_crypto_have_independent_execution_metadata(tmp_path, monkeypatch):
    output = run_scan(
        tmp_path,
        monkeypatch,
        {"code": (False, {"error": "bad config"}), "crypto": (True, {"results": [], "errors": []})},
    )
    assert output["scan_metadata"]["status"] == "partial"
    assert set(output["scan_metadata"]["sections"]) == {"code.yml", "crypto.yml"}
    assessments = {item["rule_id"]: item for item in rule_assessments(output)["rules"]}
    assert assessments["example.code"]["status"] == "not_evaluated"
    assert assessments["example.crypto"]["status"] == "not_present"


def test_partial_matches_survive_errors(tmp_path, monkeypatch):
    output = run_scan(
        tmp_path,
        monkeypatch,
        {
            "code": (
                False,
                {
                    "raw_output": {
                        "results": [{"check_id": "example.code", "path": "Example.swift", "start": {"line": 4}}],
                        "errors": [{"message": "Timeout"}],
                    }
                },
            )
        },
    )
    item = rule_assessments(output)["rules"][0]
    assert item["status"] == "present"
    assert item["execution_status"] == "not_evaluated"
    assert item["matches"][0]["start"]["line"] == 4


def test_no_targets_is_not_a_clean_scan(tmp_path, monkeypatch):
    output = run_scan(tmp_path, monkeypatch, {"code": (True, {"results": [], "paths": {"scanned": []}})})
    assert rule_assessments(output)["rules"][0]["status"] == "not_evaluated"


def test_missing_binary_rules_never_fall_back_to_source(tmp_path):
    write_rules(tmp_path / "source" / "code.yml", rule())
    config = ScanConfig(tmp_path / "app.ipa", tmp_path / "out", mode="binary", platform="IOS")
    for directory in (tmp_path / "binary", tmp_path / "source"):
        result = module.IOSSectionOpenGrepScanner(directory).scan(config)[0]
        assert not result.success
        assert json.loads(result.raw_output)["scan_metadata"]["rule_catalog"] == []


def test_persisted_scan_generates_report_without_rule_files(tmp_path, monkeypatch):
    from adapters.output.phoenix_report.builders.ios import NativeIOSReportDataBuilder
    from adapters.post_scan.ios.native.scan_detail_extractor import NativeIOSScanDetailExtractor
    from adapters.post_scan.ios.native.scan_output_loader import NativeIOSScanOutputLoader
    from application.post_scan_processing_service import PostScanProcessingService
    from application.report_generation_service import ReportGenerationService

    output = run_scan(
        tmp_path,
        monkeypatch,
        {
            "custom": (
                True,
                {"results": [{"check_id": "example.custom", "path": "Example.swift", "start": {"line": 7}}]},
            )
        },
    )
    output_root = tmp_path / "out"
    (output_root / "opengrep_source").mkdir(parents=True)
    (output_root / "opengrep_source/opengrep_results.json").write_text(json.dumps(output))
    (output_root / "scan_metadata.json").write_text(
        json.dumps({"platform": "IOS", "stack": "NATIVE_IOS", "target_type": "SOURCE", "project_path": str(tmp_path)})
    )
    (tmp_path / "source/custom.yml").unlink()
    data = PostScanProcessingService(NativeIOSScanOutputLoader(), NativeIOSScanDetailExtractor()).process(output_root)
    from dataclasses import asdict

    from domain.report import ReportTargetFactory

    data["target_information"] = asdict(
        ReportTargetFactory.from_scan_config(ScanConfig(tmp_path, output_root, platform="IOS", stack="NATIVE_IOS"))
    )
    report = ReportGenerationService([NativeIOSReportDataBuilder()]).build_report_data(data)
    check = report.vulnerability_sections[-1].checks[0]
    assert check.rule_id == "example.custom"
    assert check.name == "Example check"
    assert check.result.value == "present"
    assert report.findings_severity.high == 1
    assert "Example.swift:7" in check.evidence
