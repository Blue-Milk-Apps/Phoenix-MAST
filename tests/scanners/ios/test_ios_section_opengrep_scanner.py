import json

import pytest

from adapters.scanners.common import opengrep_scanner as module
from domain.models import ScanConfig, ScanResult, ScanType
from domain.post_scan.rule_assessment import rule_assessments
from tests.rule_fixtures import rule, write_rules


def run_scan(tmp_path, monkeypatch, payload, *, categories=("code", "crypto"), success=True):
    root = tmp_path / "source"
    for category in categories:
        write_rules(root / f"{category}.yml", rule(f"example.{category}"))
    calls = []

    class FakeScanner:
        def __init__(self, *, rules_paths, scan_paths):
            assert rules_paths == sorted(root / f"{category}.yml" for category in categories)
            assert scan_paths == [tmp_path]

        def scan(self, config):
            calls.append(config)
            return [ScanResult("OpenGrep", ScanType.OPENGREP_SOURCE, success=success, raw_output=json.dumps(payload))]

    monkeypatch.setattr(module, "OpenGrepScanner", FakeScanner)
    result = module.CategoryOpenGrepScanner(root).scan(ScanConfig(tmp_path, tmp_path / "out", platform="IOS"))[0]
    assert len(calls) == 1
    output = json.loads(result.raw_output)
    assert result.success == (output["scan_metadata"]["status"] == "success")
    return output


def test_categories_share_one_scan_and_keep_yaml_reporting_metadata(tmp_path, monkeypatch):
    output = run_scan(
        tmp_path,
        monkeypatch,
        {"results": [{"check_id": "example.crypto"}, {"check_id": "example.code"}], "errors": []},
    )
    assert output["scan_metadata"]["status"] == "success"
    assert set(output["scan_metadata"]["sections"]) == {"code.yml", "crypto.yml"}
    assert [item["phoenix_category"] for item in output["results"]] == ["crypto", "code"]
    assert all(item["phoenix_scope"] == "ios" for item in output["results"])
    assert all(item["status"] == "present" for item in rule_assessments(output)["rules"])


def test_completed_scan_without_matches_is_clean_for_all_categories(tmp_path, monkeypatch):
    output = run_scan(tmp_path, monkeypatch, {"results": [], "errors": []})
    assert output["scan_metadata"]["status"] == "success"
    assert all(item["status"] == "not_present" for item in rule_assessments(output)["rules"])


@pytest.mark.parametrize(
    "payload", [{"error": "bad config"}, "invalid", {"results": [], "errors": [{"message": "bad rule"}]}]
)
def test_incomplete_scan_does_not_certify_any_category_clean(tmp_path, monkeypatch, payload):
    output = run_scan(tmp_path, monkeypatch, payload)
    assert output["scan_metadata"]["status"] == "failed"
    assessments = {item["rule_id"]: item for item in rule_assessments(output)["rules"]}
    assert assessments["example.code"]["status"] == "not_evaluated"
    assert assessments["example.crypto"]["status"] == "not_evaluated"
    assert output["errors"]


@pytest.mark.parametrize("success", [True, False])
def test_partial_matches_survive_errors(tmp_path, monkeypatch, success):
    output = run_scan(
        tmp_path,
        monkeypatch,
        {
            "raw_output": {
                "results": [{"check_id": "example.code", "path": "Example.swift", "start": {"line": 4}}],
                "errors": [{"message": "Timeout"}],
            }
        },
        success=success,
    )
    assert output["scan_metadata"]["status"] == "partial"
    item = rule_assessments(output)["rules"][0]
    assert item["status"] == "present"
    assert item["execution_status"] == "not_evaluated"
    assert item["matches"][0]["start"]["line"] == 4
    assert rule_assessments(output)["rules"][1]["status"] == "not_evaluated"
    assert len(output["errors"]) == 2


def test_no_targets_is_not_a_clean_scan(tmp_path, monkeypatch):
    output = run_scan(tmp_path, monkeypatch, {"results": [], "paths": {"scanned": []}})
    assert rule_assessments(output)["rules"][0]["status"] == "not_evaluated"


def test_missing_binary_rules_never_fall_back_to_source(tmp_path):
    write_rules(tmp_path / "source" / "code.yml", rule())
    config = ScanConfig(tmp_path / "app.ipa", tmp_path / "out", mode="binary", platform="IOS")
    for directory in (tmp_path / "binary", tmp_path / "source"):
        result = module.CategoryOpenGrepScanner(directory).scan(config)[0]
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
        {"results": [{"check_id": "example.custom", "path": "Example.swift", "start": {"line": 7}}]},
        categories=("custom",),
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
