import json
from pathlib import Path

from adapters.scanners.ios import section_opengrep_scanner as scanner_module
from adapters.scanners.ios.rule_inventory import IOSRuleFile, IOSRuleInventory, IOSRuleSection
from domain.models import ScanConfig, ScanResult, ScanType


def _config(tmp_path: Path) -> ScanConfig:
    return ScanConfig(project_path=tmp_path / "project", output_path=tmp_path / "output", mode="source")


def _inventory(tmp_path: Path) -> IOSRuleInventory:
    files = tuple(
        IOSRuleFile(tmp_path / f"{section.name.lower()}.yml", section, (f"{section.name.lower()}.rule",))
        for section in (IOSRuleSection.CODE, IOSRuleSection.NETWORK)
    )
    return IOSRuleInventory(files=files)


def test_runs_each_section_and_aggregates_success(monkeypatch, tmp_path: Path) -> None:
    calls: list[Path] = []

    class FakeOpenGrepScanner:
        def __init__(self, rules_path, scan_paths):
            calls.append(Path(rules_path))

        def scan(self, config):
            _ = config
            section = calls[-1].stem
            return [
                ScanResult(
                    scanner_name="OpenGrep",
                    scan_type=ScanType.OPENGREP_SOURCE,
                    raw_output=json.dumps(
                        {
                            "results": [{"check_id": f"{section}.rule"}],
                            "errors": [],
                            "scan_metadata": {
                                "status": "success",
                                "configured_rule_ids": [f"{section}.rule"],
                                "tool_version": "test",
                            },
                        }
                    ),
                )
            ]

    monkeypatch.setattr(scanner_module, "validate_ios_rule_inventory", lambda _path: _inventory(tmp_path))
    monkeypatch.setattr(scanner_module, "OpenGrepScanner", FakeOpenGrepScanner)

    result = scanner_module.IOSSectionOpenGrepScanner(tmp_path / "rules").scan(_config(tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert payload["scan_metadata"]["status"] == "complete"
    assert payload["scan_metadata"]["configured_rule_ids"] == ["code.rule", "network.rule"]
    assert {finding["phoenix_scope"] for finding in payload["results"]} == {"code", "network"}
    assert [path.stem for path in calls] == ["code", "network"]


def test_failed_section_produces_partial_result(monkeypatch, tmp_path: Path) -> None:
    calls: list[Path] = []

    class FakeOpenGrepScanner:
        def __init__(self, rules_path, scan_paths):
            calls.append(Path(rules_path))

        def scan(self, config):
            _ = config
            section = calls[-1].stem
            if section == "code":
                return [
                    ScanResult(
                        scanner_name="OpenGrep",
                        scan_type=ScanType.OPENGREP_SOURCE,
                        success=False,
                        error_message="code rules failed",
                        raw_output=json.dumps(
                            {"error": "code rules failed", "return_code": 2, "stderr": "invalid language"}
                        ),
                    )
                ]
            return [
                ScanResult(
                    scanner_name="OpenGrep",
                    scan_type=ScanType.OPENGREP_SOURCE,
                    raw_output=json.dumps(
                        {
                            "results": [{"check_id": "network.rule"}],
                            "errors": [],
                            "scan_metadata": {
                                "status": "success",
                                "configured_rule_ids": ["network.rule"],
                            },
                        }
                    ),
                )
            ]

    monkeypatch.setattr(scanner_module, "validate_ios_rule_inventory", lambda _path: _inventory(tmp_path))
    monkeypatch.setattr(scanner_module, "OpenGrepScanner", FakeOpenGrepScanner)

    result = scanner_module.IOSSectionOpenGrepScanner(tmp_path / "rules").scan(_config(tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert payload["scan_metadata"]["status"] == "partial"
    assert payload["scan_metadata"]["sections"]["code"]["status"] == "failed"
    assert payload["scan_metadata"]["sections"]["network"]["status"] == "success"
    assert payload["errors"][0]["section"] == "code"
    assert payload["results"] == [{"check_id": "network.rule", "phoenix_scope": "network"}]


def test_retries_rules_named_in_structured_section_errors(monkeypatch, tmp_path: Path) -> None:
    calls: list[Path] = []
    code_rules = (
        {"id": "code.good", "metadata": {"phoenix": {"report_section": "Code"}}},
        {"id": "code.bad", "metadata": {"phoenix": {"report_section": "Code"}}},
    )
    inventory = IOSRuleInventory(
        files=(
            IOSRuleFile(
                tmp_path / "code.yml",
                IOSRuleSection.CODE,
                ("code.good", "code.bad"),
                code_rules,
            ),
        )
    )

    class FakeOpenGrepScanner:
        def __init__(self, rules_path, scan_paths):
            _ = scan_paths
            calls.append(Path(rules_path))

        def scan(self, config):
            _ = config
            rules_path = calls[-1]
            if rules_path.name == "code.yml":
                return [
                    ScanResult(
                        scanner_name="OpenGrep",
                        scan_type=ScanType.OPENGREP_SOURCE,
                        success=False,
                        error_message="code rules failed",
                        raw_output=json.dumps(
                            {
                                "error": "code rules failed",
                                "return_code": 2,
                                "stderr": "invalid language",
                                "raw_output": {
                                    "results": [{"check_id": "code.good"}],
                                    "errors": [{"rule_id": "code.bad", "message": "invalid language"}],
                                },
                            }
                        ),
                    )
                ]
            return [
                ScanResult(
                    scanner_name="OpenGrep",
                    scan_type=ScanType.OPENGREP_SOURCE,
                    raw_output=json.dumps(
                        {
                            "results": [{"check_id": "code.bad"}],
                            "errors": [],
                            "scan_metadata": {"configured_rule_ids": ["code.bad"]},
                        }
                    ),
                )
            ]

    monkeypatch.setattr(scanner_module, "validate_ios_rule_inventory", lambda _path: inventory)
    monkeypatch.setattr(scanner_module, "OpenGrepScanner", FakeOpenGrepScanner)

    result = scanner_module.IOSSectionOpenGrepScanner(tmp_path / "rules").scan(_config(tmp_path))[0]
    payload = json.loads(result.raw_output)
    section = payload["scan_metadata"]["sections"]["code"]

    assert result.success is True
    assert section["status"] == "partial"
    assert section["successful_rule_ids"] == ["code.bad", "code.good"]
    assert section["failed_rule_ids"] == []
    assert {finding["check_id"] for finding in payload["results"]} == {"code.good", "code.bad"}
    assert calls[0].name == "code.yml"
    assert calls[1].name == "code.bad.yml"
