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
