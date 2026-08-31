from __future__ import annotations

import json
from pathlib import Path

from adapters.scanners.flutter import FlutterOpenGrepScanner
from application import mobile_analysis_workflow_service as workflow
from domain.models import ScanConfig, ScanResult, ScanType


def test_scans_each_flutter_platform_with_only_its_scoped_rules(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    for source_path in ("lib", "android", "ios"):
        (project / source_path).mkdir(parents=True)
    rules_root = tmp_path / "rules"
    for scope in ("flutter", "android", "ios"):
        (rules_root / scope).mkdir(parents=True)

    calls: list[tuple[str, list[Path]]] = []
    rule_ids = {
        "flutter": "flutter.source.cleartext-http",
        "android": "android.source.cleartext-http",
        "ios": "ios.network.cookie-missing-secure-flag",
    }

    class FakeOpenGrepScanner:
        def __init__(self, rules_path=None, scan_paths=None):
            self.rules_path = Path(rules_path)
            self.scan_paths = list(scan_paths)

        def scan(self, config):
            _ = config
            scope = self.rules_path.name
            calls.append((scope, self.scan_paths))
            payload = {
                "success": True,
                "results": [{"check_id": rule_ids[scope], "path": str(self.scan_paths[0] / "source.txt")}],
                "errors": [],
                "scan_metadata": {
                    "tool_version": "test-version",
                    "configured_rule_ids": [rule_ids[scope]],
                },
            }
            return [_result(payload)]

    monkeypatch.setattr(
        "adapters.scanners.flutter.flutter_opengrep_scanner.OpenGrepScanner",
        FakeOpenGrepScanner,
    )

    result = FlutterOpenGrepScanner(
        rules_root / "flutter",
        android_rules_path=rules_root / "android",
        ios_rules_path=rules_root / "ios",
    ).scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert result.relative_target_path == "opengrep_results.json"
    assert calls == [
        ("flutter", [project / "lib"]),
        ("android", [project / "android"]),
        ("ios", [project / "ios"]),
    ]
    assert payload["scan_metadata"]["status"] == "complete"
    assert payload["scan_metadata"]["configured_rule_ids"] == sorted(rule_ids.values())
    assert set(payload["scan_metadata"]["scopes"]) == {"flutter", "android", "ios"}
    assert {finding["phoenix_scope"] for finding in payload["results"]} == {"flutter", "android", "ios"}


def test_missing_native_platforms_are_recorded_as_skipped(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    (project / "lib").mkdir(parents=True)
    rules_path = tmp_path / "rules" / "flutter"
    rules_path.mkdir(parents=True)
    calls: list[list[Path]] = []

    class FakeOpenGrepScanner:
        def __init__(self, rules_path=None, scan_paths=None):
            _ = rules_path
            calls.append(list(scan_paths))

        def scan(self, config):
            _ = config
            return [
                _result(
                    {
                        "success": True,
                        "results": [],
                        "errors": [],
                        "scan_metadata": {
                            "tool_version": "test-version",
                            "configured_rule_ids": ["flutter.source.cleartext-http"],
                        },
                    }
                )
            ]

    monkeypatch.setattr(
        "adapters.scanners.flutter.flutter_opengrep_scanner.OpenGrepScanner",
        FakeOpenGrepScanner,
    )

    result = FlutterOpenGrepScanner(rules_path).scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert calls == [[project / "lib"]]
    assert payload["scan_metadata"]["status"] == "complete"
    assert payload["scan_metadata"]["scopes"]["android"]["status"] == "skipped"
    assert payload["scan_metadata"]["scopes"]["ios"]["status"] == "skipped"
    assert "not present" in payload["scan_metadata"]["scopes"]["android"]["reason"]


def test_failed_required_flutter_scope_does_not_record_its_rule_ids(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    (project / "lib").mkdir(parents=True)
    rules_path = tmp_path / "rules" / "flutter"
    rules_path.mkdir(parents=True)

    class FakeOpenGrepScanner:
        def __init__(self, rules_path=None, scan_paths=None):
            _ = (rules_path, scan_paths)

        def scan(self, config):
            _ = config
            return [
                ScanResult(
                    scanner_name="OpenGrep",
                    scan_type=ScanType.OPENGREP_SOURCE,
                    success=False,
                    error_message="scanner failed",
                    raw_output=json.dumps({"success": False, "error": "scanner failed"}),
                )
            ]

    monkeypatch.setattr(
        "adapters.scanners.flutter.flutter_opengrep_scanner.OpenGrepScanner",
        FakeOpenGrepScanner,
    )

    result = FlutterOpenGrepScanner(rules_path).scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is False
    assert payload["success"] is False
    assert payload["scan_metadata"]["status"] == "failed"
    assert payload["scan_metadata"]["configured_rule_ids"] == []
    assert payload["scan_metadata"]["scopes"]["flutter"]["status"] == "failed"
    assert payload["errors"] == [{"error": "scanner failed", "scope": "flutter"}]


def test_failed_native_scope_makes_report_partial_without_discarding_flutter_results(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "project"
    (project / "lib").mkdir(parents=True)
    (project / "android").mkdir()
    rules_root = tmp_path / "rules"
    (rules_root / "flutter").mkdir(parents=True)
    (rules_root / "android").mkdir()

    class FakeOpenGrepScanner:
        def __init__(self, rules_path=None, scan_paths=None):
            self.scope = Path(rules_path).name
            _ = scan_paths

        def scan(self, config):
            _ = config
            if self.scope == "android":
                return [
                    ScanResult(
                        scanner_name="OpenGrep",
                        scan_type=ScanType.OPENGREP_SOURCE,
                        success=False,
                        error_message="Android rules failed",
                        raw_output=json.dumps({"success": False, "error": "Android rules failed"}),
                    )
                ]
            return [
                _result(
                    {
                        "success": True,
                        "results": [{"check_id": "flutter.source.cleartext-http"}],
                        "errors": [],
                        "scan_metadata": {
                            "configured_rule_ids": ["flutter.source.cleartext-http"],
                        },
                    }
                )
            ]

    monkeypatch.setattr(
        "adapters.scanners.flutter.flutter_opengrep_scanner.OpenGrepScanner",
        FakeOpenGrepScanner,
    )

    result = FlutterOpenGrepScanner(
        rules_root / "flutter",
        android_rules_path=rules_root / "android",
    ).scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert payload["scan_metadata"]["status"] == "partial"
    assert payload["scan_metadata"]["configured_rule_ids"] == ["flutter.source.cleartext-http"]
    assert payload["scan_metadata"]["scopes"]["android"]["status"] == "failed"
    assert payload["results"][0]["phoenix_scope"] == "flutter"


def test_workflow_selects_scoped_opengrep_for_flutter(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    rules_path = tmp_path / "rules" / "flutter"
    rules_path.mkdir(parents=True)
    config = _config(project, tmp_path)
    config.opengrep_rules_path = rules_path
    captured: list[Path] = []

    class FakeFlutterOpenGrepScanner:
        def __init__(self, flutter_rules_path):
            captured.append(Path(flutter_rules_path))

        def scan(self, scan_config):
            assert scan_config is config
            return [_result({"success": True, "results": []})]

    monkeypatch.setattr(workflow, "FlutterOpenGrepScanner", FakeFlutterOpenGrepScanner)

    results = workflow.MobileAnalysisWorkflowService()._perform_opengrep_scan(config, None)

    assert captured == [rules_path]
    assert len(results) == 1


def _result(payload: dict[str, object]) -> ScanResult:
    return ScanResult(
        scanner_name="OpenGrep",
        scan_type=ScanType.OPENGREP_SOURCE,
        success=True,
        raw_output=json.dumps(payload),
    )


def _config(project: Path, tmp_path: Path) -> ScanConfig:
    return ScanConfig(
        project_path=project,
        output_path=tmp_path / "results",
        mode="source",
        platform="ANY",
        stack="FLUTTER",
    )
