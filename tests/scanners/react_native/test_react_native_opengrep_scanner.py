"""Tests for scoped React Native OpenGrep orchestration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adapters.scanners.react_native import ReactNativeOpenGrepScanner
from application import mobile_analysis_workflow_service as workflow
from domain.models import ScanConfig, ScanResult, ScanType


def test_selects_application_source_paths_without_dependency_or_native_trees(tmp_path: Path) -> None:
    project = tmp_path / "project"
    for source_file in (
        "src/App.tsx",
        "app/index.tsx",
        "components/Button.jsx",
        "node_modules/package/index.js",
        "dist/bundle.js",
        "android/app/source.js",
        "ios/App/source.js",
        "index.js",
    ):
        path = project / source_file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")

    paths = ReactNativeOpenGrepScanner._react_native_scan_paths(project)

    assert paths == [
        project / "app",
        project / "components",
        project / "src",
        project / "index.js",
    ]


def test_scans_react_native_android_and_ios_with_scoped_rules(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    for source_file in ("src/App.tsx", "android/App.kt", "ios/App.swift"):
        path = project / source_file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    rules_root = tmp_path / "rules"
    for scope in ("react_native", "android", "ios"):
        (rules_root / scope).mkdir(parents=True)

    calls: list[tuple[str, list[Path]]] = []
    rule_ids = {
        "react_native": "react-native.source.cleartext-http",
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
            return [
                _result(
                    {
                        "success": True,
                        "results": [{"check_id": rule_ids[scope], "path": str(self.scan_paths[0])}],
                        "errors": [],
                        "scan_metadata": {
                            "tool_version": "test-version",
                            "configured_rule_ids": [rule_ids[scope]],
                        },
                    }
                )
            ]

    monkeypatch.setattr(
        "adapters.scanners.react_native.react_native_opengrep_scanner.OpenGrepScanner",
        FakeOpenGrepScanner,
    )

    result = ReactNativeOpenGrepScanner(
        rules_root / "react_native",
        android_rules_path=rules_root / "android",
        ios_rules_path=rules_root / "ios",
    ).scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is True
    assert calls == [
        ("react_native", [project / "src"]),
        ("android", [project / "android"]),
        ("ios", [project / "ios"]),
    ]
    assert payload["scan_metadata"]["status"] == "complete"
    assert payload["scan_metadata"]["configured_rule_ids"] == sorted(rule_ids.values())
    assert set(payload["scan_metadata"]["scopes"]) == {"react_native", "android", "ios"}
    assert {finding["phoenix_scope"] for finding in payload["results"]} == {
        "react_native",
        "android",
        "ios",
    }


def test_missing_required_react_native_source_scope_fails(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    rules_path = tmp_path / "rules" / "react_native"
    rules_path.mkdir(parents=True)

    result = ReactNativeOpenGrepScanner(rules_path).scan(_config(project, tmp_path))[0]
    payload = json.loads(result.raw_output)

    assert result.success is False
    assert payload["scan_metadata"]["status"] == "failed"
    assert payload["scan_metadata"]["scopes"]["react_native"]["status"] == "skipped"


def test_workflow_selects_scoped_opengrep_for_react_native(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    rules_path = tmp_path / "rules" / "react_native"
    rules_path.mkdir(parents=True)
    config = _config(project, tmp_path)
    config.opengrep_rules_path = rules_path
    captured: list[Path] = []

    class FakeReactNativeOpenGrepScanner:
        def __init__(self, react_native_rules_path):
            captured.append(Path(react_native_rules_path))

        def scan(self, scan_config):
            assert scan_config is config
            return [_result({"success": True, "results": []})]

    monkeypatch.setattr(workflow, "ReactNativeOpenGrepScanner", FakeReactNativeOpenGrepScanner)

    results = workflow.MobileAnalysisWorkflowService()._perform_opengrep_scan(config, None)

    assert captured == [rules_path]
    assert len(results) == 1


def test_rejects_failed_react_native_metadata_before_post_processing(tmp_path: Path) -> None:
    config = _config(tmp_path, tmp_path)
    failed = ScanResult(
        scanner_name="React Native Metadata Scanner",
        scan_type=ScanType.REACT_NATIVE_METADATA,
        success=False,
        skipped=True,
        error_message="package.json does not declare react-native or expo",
    )

    with pytest.raises(ValueError, match="React Native target validation failed.*does not declare"):
        workflow.MobileAnalysisWorkflowService._validate_required_metadata(config, [failed])


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
        stack="REACT_NATIVE",
    )
