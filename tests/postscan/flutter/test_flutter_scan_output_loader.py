"""Tests for loading persisted Flutter source scan artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.post_scan.flutter import FlutterScanOutputLoader


def test_loads_flutter_and_embedded_platform_artifacts(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_flutter_source_2026-08-30_12-00-00"
    _write_json(
        scan_dir / "scan_metadata.json",
        {"platform": "ANY", "stack": "FLUTTER", "target_type": "SOURCE"},
    )
    source_metadata = {
        "identity": {"package_name": "example_app", "version": "1.2.3+42"},
        "android": {
            "available": True,
            "metadata": {"identity": {"package_name": "com.example.app"}},
        },
        "ios": {
            "available": True,
            "metadata": {"identity": {"bundle_identifier": "com.example.app"}},
        },
    }
    _write_json(
        scan_dir / "flutter_source_metadata" / "project_metadata.json",
        source_metadata,
    )
    _write_json(
        scan_dir / "opengrep_source" / "opengrep_results.json",
        {
            "results": [],
            "scan_metadata": {"scopes": {"flutter": {"status": "success"}}},
        },
    )
    _write_json(
        scan_dir / "plist_source" / "Runner" / "Info.json",
        {"app_meta": {"bundle_identifier": "com.example.app"}},
    )
    _write_json(
        scan_dir / "plist_source" / "Runner" / "Runner.entitlements.json",
        {"entitlements": {"aps_environment": "development"}},
    )
    _write_json(
        scan_dir / "plist_source" / "scan_index.json",
        {"plists": [{"output_path": "Runner/Info.json", "role": "app"}]},
    )
    _write_json(
        scan_dir / "trufflehog" / "trufflehog_results.json",
        [{"DetectorName": "AWS"}],
    )
    _write_json(
        scan_dir / "gitleaks" / "gitleaks_report.json",
        [{"RuleID": "generic-api-key"}],
    )
    _write_json(
        scan_dir / "syft" / "sbom.json",
        {"artifacts": [{"name": "http", "version": "1.2.0"}]},
    )

    loaded = FlutterScanOutputLoader().load(scan_dir)

    assert loaded == {
        "scan_output_path": str(scan_dir),
        "scan_metadata": {"platform": "ANY", "stack": "FLUTTER", "target_type": "SOURCE"},
        "source_metadata": source_metadata,
        "opengrep": {
            "results": [],
            "scan_metadata": {"scopes": {"flutter": {"status": "success"}}},
        },
        "plist_outputs": {
            "Runner/Info.json": {"app_meta": {"bundle_identifier": "com.example.app"}},
            "Runner/Runner.entitlements.json": {"entitlements": {"aps_environment": "development"}},
        },
        "plist_index": {"plists": [{"output_path": "Runner/Info.json", "role": "app"}]},
        "trufflehog_outputs": {"trufflehog_results.json": [{"DetectorName": "AWS"}]},
        "gitleaks_outputs": {"gitleaks_report.json": [{"RuleID": "generic-api-key"}]},
        "syft_outputs": {"sbom.json": {"artifacts": [{"name": "http", "version": "1.2.0"}]}},
    }


def test_missing_flutter_artifacts_use_unassessed_defaults(tmp_path: Path) -> None:
    loaded = FlutterScanOutputLoader().load(tmp_path)

    assert loaded == {
        "scan_output_path": str(tmp_path),
        "scan_metadata": None,
        "source_metadata": None,
        "opengrep": None,
        "plist_outputs": {},
        "plist_index": None,
        "trufflehog_outputs": {},
        "gitleaks_outputs": {},
        "syft_outputs": {},
    }


def test_malformed_json_is_not_treated_as_a_successful_empty_report(tmp_path: Path) -> None:
    paths = (
        tmp_path / "flutter_source_metadata" / "project_metadata.json",
        tmp_path / "opengrep_source" / "opengrep_results.json",
        tmp_path / "plist_source" / "Runner" / "Info.json",
        tmp_path / "plist_source" / "scan_index.json",
        tmp_path / "gitleaks" / "gitleaks_report.json",
        tmp_path / "trufflehog" / "trufflehog_results.json",
        tmp_path / "syft" / "sbom.json",
    )
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not valid json", encoding="utf-8")

    loaded = FlutterScanOutputLoader().load(tmp_path)

    assert loaded["source_metadata"] is None
    assert loaded["opengrep"] is None
    assert loaded["plist_outputs"] == {"Runner/Info.json": None}
    assert loaded["plist_index"] is None
    assert loaded["gitleaks_outputs"] == {"gitleaks_report.json": None}
    assert loaded["trufflehog_outputs"] == {"trufflehog_results.json": None}
    assert loaded["syft_outputs"] == {"sbom.json": None}


def test_ignores_unknown_scanner_artifacts_but_loads_nested_plist_reports(tmp_path: Path) -> None:
    _write_json(tmp_path / "gitleaks" / "gitleaks_report.json", [])
    _write_json(tmp_path / "gitleaks" / "unknown.json", {"ignored": True})
    _write_json(tmp_path / "syft" / "nested" / "sbom.json", {"ignored": True})
    _write_json(tmp_path / "plist_source" / "nested" / "PrivacyInfo.xcprivacy.json", {"privacy": {}})

    loaded = FlutterScanOutputLoader().load(tmp_path)

    assert loaded["gitleaks_outputs"] == {"gitleaks_report.json": []}
    assert loaded["syft_outputs"] == {}
    assert loaded["plist_outputs"] == {"nested/PrivacyInfo.xcprivacy.json": {"privacy": {}}}


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
