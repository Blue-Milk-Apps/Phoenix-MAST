"""Tests for loading persisted React Native source scan artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.post_scan.react_native import ReactNativeScanOutputLoader


def test_loads_react_native_and_embedded_platform_artifacts(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_react_native_source_2026-09-02_12-00-00"
    _write_json(
        scan_dir / "scan_metadata.json",
        {"platform": "ANY", "stack": "REACT_NATIVE", "target_type": "SOURCE"},
    )
    source_metadata = {
        "identity": {"package_name": "example-app", "version": "1.2.3"},
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
        scan_dir / "react_native_metadata" / "project_metadata.json",
        source_metadata,
    )
    _write_json(
        scan_dir / "opengrep_source" / "opengrep_results.json",
        {
            "results": [],
            "scan_metadata": {"scopes": {"react_native": {"status": "success"}}},
        },
    )
    _write_json(
        scan_dir / "plist_source" / "Example" / "Info.json",
        {"app_meta": {"bundle_identifier": "com.example.app"}},
    )
    _write_json(
        scan_dir / "plist_source" / "Example" / "Example.entitlements.json",
        {"entitlements": {"aps_environment": "development"}},
    )
    _write_json(
        scan_dir / "plist_source" / "scan_index.json",
        {"plists": [{"output_path": "Example/Info.json", "role": "app"}]},
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
        {"artifacts": [{"name": "react", "version": "19.1.0"}]},
    )

    loaded = ReactNativeScanOutputLoader().load(scan_dir)

    assert loaded == {
        "scan_output_path": str(scan_dir),
        "scan_metadata": {"platform": "ANY", "stack": "REACT_NATIVE", "target_type": "SOURCE"},
        "source_metadata": source_metadata,
        "opengrep": {
            "results": [],
            "scan_metadata": {"scopes": {"react_native": {"status": "success"}}},
        },
        "plist_outputs": {
            "Example/Example.entitlements.json": {"entitlements": {"aps_environment": "development"}},
            "Example/Info.json": {"app_meta": {"bundle_identifier": "com.example.app"}},
        },
        "plist_index": {"plists": [{"output_path": "Example/Info.json", "role": "app"}]},
        "trufflehog_outputs": {"trufflehog_results.json": [{"DetectorName": "AWS"}]},
        "gitleaks_outputs": {"gitleaks_report.json": [{"RuleID": "generic-api-key"}]},
        "syft_outputs": {"sbom.json": {"artifacts": [{"name": "react", "version": "19.1.0"}]}},
    }


def test_missing_react_native_artifacts_use_unassessed_defaults(tmp_path: Path) -> None:
    loaded = ReactNativeScanOutputLoader().load(tmp_path)

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


def test_malformed_json_is_preserved_as_unassessed(tmp_path: Path) -> None:
    paths = (
        tmp_path / "react_native_metadata" / "project_metadata.json",
        tmp_path / "opengrep_source" / "opengrep_results.json",
        tmp_path / "plist_source" / "Example" / "Info.json",
        tmp_path / "plist_source" / "scan_index.json",
        tmp_path / "gitleaks" / "gitleaks_report.json",
        tmp_path / "trufflehog" / "trufflehog_results.json",
        tmp_path / "syft" / "sbom.json",
    )
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not valid json", encoding="utf-8")

    loaded = ReactNativeScanOutputLoader().load(tmp_path)

    assert loaded["source_metadata"] is None
    assert loaded["opengrep"] is None
    assert loaded["plist_outputs"] == {"Example/Info.json": None}
    assert loaded["plist_index"] is None
    assert loaded["gitleaks_outputs"] == {"gitleaks_report.json": None}
    assert loaded["trufflehog_outputs"] == {"trufflehog_results.json": None}
    assert loaded["syft_outputs"] == {"sbom.json": None}


def test_ignores_unknown_artifacts_and_loads_nested_plist_reports(tmp_path: Path) -> None:
    _write_json(tmp_path / "gitleaks" / "gitleaks_report.json", [])
    _write_json(tmp_path / "gitleaks" / "unknown.json", {"ignored": True})
    _write_json(tmp_path / "syft" / "nested" / "sbom.json", {"ignored": True})
    _write_json(tmp_path / "plist_source" / "nested" / "PrivacyInfo.xcprivacy.json", {"privacy": {}})

    loaded = ReactNativeScanOutputLoader().load(tmp_path)

    assert loaded["gitleaks_outputs"] == {"gitleaks_report.json": []}
    assert loaded["syft_outputs"] == {}
    assert loaded["plist_outputs"] == {"nested/PrivacyInfo.xcprivacy.json": {"privacy": {}}}


def test_does_not_follow_artifact_symlinks_outside_scan_root(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    outside = tmp_path / "outside"
    _write_json(outside / "Info.json", {"secret": True})
    plist_root = scan_dir / "plist_source"
    plist_root.mkdir(parents=True)
    (plist_root / "Info.json").symlink_to(outside / "Info.json")

    loaded = ReactNativeScanOutputLoader().load(scan_dir)

    assert loaded["plist_outputs"] == {}


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
