import json
from pathlib import Path
from typing import Any

from adapters.post_scan import NativeAndroidScanOutputLoader


def test_loads_known_native_android_source_artifacts(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_native_android_source_2026-08-27_12-00-00"
    _write_json(scan_dir / "scan_metadata.json", {"platform": "ANDROID"})
    _write_json(scan_dir / "opengrep_source" / "opengrep_results.json", {"results": []})
    _write_json(scan_dir / "trufflehog" / "trufflehog_results.json", [{"DetectorName": "GCP"}])
    _write_json(scan_dir / "gitleaks" / "gitleaks_report.json", [{"RuleID": "generic-api-key"}])
    _write_json(scan_dir / "syft" / "sbom.json", {"artifacts": [{"name": "gradle-wrapper"}]})

    loaded = NativeAndroidScanOutputLoader().load(scan_dir)

    assert loaded == {
        "scan_output_path": str(scan_dir),
        "scan_metadata": {"platform": "ANDROID"},
        "opengrep": {"results": []},
        "trufflehog_outputs": {"trufflehog_results.json": [{"DetectorName": "GCP"}]},
        "gitleaks_outputs": {"gitleaks_report.json": [{"RuleID": "generic-api-key"}]},
        "syft_outputs": {"sbom.json": {"artifacts": [{"name": "gradle-wrapper"}]}},
    }


def test_missing_native_android_source_artifacts_use_empty_defaults(tmp_path: Path) -> None:
    loaded = NativeAndroidScanOutputLoader().load(tmp_path)

    assert loaded["scan_metadata"] is None
    assert loaded["opengrep"] is None
    assert loaded["trufflehog_outputs"] == {}
    assert loaded["gitleaks_outputs"] == {}
    assert loaded["syft_outputs"] == {}


def test_malformed_known_json_is_retained_as_none(tmp_path: Path) -> None:
    report = tmp_path / "gitleaks" / "gitleaks_report.json"
    report.parent.mkdir(parents=True)
    report.write_text("not valid json", encoding="utf-8")

    loaded = NativeAndroidScanOutputLoader().load(tmp_path)

    assert loaded["gitleaks_outputs"] == {"gitleaks_report.json": None}


def test_unknown_and_nested_artifacts_are_ignored(tmp_path: Path) -> None:
    _write_json(tmp_path / "trufflehog" / "trufflehog_results.json", [])
    _write_json(tmp_path / "trufflehog" / "unknown.json", {"ignored": True})
    _write_json(tmp_path / "trufflehog" / "nested" / "secondary_results.json", {"ignored": True})

    loaded = NativeAndroidScanOutputLoader().load(tmp_path)

    assert loaded["trufflehog_outputs"] == {"trufflehog_results.json": []}


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
