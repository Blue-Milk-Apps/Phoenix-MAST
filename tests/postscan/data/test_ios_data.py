import json
from pathlib import Path

from adapters.post_scan import IOSBinaryScanOutputLoader


def test_ios_binary_scan_output_loader_loads_expected_artifacts(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_ios_binary_2026-07-23_10-00-00"
    (scan_dir / "opengrep_source").mkdir(parents=True)
    (scan_dir / "ipsw" / "Payload" / "App.app").mkdir(parents=True)
    (scan_dir / "lief" / "Payload" / "App.app").mkdir(parents=True)
    (scan_dir / "plist_binary").mkdir()
    (scan_dir / "strings").mkdir()
    (scan_dir / "trufflehog").mkdir()
    (scan_dir / "gitleaks").mkdir()
    (scan_dir / "syft").mkdir()

    _write_json(
        scan_dir / "scan_metadata.json",
        {
            "platform": "IOS",
            "project_path": str(tmp_path / "Demo.ipa"),
        },
    )
    _write_json(scan_dir / "opengrep_source" / "opengrep_results.json", {"results": []})
    _write_json(
        scan_dir / "ipsw" / "Payload" / "App.app" / "App.json",
        {"app_info": {"bundle_id": "com.example.app"}},
    )
    _write_json(
        scan_dir / "lief" / "Payload" / "App.app" / "App.json",
        {"binary": {"name": "App"}},
    )
    _write_json(
        scan_dir / "plist_binary" / "Info.json",
        {
            "app_meta": {
                "bundle_identifier": "com.example.app",
                "bundle_name": "ExampleApp",
                "display_name": "ExampleApp",
                "version": "1.2.3",
                "build": "7",
            },
            "plist": {"CFBundleExecutable": "ExampleApp"},
        },
    )
    _write_json(scan_dir / "plist_binary" / "scan_index.json", {"plists": []})
    (scan_dir / "strings" / "main.txt").write_text("hello\n", encoding="utf-8")
    (scan_dir / "trufflehog" / "report.json").write_text("{}", encoding="utf-8")
    (scan_dir / "gitleaks" / "report.json").write_text("{}", encoding="utf-8")
    (scan_dir / "syft" / "sbom.json").write_text("{}", encoding="utf-8")

    loaded = IOSBinaryScanOutputLoader().load(scan_dir)

    assert loaded["scan_output_path"] == str(scan_dir)
    assert loaded["scan_metadata"] == {"platform": "IOS", "project_path": str(tmp_path / "Demo.ipa")}
    assert loaded["opengrep"] == {"results": []}
    assert loaded["ipsw_outputs"] == {"Payload/App.app/App.json": {"app_info": {"bundle_id": "com.example.app"}}}
    assert loaded["lief_outputs"] == {"Payload/App.app/App.json": {"binary": {"name": "App"}}}
    assert loaded["plist_outputs"] == {
        "Info.json": {
            "app_meta": {
                "bundle_identifier": "com.example.app",
                "bundle_name": "ExampleApp",
                "display_name": "ExampleApp",
                "version": "1.2.3",
                "build": "7",
            },
            "plist": {"CFBundleExecutable": "ExampleApp"},
        }
    }
    assert loaded["plist_index"] == {"plists": []}
    assert loaded["strings_outputs"] == {"main.txt": "hello\n"}
    assert loaded["trufflehog_outputs"] == {"report.json": {}}
    assert loaded["gitleaks_outputs"] == {"report.json": {}}
    assert loaded["syft_outputs"] == {"sbom.json": {}}


def test_ios_binary_scan_output_loader_tolerates_missing_optional_artifacts(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_ios_binary_2026-07-23_10-00-00"
    scan_dir.mkdir()
    _write_json(scan_dir / "scan_metadata.json", {"platform": "IOS"})

    loaded = IOSBinaryScanOutputLoader().load(scan_dir)

    assert loaded["scan_metadata"] == {"platform": "IOS"}
    assert loaded["opengrep"] is None
    assert loaded["ipsw_outputs"] == {}
    assert loaded["lief_outputs"] == {}
    assert loaded["plist_outputs"] == {}
    assert loaded["plist_index"] is None
    assert loaded["strings_outputs"] == {}
    assert loaded["trufflehog_outputs"] == {}
    assert loaded["gitleaks_outputs"] == {}
    assert loaded["syft_outputs"] == {}


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")
