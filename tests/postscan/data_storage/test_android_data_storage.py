import json
from pathlib import Path

from adapters.post_scan import AndroidBinaryScanOutputLoader


def test_android_data_storage_scan_output_loader_loads_expected_artifacts(tmp_path: Path) -> None:
    scan_dir = tmp_path / "SAST_android_binary_2026-07-03_23-34-29"
    (scan_dir / "opengrep_source").mkdir(parents=True)
    (scan_dir / "androguard").mkdir()
    (scan_dir / "aapt2").mkdir()
    (scan_dir / "apksigner").mkdir()
    (scan_dir / "apktool").mkdir()

    _write_json(scan_dir / "scan_metadata.json", {"platform": "ANDROID"})
    _write_json(scan_dir / "opengrep_source" / "opengrep_results.json", {"results": []})
    _write_json(scan_dir / "androguard" / "components.json", {"activities": []})
    _write_json(scan_dir / "androguard" / "metadata.json", {"app_name": "APKPure"})
    _write_json(scan_dir / "androguard" / "permissions.json", {"items": []})
    _write_json(scan_dir / "androguard" / "api_calls.json", {"items": []})
    _write_json(scan_dir / "androguard" / "certificates.json", {"all": []})
    _write_json(scan_dir / "aapt2" / "components.json", {"activities": []})
    _write_json(scan_dir / "aapt2" / "identity.json", {"application_label": "APKPure"})
    _write_json(scan_dir / "aapt2" / "application.json", {"id": "app"})
    _write_json(scan_dir / "aapt2" / "manifest_security_posture.json", {"posture_kind": "facts"})
    _write_json(scan_dir / "aapt2" / "permissions.json", {"permissions": []})
    _write_json(scan_dir / "apksigner" / "signing_evidence.json", {"verification": {}})
    _write_json(scan_dir / "apktool" / "manifest_summary.json", {"application": {"debuggable": "true"}})
    _write_json(scan_dir / "apktool" / "permissions.json", {"declared": []})
    _write_json(scan_dir / "apktool" / "secrets_endpoints.json", {"items": []})
    _write_json(scan_dir / "apktool" / "network_security_config.json", {"config_file_present": False})
    _write_json(scan_dir / "apktool" / "deep_links.json", {"deep_links": []})

    loaded = AndroidBinaryScanOutputLoader().load(scan_dir)

    assert loaded["scan_output_path"] == str(scan_dir)
    assert loaded["scan_metadata"] == {"platform": "ANDROID"}
    assert loaded["opengrep"] == {"results": []}
    assert loaded["androguard_components"] == {"activities": []}
    assert loaded["androguard_metadata"] == {"app_name": "APKPure"}
    assert loaded["androguard_permissions"] == {"items": []}
    assert loaded["androguard_api_calls"] == {"items": []}
    assert loaded["androguard_certificates"] == {"all": []}
    assert loaded["aapt2_components"] == {"activities": []}
    assert loaded["aapt2_identity"] == {"application_label": "APKPure"}
    assert loaded["aapt2_application"] == {"id": "app"}
    assert loaded["aapt2_manifest_security_posture"] == {"posture_kind": "facts"}
    assert loaded["aapt2_permissions"] == {"permissions": []}
    assert loaded["apksigner_signing_evidence"] == {"verification": {}}
    assert loaded["apktool_manifest_summary"] == {"application": {"debuggable": "true"}}
    assert loaded["apktool_permissions"] == {"declared": []}
    assert loaded["apktool_secrets_endpoints"] == {"items": []}
    assert loaded["apktool_network_security_config"] == {"config_file_present": False}
    assert loaded["apktool_deep_links"] == {"deep_links": []}


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")
