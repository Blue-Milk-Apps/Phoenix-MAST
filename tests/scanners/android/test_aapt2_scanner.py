from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

from adapters.scanners.android import aapt2_scanner
from adapters.scanners.android.aapt2_scanner import Aapt2Scanner
from domain.models import ScanConfig, ScanType

BADGING_OUTPUT = """\
package: name='com.example.app' versionCode='42' versionName='4.2' compileSdkVersion='35'
sdkVersion:'23'
targetSdkVersion:'35'
application-label:'Example'
launchable-activity: name='com.example.app.MainActivity' label='Example'
uses-permission: name='android.permission.CAMERA'
native-code: 'arm64-v8a' 'armeabi-v7a'
"""

PERMISSIONS_OUTPUT = """\
package: com.example.app
uses-permission: name='android.permission.INTERNET'
uses-permission: name='android.permission.CAMERA'
"""

XMLTREE_OUTPUT = """\
N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=2)
    A: package="com.example.app" (Raw: "com.example.app")
    E: application (line=10)
      A: android:allowBackup(0x01010280)=(type 0x12)0xffffffff
      A: android:usesCleartextTraffic(0x010104ec)=(type 0x12)0xffffffff
      A: android:networkSecurityConfig(0x010104ee)=@0x7f130001
      A: android:requestLegacyExternalStorage(0x01010503)=(type 0x12)0x00000000
      E: activity (line=20)
        A: android:name(0x01010003)="com.example.app.MainActivity" (Raw: "com.example.app.MainActivity")
        A: android:exported(0x01010010)=(type 0x12)0xffffffff
        E: intent-filter (line=22)
          E: action (line=23)
            A: android:name(0x01010003)="android.intent.action.VIEW" (Raw: "android.intent.action.VIEW")
          E: category (line=24)
            A: android:name(0x01010003)="android.intent.category.BROWSABLE" (Raw: "android.intent.category.BROWSABLE")
          E: data (line=25)
            A: android:scheme(0x01010027)="https" (Raw: "https")
            A: android:host(0x01010028)="example.com" (Raw: "example.com")
            A: android:pathPrefix(0x0101002c)="/oauth/callback" (Raw: "/oauth/callback")
      E: provider (line=30)
        A: android:name(0x01010003)="androidx.core.content.FileProvider" (Raw: "androidx.core.content.FileProvider")
        A: android:authorities(0x01010018)="com.example.app.fileprovider" (Raw: "com.example.app.fileprovider")
        A: android:exported(0x01010010)=(type 0x12)0x00000000
        A: android:permission(0x01010006)="com.example.app.PRIVATE_PROVIDER" (Raw: "com.example.app.PRIVATE_PROVIDER")
"""

RESOURCES_OUTPUT = """\
resource 0x7f130001 com.example.app:xml/network_security_config: t=0x03 d=0x00000000
resource 0x7f100002 com.example.app:string/oauth_client_id: t=0x03 d=0x00000001
resource 0x7f080003 com.example.app:drawable/logo: t=0x03 d=0x00000002
"""


def test_aapt2_metadata() -> None:
    scanner = Aapt2Scanner()

    assert scanner.scan_type is ScanType.AAPT2
    assert scanner.name == "aapt2 Evidence Extractor"
    assert "package" in scanner.description.lower()


def test_aapt2_availability(monkeypatch) -> None:
    monkeypatch.setattr(aapt2_scanner.shutil, "which", lambda _: "/sdk/aapt2")

    assert Aapt2Scanner().is_available()


def test_aapt2_scan_skips_non_apk(tmp_path: Path) -> None:
    source_file = tmp_path / "sample.ipa"
    source_file.write_bytes(b"not-an-apk")

    results = Aapt2Scanner().scan(scan_config(source_file))

    assert len(results) == 1
    assert results[0].skipped
    assert "APK" in results[0].error_message


def test_aapt2_scan_skips_when_command_missing(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    monkeypatch.setattr(aapt2_scanner.shutil, "which", lambda _: None)

    results = Aapt2Scanner().scan(scan_config(apk_path))

    assert len(results) == 1
    assert results[0].skipped
    assert "aapt2" in results[0].error_message


def test_aapt2_extracts_normalized_evidence(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    monkeypatch.setattr(aapt2_scanner.shutil, "which", lambda _: "/sdk/aapt2")
    monkeypatch.setattr(aapt2_scanner.subprocess, "run", fake_run_success)

    results = Aapt2Scanner().scan(scan_config(apk_path))
    evidence = json.loads(results[0].raw_output)
    paths = {result.relative_target_path for result in results}

    assert results[0].success
    assert results[0].relative_target_path == "aapt2_evidence.json"
    assert "metadata.json" in paths
    assert "execution_metadata.json" in paths
    assert "identity.json" in paths
    assert "permissions.json" in paths
    assert "manifest_security_posture.json" in paths
    assert "application.json" in paths
    assert "components.json" in paths
    assert "intent_filters.json" in paths
    assert "resource_summary.json" in paths
    assert "resource_candidates.json" in paths
    assert "evidence_relationships.json" in paths
    assert "candidate_interpretations.json" in paths
    assert "correlation_requirements.json" in paths
    assert "limitations.json" in paths
    assert "scan_index.json" in paths
    assert "raw/aapt2_badging_stdout.txt" in paths
    assert "raw/aapt2_xmltree_manifest_stdout.txt" in paths
    assert evidence["apk"]["package_name"] == "com.example.app"
    assert evidence["identity"]["target_sdk_version"] == "35"
    assert evidence["extraction_metadata"]["aapt2_version"] == "Android Asset Packaging Tool (aapt) 2.0"
    assert evidence["manifest_security_posture"]["exported_component_count"] == 1
    assert evidence["application"]["allow_backup"] is True
    assert evidence["application"]["network_security_config_reference"] == "@0x7f130001"
    assert any(
        permission["name"] == "android.permission.CAMERA" and permission["protection_level_hint"] == "dangerous"
        for permission in evidence["permissions"]
    )
    assert any(
        component["component_type"] == "provider" and component["name"] == "androidx.core.content.FileProvider"
        for component in evidence["components"]
    )
    assert evidence["intent_filters"][0]["uri_patterns"][0]["normalized"] == ("https://example.com/oauth/callback")
    assert evidence["intent_filters"][0]["auth_related_entrypoint_indicator"] is True
    assert any(candidate["name"] == "network_security_config" for candidate in evidence["resource_candidates"])
    assert any(
        relationship["relationship_type"] == "intent_filter_declares_uri_pattern"
        for relationship in evidence["evidence_relationships"]
    )
    assert all(candidate["not_a_finding"] for candidate in evidence["candidate_interpretations"])
    components = output_json(results, "components.json")
    scan_index = output_json(results, "scan_index.json")
    assert len(components["activities"]) == 1
    assert len(components["providers"]) == 1
    assert scan_index["command_status"]["xmltree_manifest"] == "SUCCESS"
    assert any(item["name"] == "components.json" and item["item_count"] == 2 for item in scan_index["artifacts"])


def test_aapt2_tolerates_partial_command_failure(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    monkeypatch.setattr(aapt2_scanner.shutil, "which", lambda _: "/sdk/aapt2")

    def fake_run(cmd, capture_output, text, check, timeout):
        if cmd == ["/sdk/aapt2", "version"]:
            return fake_completed(0, "aapt2 9.9\n", "")
        if cmd[:3] == ["/sdk/aapt2", "dump", "resources"]:
            return fake_completed(1, "", "resources unavailable\n")
        return fake_run_success(cmd, capture_output, text, check, timeout)

    monkeypatch.setattr(aapt2_scanner.subprocess, "run", fake_run)

    results = Aapt2Scanner().scan(scan_config(apk_path))
    evidence = json.loads(results[0].raw_output)
    paths = {result.relative_target_path for result in results}

    assert results[0].success
    assert evidence["extraction_metadata"]["execution_status"] == "PARTIAL_SUCCESS"
    assert evidence["commands"][3]["key"] == "resources"
    assert evidence["commands"][3]["execution_status"] == "PARTIAL_SUCCESS"
    assert "raw/aapt2_resources_stderr.txt" in paths
    scan_index = output_json(results, "scan_index.json")
    assert any(
        item["name"] == "resource_candidates.json" and item["partial_failure"] for item in scan_index["artifacts"]
    )


def fake_run_success(cmd, capture_output, text, check, timeout):
    if cmd == ["/sdk/aapt2", "version"]:
        return fake_completed(0, "Android Asset Packaging Tool (aapt) 2.0\n", "")
    if cmd[:3] == ["/sdk/aapt2", "dump", "badging"]:
        return fake_completed(0, BADGING_OUTPUT, "")
    if cmd[:3] == ["/sdk/aapt2", "dump", "permissions"]:
        return fake_completed(0, PERMISSIONS_OUTPUT, "")
    if cmd[:3] == ["/sdk/aapt2", "dump", "xmltree"]:
        assert cmd == [
            "/sdk/aapt2",
            "dump",
            "xmltree",
            "--file",
            "AndroidManifest.xml",
            cmd[-1],
        ]
        return fake_completed(0, XMLTREE_OUTPUT, "")
    if cmd[:3] == ["/sdk/aapt2", "dump", "resources"]:
        return fake_completed(0, RESOURCES_OUTPUT, "")
    raise AssertionError(f"unexpected command: {cmd}")


def fake_completed(returncode: int, stdout: str, stderr: str):
    return subprocess.CompletedProcess(
        args=[],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def output_json(results, relative_target_path: str):
    for result in results:
        if result.relative_target_path == relative_target_path:
            return json.loads(result.raw_output)
    raise AssertionError(f"missing output: {relative_target_path}")


def make_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex\n035\0")
    return path


def scan_config(path: Path) -> ScanConfig:
    return ScanConfig(project_path=path, output_path=path.parent / "out", mode="binary")
