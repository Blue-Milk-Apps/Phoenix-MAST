from __future__ import annotations

import json
import zipfile
from pathlib import Path

from adapters.scanners.android import apktool_scanner
from adapters.scanners.android.apktool_scanner import ApktoolScanner
from domain.models import ScanConfig, ScanType


def test_apktool_metadata() -> None:
    scanner = ApktoolScanner()

    assert scanner.scan_type is ScanType.APKTOOL
    assert scanner.name == "Apktool Evidence Extractor"
    assert "android security evidence" in scanner.description.lower()


def test_apktool_availability(monkeypatch) -> None:
    monkeypatch.setattr(apktool_scanner.shutil, "which", lambda _: "/usr/bin/apktool")

    assert ApktoolScanner().is_available()


def test_apktool_scan_skips_non_apk(tmp_path: Path) -> None:
    source_file = tmp_path / "sample.ipa"
    source_file.write_bytes(b"not-an-apk")
    config = ScanConfig(
        project_path=source_file,
        output_path=tmp_path / "scan-results",
        mode="binary",
    )

    results = ApktoolScanner().scan(config)

    assert len(results) == 1
    assert results[0].skipped
    assert "APK" in results[0].error_message


def test_apktool_scan_skips_when_command_missing(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    config = scan_config(apk_path)
    monkeypatch.setattr(apktool_scanner.shutil, "which", lambda _: None)

    results = ApktoolScanner().scan(config)

    assert len(results) == 1
    assert results[0].skipped
    assert "apktool" in results[0].error_message


def test_apktool_partial_decode_extracts_normalized_evidence(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    work_dir = tmp_path / "apktool-work"
    config = scan_config(apk_path)

    monkeypatch.setattr(
        apktool_scanner.tempfile,
        "mkdtemp",
        lambda prefix: str(work_dir),
    )
    monkeypatch.setattr(
        apktool_scanner.shutil,
        "which",
        lambda command: "/usr/bin/apktool" if command == "apktool" else None,
    )

    def fake_run(cmd, capture_output, text, check, timeout):
        class FakeResult:
            def __init__(self, returncode: int, stdout: str, stderr: str):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        if cmd == ["/usr/bin/apktool", "--version"]:
            return FakeResult(0, "2.10.0\n", "")

        assert cmd[:3] == ["/usr/bin/apktool", "d", "-f"]
        assert "--no-src" not in cmd
        decoded_root = Path(cmd[cmd.index("-o") + 1])
        write_decoded_apk(decoded_root)
        return FakeResult(1, "decode warning\n", "partial decode\n")

    monkeypatch.setattr(apktool_scanner.subprocess, "run", fake_run)

    results = ApktoolScanner().scan(config)

    artifacts = {result.relative_target_path: json.loads(result.raw_output) for result in results}
    assert all(result.success for result in results)
    assert artifacts["decode_metadata.json"]["partial_success"] is True
    assert artifacts["decode_metadata.json"]["apktool_version"] == "2.10.0"
    assert "AndroidManifest.xml" in artifacts["decode_metadata.json"]["decoded_files_used"]
    assert artifacts["manifest_summary.json"]["target_sdk"] == "22"
    assert {item["value"] for item in artifacts["permissions.json"]["requested"]} == {
        "android.permission.INTERNET",
        "android.permission.READ_PHONE_STATE",
    }
    assert artifacts["attack_surface.json"]["components"][0]["context"]["exported"] == "true"
    assert artifacts["deep_links.json"]["deep_links"][0]["context"]["host"] == "example.com"
    assert artifacts["network_security_config.json"]["domains"][0]["domains"][0]["value"] == "api.example.com"
    assert artifacts["network_security_config.json"]["target_sdk"] == "22"
    assert artifacts["code_indicators.json"]["items"][0]["provenance"]["path"].endswith(".smali")
    assert artifacts["secrets_endpoints.json"]["items"]
    assert artifacts["native_libraries.json"]["libraries"][0]["abi"] == "arm64-v8a"
    assert artifacts["assets_inventory.json"]["assets"][0]["path"] == "assets/config.json"
    assert not work_dir.exists()


def test_apktool_network_policy_explains_missing_config(tmp_path: Path) -> None:
    decoded_root = tmp_path / "decoded"
    decoded_root.mkdir()
    (decoded_root / "AndroidManifest.xml").write_text(
        """\
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
  <application />
</manifest>
""",
        encoding="utf-8",
    )
    (decoded_root / "apktool.yml").write_text(
        """\
sdkInfo:
  targetSdkVersion: 22
""",
        encoding="utf-8",
    )

    evidence = ApktoolScanner()._extract_network_security_config(decoded_root)

    assert evidence["config_file_present"] is False
    assert evidence["effective_cleartext_traffic_default"] == "true"
    assert evidence["policy_source"] == "manifest_default_no_network_security_config"


def make_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")
    return path


def scan_config(apk_path: Path) -> ScanConfig:
    return ScanConfig(
        project_path=apk_path,
        output_path=apk_path.parent / "scan-results",
        mode="binary",
    )


def write_decoded_apk(decoded_root: Path) -> None:
    decoded_root.mkdir(parents=True)
    (decoded_root / "AndroidManifest.xml").write_text(
        """\
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app"
    android:versionCode="7"
    android:versionName="1.2.3">
  <uses-permission android:name="android.permission.INTERNET" />
  <android:uses-permission android:name="android.permission.READ_PHONE_STATE" />
  <permission
      android:name="com.example.PRIVATE"
      android:protectionLevel="signature" />
  <application
      android:debuggable="false"
      android:allowBackup="false"
      android:usesCleartextTraffic="false"
      android:networkSecurityConfig="@xml/network_security_config">
    <activity android:name="com.example.DeepLinkActivity" android:exported="true">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="example.com" android:pathPrefix="/login" />
      </intent-filter>
    </activity>
  </application>
</manifest>
""",
        encoding="utf-8",
    )
    (decoded_root / "apktool.yml").write_text(
        """\
version: 3.0.2
sdkInfo:
  minSdkVersion: 15
  targetSdkVersion: 22
versionInfo:
  versionCode: 1
  versionName: 1.0
""",
        encoding="utf-8",
    )
    network_config = decoded_root / "res" / "xml" / "network_security_config.xml"
    network_config.parent.mkdir(parents=True)
    network_config.write_text(
        """\
<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain includeSubdomains="true">api.example.com</domain>
    <trust-anchors>
      <certificates src="@raw/prod_ca" />
    </trust-anchors>
  </domain-config>
</network-security-config>
""",
        encoding="utf-8",
    )
    smali_file = decoded_root / "smali" / "com" / "example" / "DeepLinkActivity.smali"
    smali_file.parent.mkdir(parents=True)
    smali_file.write_text(
        """\
.class public Lcom/example/DeepLinkActivity;
.method public configure()V
    invoke-virtual {p0}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    const-string v0, "https://api.example.com/auth?token=abc"
.end method
""",
        encoding="utf-8",
    )
    asset = decoded_root / "assets" / "config.json"
    asset.parent.mkdir(parents=True)
    asset.write_text('{"endpoint": "https://api.example.com"}', encoding="utf-8")
    native_lib = decoded_root / "lib" / "arm64-v8a" / "libnative.so"
    native_lib.parent.mkdir(parents=True)
    native_lib.write_bytes(b"native")
