from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

from adapters.scanners.android import apkid_scanner
from adapters.scanners.android.apkid_scanner import ApkidScanner
from domain.models import ScanConfig, ScanType


def test_apkid_metadata() -> None:
    scanner = ApkidScanner()

    assert scanner.scan_type is ScanType.APKID
    assert scanner.name == "APKiD Intelligence Extractor"
    assert "routing" in scanner.description.lower()


def test_apkid_availability(monkeypatch) -> None:
    monkeypatch.setattr(apkid_scanner.shutil, "which", lambda _: "/usr/bin/apkid")

    assert ApkidScanner().is_available()


def test_apkid_scan_skips_non_apk(tmp_path: Path) -> None:
    source_file = tmp_path / "sample.ipa"
    source_file.write_bytes(b"not-an-apk")

    results = ApkidScanner().scan(scan_config(source_file))

    assert len(results) == 1
    assert results[0].skipped
    assert "APK" in results[0].error_message


def test_apkid_scan_skips_when_command_missing(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    monkeypatch.setattr(apkid_scanner.shutil, "which", lambda _: None)

    results = ApkidScanner().scan(scan_config(apk_path))

    assert len(results) == 1
    assert results[0].skipped
    assert "apkid" in results[0].error_message.lower()


def test_apkid_extracts_normalized_operational_intelligence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    monkeypatch.setattr(apkid_scanner.shutil, "which", lambda _: "/usr/bin/apkid")

    def fake_run(cmd, capture_output, text, check, timeout):
        class FakeResult:
            def __init__(self, returncode: int, stdout: str, stderr: str):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        if cmd == ["/usr/bin/apkid", "--version"]:
            return FakeResult(0, "APKiD 2.1.5\n", "")
        if cmd == ["/usr/bin/apkid", "-v"]:
            return FakeResult(0, "", "")

        assert cmd[0:2] == ["/usr/bin/apkid", "-j"]
        targets = cmd[2:]
        dex_target = next(target for target in targets if target.endswith("classes.dex"))
        stdout = json.dumps(
            {
                "rules_sha256": "abc123",
                "files": [
                    {
                        "filename": str(apk_path),
                        "matches": {
                            "packer": ["Bangcle"],
                            "compiler": ["dexlib 2.x"],
                        },
                    },
                    {
                        "filename": dex_target,
                        "matches": {
                            "anti-debug": ["Debug.isDebuggerConnected"],
                            "kotlin": ["kotlin metadata"],
                        },
                    },
                ],
            }
        )
        return FakeResult(0, stdout, "")

    monkeypatch.setattr(apkid_scanner.subprocess, "run", fake_run)

    results = ApkidScanner().scan(scan_config(apk_path))
    evidence = json.loads(results[0].raw_output)

    assert results[0].success
    assert results[0].relative_target_path == "apkid_intelligence.json"
    assert evidence["schema_version"] == "1.0"
    assert evidence["extraction_metadata"]["apkid_version"] == "APKiD 2.1.5"
    assert evidence["extraction_metadata"]["rule_signature_metadata"]["rules_sha256"] == "abc123"
    assert evidence["downstream_findings"] == []
    assert evidence["raw_evidence"]["stdout"] == "raw/apkid_stdout.json"
    assert {result.relative_target_path for result in results} == {
        "apkid_intelligence.json",
        "raw/apkid_stdout.json",
    }

    detections = evidence["normalized_detections"]
    by_family = {item["family"]: item for item in detections}
    assert by_family["packer"]["signal_tier"] == "routing-critical"
    assert by_family["packer"]["priority"] == "high"
    assert "static_code_visibility_may_be_incomplete" in by_family["packer"]["analysis_impacts"]
    assert by_family["anti_debug"]["signal_tier"] == "routing-critical"
    assert by_family["compiler"]["signal_tier"] == "informational"
    assert by_family["kotlin"]["confidence_modifier"] == "contextual_enrichment_only"
    assert any(
        hint["tools"] == ["JADX", "apktool", "Androguard", "Frida", "runtime_instrumentation"]
        for hint in evidence["correlated_evidence"]["correlation_hints"]
    )


def test_apkid_timeout_is_tool_failure(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    monkeypatch.setattr(apkid_scanner.shutil, "which", lambda _: "/usr/bin/apkid")

    def fake_run(cmd, capture_output, text, check, timeout):
        if cmd == ["/usr/bin/apkid", "--version"]:

            class VersionResult:
                returncode = 0
                stdout = "APKiD 2.1.5\n"
                stderr = ""

            return VersionResult()
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(apkid_scanner.subprocess, "run", fake_run)

    results = ApkidScanner().scan(scan_config(apk_path))
    evidence = json.loads(results[0].raw_output)

    assert not results[0].success
    assert evidence["extraction_metadata"]["execution_status"] == "TIMEOUT"
    assert evidence["normalized_detections"] == []


def make_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("classes.dex", b"dex")
        archive.writestr("lib/arm64-v8a/libnative.so", b"native")
    return path


def scan_config(apk_path: Path) -> ScanConfig:
    return ScanConfig(
        project_path=apk_path,
        output_path=apk_path.parent / "scan-results",
        mode="binary",
    )
