from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

import pytest

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


@pytest.mark.parametrize("output_format", ["document", "stream", "pretty_stream", "list", "truncated", "scalar_tail"])
def test_apkid_extracts_normalized_operational_intelligence(
    monkeypatch,
    tmp_path: Path,
    output_format: str,
) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    monkeypatch.setattr(apkid_scanner.shutil, "which", lambda _: "/usr/bin/apkid")
    commands = []

    def fake_run(cmd, capture_output, text, check, timeout):
        class FakeResult:
            def __init__(self, returncode: int, stdout: str, stderr: str):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        commands.append(cmd)
        assert cmd[0:2] == ["/usr/bin/apkid", "-j"]
        targets = cmd[2:]
        dex_target = next(target for target in targets if target.endswith("classes.dex"))
        stdout = json.dumps(
            {
                "apkid_version": "3.1.0",
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
        payload = json.loads(stdout)
        if output_format == "list":
            stdout = json.dumps(payload["files"])
        elif output_format != "document":
            stdout = "\n\n".join(
                json.dumps({**payload, "files": [record]}, indent=2 if output_format == "pretty_stream" else None)
                for record in payload["files"]
            )
            if output_format == "truncated":
                stdout += '\n{"files": ['
            elif output_format == "scalar_tail":
                stdout += "\n42"
        stdout = " \n" + stdout + "\n\t"
        return FakeResult(0, stdout, "")

    monkeypatch.setattr(apkid_scanner.subprocess, "run", fake_run)

    results = ApkidScanner().scan(scan_config(apk_path))
    evidence = json.loads(results[0].raw_output)

    malformed = output_format in {"truncated", "scalar_tail"}
    assert results[0].success is not malformed
    assert len(commands) == 1
    assert evidence["extraction_metadata"]["execution_status"] == ("PARSING_ERROR" if malformed else "SUCCESS")
    assert bool(evidence["extraction_metadata"]["parser_errors"]) is malformed
    if malformed:
        assert "APKiD JSON" in results[0].error_message
    assert results[0].relative_target_path == "apkid_intelligence.json"
    assert evidence["schema_version"] == "1.0"
    assert evidence["extraction_metadata"]["apkid_version"] == ("" if output_format == "list" else "3.1.0")
    assert evidence["extraction_metadata"]["signature_metadata"]["rules_sha256"] == (
        None if output_format == "list" else "abc123"
    )
    assert evidence["downstream_findings"] == []
    assert evidence["raw_evidence"]["stdout"] == "raw/apkid_stdout.json"
    assert {result.relative_target_path for result in results} == {
        "apkid_intelligence.json",
        "raw/apkid_stdout.json",
    }

    detections = evidence["normalized_detections"]
    assert len(detections) == 4
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


@pytest.mark.parametrize("output", [None, b'{"files": []}\n{"files": [', '{"files": []}'])
def test_apkid_timeout_is_tool_failure(monkeypatch, tmp_path: Path, output: str | bytes | None) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    monkeypatch.setattr(apkid_scanner.shutil, "which", lambda _: "/usr/bin/apkid")

    def fake_run(cmd, capture_output, text, check, timeout):
        raise subprocess.TimeoutExpired(cmd, timeout, output=output, stderr=b"tool interrupted")

    monkeypatch.setattr(apkid_scanner.subprocess, "run", fake_run)

    results = ApkidScanner().scan(scan_config(apk_path))
    evidence = json.loads(results[0].raw_output)

    assert not results[0].success
    assert evidence["extraction_metadata"]["execution_status"] == "TIMEOUT"
    assert evidence["normalized_detections"] == []
    assert results[-1].raw_output == "tool interrupted"


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
