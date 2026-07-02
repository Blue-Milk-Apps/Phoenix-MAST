from __future__ import annotations

import json
import subprocess
import zipfile
from pathlib import Path

from adapters.binary_scanners import apksigner_scanner
from adapters.binary_scanners.apksigner_scanner import ApksignerScanner
from domain.models import ScanConfig, ScanType

VERIFIED_OUTPUT = """\
Verifies
Verified using v1 scheme (JAR signing): true
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): false
Verified using v4 scheme (APK Signature Scheme v4): false
Number of signers: 1
Signer #1 certificate DN: CN=AppcritIQ,O=Blue Milk Apps,C=US
Signer #1 certificate SHA-256 digest: aa:bb:cc
Signer #1 certificate SHA-1 digest: 11:22:33
Signer #1 certificate MD5 digest: de:ad:be:ef
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
Signer #1 public key SHA-256 digest: 44:55:66
"""


def test_apksigner_metadata() -> None:
    scanner = ApksignerScanner()

    assert scanner.scan_type is ScanType.APKSIGNER
    assert scanner.name == "Apksigner Evidence Extractor"
    assert "signing" in scanner.description.lower()


def test_apksigner_availability(monkeypatch) -> None:
    monkeypatch.setattr(
        apksigner_scanner.shutil,
        "which",
        lambda _: "/usr/local/bin/apksigner",
    )

    assert ApksignerScanner().is_available()


def test_apksigner_scan_skips_non_apk(tmp_path: Path) -> None:
    source_file = tmp_path / "sample.ipa"
    source_file.write_bytes(b"not-an-apk")
    config = scan_config(source_file)

    results = ApksignerScanner().scan(config)

    assert len(results) == 1
    assert results[0].skipped
    assert "APK" in results[0].error_message


def test_apksigner_scan_skips_when_command_missing(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    config = scan_config(apk_path)
    monkeypatch.setattr(apksigner_scanner.shutil, "which", lambda _: None)

    results = ApksignerScanner().scan(config)

    assert len(results) == 1
    assert results[0].skipped
    assert "apksigner" in results[0].error_message


def test_apksigner_verified_apk_extracts_signing_evidence(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    config = scan_config(apk_path)
    monkeypatch.setattr(
        apksigner_scanner.shutil,
        "which",
        lambda command: "/usr/local/bin/apksigner" if command == "apksigner" else None,
    )

    def fake_run(cmd, capture_output, text, check, timeout):
        class FakeResult:
            def __init__(self, returncode: int, stdout: str, stderr: str):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        if cmd == ["/usr/local/bin/apksigner", "version"]:
            return FakeResult(0, "0.9\n", "")
        assert cmd[:4] == [
            "/usr/local/bin/apksigner",
            "verify",
            "--verbose",
            "--print-certs",
        ]
        return FakeResult(0, VERIFIED_OUTPUT, "")

    monkeypatch.setattr(apksigner_scanner.subprocess, "run", fake_run)

    results = ApksignerScanner().scan(config)
    evidence = json.loads(results[0].raw_output)

    assert results[0].relative_target_path == "signing_evidence.json"
    assert results[0].success
    assert evidence["schema_version"] == "1.0"
    assert evidence["extraction_metadata"]["apksigner_version"] == "0.9"
    assert evidence["verification"]["overall_status"] == "VERIFIED"
    assert evidence["signature_schemes"]["v1"]["state"] == "VERIFIED"
    assert evidence["signature_schemes"]["v3"]["state"] == "MISSING"
    assert evidence["signers"][0]["certificate"]["subject_dn"] == ("CN=AppcritIQ,O=Blue Milk Apps,C=US")
    assert evidence["signers"][0]["certificate"]["sha256"] == "AABBCC"
    assert evidence["signers"][0]["certificate"]["public_key_algorithm"] == "RSA"
    assert evidence["signers"][0]["certificate"]["public_key_size_bits"] == 2048
    assert evidence["enrichment"]["signer_classification"] == "UNKNOWN"
    assert evidence["raw_evidence"]["stdout"] == "raw/apksigner_verify_stdout.txt"
    assert {result.relative_target_path for result in results} == {
        "signing_evidence.json",
        "raw/apksigner_verify_stdout.txt",
    }


def test_apksigner_verification_failure_is_evidence_success(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    config = scan_config(apk_path)
    monkeypatch.setattr(apksigner_scanner.shutil, "which", lambda _: "/bin/apksigner")

    def fake_run(cmd, capture_output, text, check, timeout):
        class FakeResult:
            returncode = 1
            stdout = ""
            stderr = "DOES NOT VERIFY\n"

        if cmd == ["/bin/apksigner", "version"]:
            FakeResult.returncode = 0
            FakeResult.stdout = "0.9\n"
            FakeResult.stderr = ""
        return FakeResult()

    monkeypatch.setattr(apksigner_scanner.subprocess, "run", fake_run)

    results = ApksignerScanner().scan(config)
    evidence = json.loads(results[0].raw_output)

    assert results[0].success
    assert evidence["verification"]["overall_status"] == "FAILED"
    assert evidence["extraction_metadata"]["execution_status"] == "PARTIAL_SUCCESS"
    assert evidence["raw_evidence"]["stderr"] == "raw/apksigner_verify_stderr.txt"


def test_apksigner_timeout_is_tool_failure(monkeypatch, tmp_path: Path) -> None:
    apk_path = make_apk(tmp_path / "sample.apk")
    config = scan_config(apk_path)
    monkeypatch.setattr(apksigner_scanner.shutil, "which", lambda _: "/bin/apksigner")

    def fake_run(cmd, capture_output, text, check, timeout):
        if cmd == ["/bin/apksigner", "version"]:

            class VersionResult:
                returncode = 0
                stdout = "0.9\n"
                stderr = ""

            return VersionResult()
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(apksigner_scanner.subprocess, "run", fake_run)

    results = ApksignerScanner().scan(config)
    evidence = json.loads(results[0].raw_output)

    assert not results[0].success
    assert evidence["extraction_metadata"]["execution_status"] == "TIMEOUT"
    assert evidence["verification"]["overall_status"] == "TOOL_ERROR"


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
