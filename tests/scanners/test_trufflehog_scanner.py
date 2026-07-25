import json
import plistlib
import zipfile
from pathlib import Path

from adapters.source_code_scanners import trufflehog_scanner
from adapters.source_code_scanners.trufflehog_scanner import TrufflehogScanner
from domain.models import ScanConfig, ScanType


def test_trufflehog_metadata() -> None:
    scanner = TrufflehogScanner()

    assert scanner.scan_type is ScanType.TRUFFLEHOG
    assert scanner.name == "Trufflehog Secrets Scanner"
    assert "secrets" in scanner.description


def test_trufflehog_availability(monkeypatch) -> None:
    monkeypatch.setattr(trufflehog_scanner.shutil, "which", lambda _: "/usr/local/bin/trufflehog")

    assert TrufflehogScanner().is_available()


def test_trufflehog_scan_success_returns_raw_output(monkeypatch, tmp_path, scan_config) -> None:
    config = scan_config(tmp_path)
    captured_cmd: list[str] = []

    class FakeProcess:
        returncode = 0

        def __init__(self, cmd: list[str]) -> None:
            captured_cmd.extend(cmd)

        def communicate(self) -> tuple[str, str]:
            return '{"SourceMetadata": {}}\n', "status line\n"

    monkeypatch.setattr(
        trufflehog_scanner.subprocess,
        "Popen",
        lambda cmd, *args, **kwargs: FakeProcess(cmd),
    )

    results = TrufflehogScanner().scan(config)

    assert len(results) == 1
    assert results[0].success
    assert json.loads(results[0].raw_output) == [{"SourceMetadata": {}}]
    assert results[0].relative_target_path == "trufflehog_results.json"
    assert "--only-verified" not in captured_cmd


def test_trufflehog_ios_binary_scan_uses_extracted_app_bundle_and_skips_verified_only(
    monkeypatch, tmp_path: Path
) -> None:
    ipa_path = _build_test_ipa(tmp_path / "Demo.ipa")
    config = ScanConfig(
        project_path=ipa_path,
        output_path=tmp_path / "scan-results",
        mode="binary",
        platform="IOS",
    )
    captured_cmd: list[str] = []

    class FakeProcess:
        returncode = 0

        def __init__(self, cmd: list[str]) -> None:
            captured_cmd.extend(cmd)
            assert Path(cmd[2]).is_dir()
            assert Path(cmd[2]).name == "Demo.app"

        def communicate(self) -> tuple[str, str]:
            return '{"SourceMetadata": {}}\n', ""

    monkeypatch.setattr(
        trufflehog_scanner.subprocess,
        "Popen",
        lambda cmd, *args, **kwargs: FakeProcess(cmd),
    )
    monkeypatch.setattr(trufflehog_scanner.shutil, "which", lambda _: "/usr/local/bin/trufflehog")

    results = TrufflehogScanner().scan(config)

    assert len(results) == 1
    assert results[0].success
    assert captured_cmd[2] != str(ipa_path)
    assert "--only-verified" not in captured_cmd


def _build_test_ipa(ipa_path: Path) -> Path:
    info_plist = plistlib.dumps(
        {
            "CFBundleExecutable": "Demo",
            "CFBundleIdentifier": "com.example.demo",
        }
    )
    with zipfile.ZipFile(ipa_path, "w") as archive:
        archive.writestr("Payload/Demo.app/Info.plist", info_plist)
        archive.writestr("Payload/Demo.app/Demo", b"binary")
    return ipa_path
