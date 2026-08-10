import plistlib
import zipfile
from pathlib import Path

from adapters.scanners.common import gitleaks_scanner
from adapters.scanners.common.gitleaks_scanner import GitleaksScanner
from domain.models import ScanConfig, ScanType


def test_gitleaks_metadata() -> None:
    scanner = GitleaksScanner()

    assert scanner.scan_type is ScanType.GITLEAKS
    assert scanner.name == "Gitleaks Secrets Scanner"
    assert "secrets" in scanner.description


def test_gitleaks_availability(monkeypatch) -> None:
    monkeypatch.setattr(gitleaks_scanner.shutil, "which", lambda _: "/usr/local/bin/gitleaks")

    assert GitleaksScanner().is_available()


def test_gitleaks_scan_success_returns_raw_output(monkeypatch, tmp_path: Path, scan_config) -> None:
    config = scan_config(tmp_path)
    (config.project_path / ".gitleaks.toml").write_text("title = 'test'\n")

    monkeypatch.setattr(gitleaks_scanner.shutil, "which", lambda _: "/usr/local/bin/gitleaks")
    captured_cmd = []

    class FakeProcess:
        def __init__(self, cmd: list[str]) -> None:
            captured_cmd.extend(cmd)
            self.cmd = cmd
            self.returncode = 0

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            return "[]", ""

        def kill(self) -> None:
            return None

    monkeypatch.setattr(
        gitleaks_scanner.subprocess,
        "Popen",
        lambda cmd, *args, **kwargs: FakeProcess(cmd),
    )

    results = GitleaksScanner().scan(config)

    assert len(results) == 1
    assert results[0].success
    assert results[0].raw_output == "[]"
    assert results[0].relative_target_path == "gitleaks_report.json"
    assert captured_cmd[captured_cmd.index("--report-path") + 1] == "-"


def test_gitleaks_scan_reports_findings(monkeypatch, tmp_path: Path, scan_config) -> None:
    config = scan_config(tmp_path)
    (config.project_path / ".gitleaks.toml").write_text("title = 'test'\n")

    monkeypatch.setattr(gitleaks_scanner.shutil, "which", lambda _: "/usr/local/bin/gitleaks")

    class FakeProcess:
        def __init__(self, cmd: list[str]) -> None:
            self.cmd = cmd
            self.returncode = 1

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            return (
                '[{"RuleID":"custom-api-key","Description":"API key found","File":"app.py","StartLine":12,"EndLine":14}]',
                "",
            )

        def kill(self) -> None:
            return None

    monkeypatch.setattr(
        gitleaks_scanner.subprocess,
        "Popen",
        lambda cmd, *args, **kwargs: FakeProcess(cmd),
    )

    results = GitleaksScanner().scan(config)

    assert len(results) == 1
    assert results[0].success
    assert results[0].raw_output.startswith("[")
    assert results[0].relative_target_path == "gitleaks_report.json"


def test_gitleaks_ios_binary_scan_uses_extracted_app_bundle(monkeypatch, tmp_path: Path) -> None:
    ipa_path = _build_test_ipa(tmp_path / "Demo.ipa")
    config = ScanConfig(
        project_path=ipa_path,
        output_path=tmp_path / "scan-results",
        mode="binary",
        platform="IOS",
    )

    monkeypatch.setattr(gitleaks_scanner.shutil, "which", lambda _: "/usr/local/bin/gitleaks")
    captured_cmd: list[str] = []

    class FakeProcess:
        def __init__(self, cmd: list[str]) -> None:
            captured_cmd.extend(cmd)
            self.returncode = 0
            assert Path(cmd[-1]).is_dir()
            assert Path(cmd[-1]).name == "Demo.app"

        def communicate(self, timeout: int | None = None) -> tuple[str, str]:
            return "[]", ""

        def kill(self) -> None:
            return None

    monkeypatch.setattr(
        gitleaks_scanner.subprocess,
        "Popen",
        lambda cmd, *args, **kwargs: FakeProcess(cmd),
    )

    results = GitleaksScanner().scan(config)

    assert len(results) == 1
    assert results[0].success
    assert captured_cmd[-1] != str(ipa_path)


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
