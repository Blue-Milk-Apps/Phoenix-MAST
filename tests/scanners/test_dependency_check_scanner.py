from pathlib import Path

from adapters.source_code_scanners import dependency_check_scanner
from adapters.source_code_scanners.dependency_check_scanner import (
    DependencyCheckScanner,
)
from domain.models import ScanType


def test_dependency_check_metadata() -> None:
    scanner = DependencyCheckScanner()

    assert scanner.scan_type is ScanType.DEPENDENCY_CHECK
    assert scanner.name == "OWASP Dependency Check Scanner"
    assert "National Vulnerability Database" in scanner.description


def test_dependency_check_availability(monkeypatch) -> None:
    # Use monkeypatch to fake the existence of the binary in PATH
    monkeypatch.setattr(
        dependency_check_scanner.shutil,
        "which",
        lambda _: "/usr/local/bin/dependency-check",
    )

    assert DependencyCheckScanner().is_available()


def test_dependency_check_scan_success(monkeypatch, tmp_path, scan_config) -> None:
    config = scan_config(tmp_path)

    class FakeProcess:
        stdout = ["Analyzing: skipped\n", "Dependency Check complete\n"]

        def __init__(self, cmd: list[str]) -> None:
            self.cmd = cmd
            self.returncode = 0

        def wait(self) -> None:
            output_dir = Path(self.cmd[self.cmd.index("--out") + 1])
            output_file = output_dir / "dependency-check-report.json"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text('{"dependencies": []}', encoding="utf-8")
            return None

    monkeypatch.setattr(
        dependency_check_scanner.subprocess,
        "Popen",
        lambda cmd, *args, **kwargs: FakeProcess(cmd),
    )

    results = DependencyCheckScanner().scan(config)

    assert len(results) == 1
    assert results[0].success
    assert results[0].raw_output == '{"dependencies": []}'
    assert results[0].relative_target_path == "dependency-check-report.json"
