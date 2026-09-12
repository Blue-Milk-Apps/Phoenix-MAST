from pathlib import Path

from adapters.scanners.common import opengrep_scanner
from adapters.scanners.common.opengrep_scanner import OpenGrepScanner
from domain.models import ScanConfig


def test_opengrep_command_receives_one_strings_directory(tmp_path: Path, monkeypatch) -> None:
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "rule.yml").write_text("rules:\n  - id: test-rule\n", encoding="utf-8")
    strings_path = tmp_path / "scan-results" / "strings"
    strings_path.mkdir(parents=True)
    (strings_path / "classes.txt").write_text("example", encoding="utf-8")

    command: list[str] = []

    class FakeProcess:
        returncode = 0

        def __init__(self, arguments: list[str], **_kwargs: object) -> None:
            command.extend(arguments)

        def communicate(self, timeout: int) -> tuple[str, str]:
            assert timeout > 0
            return '{"results": []}', ""

    monkeypatch.setattr(opengrep_scanner.subprocess, "Popen", FakeProcess)
    scanner = OpenGrepScanner(rules_path=rules_path, scan_paths=[strings_path])
    scanner._opengrep_executable = lambda: "opengrep"  # type: ignore[method-assign]
    scanner._opengrep_core_executable = lambda: "opengrep-core"  # type: ignore[method-assign]
    scanner._tool_version = "test"

    result = scanner.scan(
        ScanConfig(
            project_path=tmp_path / "app.apk",
            output_path=tmp_path / "scan-results",
            mode="binary",
        )
    )[0]

    assert result.success is True
    assert command[4:5] == [str(strings_path.resolve())]
    assert str(strings_path / "classes.txt") not in command
