"""Tests for OpenGrep command construction."""

from __future__ import annotations

from pathlib import Path

from adapters.scanners.common import OpenGrepScanner
from domain.models import ScanConfig


class _CompletedProcess:
    returncode = 0

    def communicate(self, timeout: int) -> tuple[str, str]:
        assert timeout > 0
        return '{"results": [], "errors": []}', ""

    def kill(self) -> None:
        pass


def test_source_scan_sets_selected_project_as_opengrep_project_root(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "src"
    source.mkdir()
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rules.yml").write_text("rules: []\n", encoding="utf-8")
    commands: list[list[str]] = []

    scanner = OpenGrepScanner(rules_path=rules, scan_paths=[source])
    monkeypatch.setattr(scanner, "_opengrep_executable", lambda: "opengrep")
    monkeypatch.setattr(scanner, "_opengrep_core_executable", lambda: "opengrep-core")
    monkeypatch.setattr(scanner, "_tool_version", "test-version")
    monkeypatch.setattr(
        "adapters.scanners.common.opengrep_scanner.subprocess.Popen",
        lambda command, **kwargs: commands.append(command) or _CompletedProcess(),
    )

    result = scanner.scan(
        ScanConfig(
            project_path=project,
            output_path=tmp_path / "results",
            mode="source",
            platform="ANY",
            stack="REACT_NATIVE",
        )
    )[0]

    assert result.success is True
    assert "--experimental" in commands[0]
    root_option = commands[0].index("--project-root")
    assert commands[0][root_option + 1] == str(project.resolve())


def test_binary_scan_does_not_set_source_project_root(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "app.apk"
    binary.write_bytes(b"fixture")
    scan_path = tmp_path / "strings"
    scan_path.mkdir()
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rules.yml").write_text("rules: []\n", encoding="utf-8")
    commands: list[list[str]] = []

    scanner = OpenGrepScanner(rules_path=rules, scan_paths=[scan_path])
    monkeypatch.setattr(scanner, "_opengrep_executable", lambda: "opengrep")
    monkeypatch.setattr(scanner, "_opengrep_core_executable", lambda: "opengrep-core")
    monkeypatch.setattr(scanner, "_tool_version", "test-version")
    monkeypatch.setattr(
        "adapters.scanners.common.opengrep_scanner.subprocess.Popen",
        lambda command, **kwargs: commands.append(command) or _CompletedProcess(),
    )

    result = scanner.scan(
        ScanConfig(
            project_path=binary,
            output_path=tmp_path / "results",
            mode="binary",
            platform="ANDROID",
        )
    )[0]

    assert result.success is True
    assert "--project-root" not in commands[0]
