from __future__ import annotations

import json
from pathlib import Path

from adapters.scanners.common.opengrep_scanner import OpenGrepScanner


def test_opengrep_report_records_exact_configured_rule_ids(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules"
    rules_path.mkdir()
    (rules_path / "one.yml").write_text(
        "rules:\n  - id: first.rule\n    message: first\n",
        encoding="utf-8",
    )
    nested = rules_path / "nested"
    nested.mkdir()
    (nested / "two.yaml").write_text(
        "rules:\n  - id: 'second.rule'\n    message: second\n",
        encoding="utf-8",
    )
    (rules_path / "ignored.txt").write_text("  - id: ignored.rule\n", encoding="utf-8")

    report = json.loads(OpenGrepScanner()._report('{"results": []}', rules_path, [tmp_path]))

    assert report["scan_metadata"]["configured_rule_ids"] == ["first.rule", "second.rule"]


def test_metadata_compliance_ids_are_not_rule_ids(tmp_path):
    from tests.rule_fixtures import rule, write_rules

    write_rules(tmp_path / "code.yml", rule("example.only-rule"))
    assert OpenGrepScanner._configured_rule_ids(tmp_path) == ["example.only-rule"]


def test_multiple_rule_directories_reject_duplicate_ids(tmp_path):
    import pytest

    from tests.rule_fixtures import rule, write_rules

    write_rules(tmp_path / "one" / "code.yml", rule())
    write_rules(tmp_path / "two" / "storage.yml", rule())
    with pytest.raises(ValueError, match="Duplicate rule id"):
        OpenGrepScanner._configured_rule_ids([tmp_path / "one", tmp_path / "two"])


def test_multiple_configs_are_passed_to_opengrep(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from adapters.scanners.common import opengrep_scanner as module
    from domain.models import ScanConfig
    from tests.rule_fixtures import rule, write_rules

    paths = [tmp_path / "one", tmp_path / "two"]
    for index, path in enumerate(paths):
        write_rules(path / "code.yml", rule(f"example.{index}"))
    commands = []

    def start(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, communicate=lambda **kwargs: ('{"results": [], "errors": []}', ""))

    monkeypatch.setattr(module.subprocess, "Popen", start)
    monkeypatch.setattr(OpenGrepScanner, "_opengrep_executable", lambda self: "opengrep")
    monkeypatch.setattr(OpenGrepScanner, "_opengrep_core_executable", lambda self: "opengrep-core")
    monkeypatch.setattr(OpenGrepScanner, "_opengrep_version", lambda self: "test")
    result = OpenGrepScanner(rules_paths=paths).scan(ScanConfig(tmp_path, tmp_path / "out"))[0]
    assert result.success
    command = commands[0]
    assert [command[i + 1] for i, value in enumerate(command) if value == "--config"] == [str(path) for path in paths]
    assert json.loads(result.raw_output)["scan_metadata"]["configured_rule_ids"] == ["example.0", "example.1"]


def test_malformed_output_cannot_be_reported_as_a_clean_scan(monkeypatch, tmp_path):
    from tests.rule_fixtures import write_rules

    write_rules(tmp_path / "code.yml")
    monkeypatch.setattr(OpenGrepScanner, "_opengrep_version", lambda self: "test")
    for raw in ("", "not json", '{"version": "test"}'):
        output = json.loads(OpenGrepScanner()._report(raw, tmp_path, [tmp_path]))
        assert output["success"] is False
        assert output["errors"]
