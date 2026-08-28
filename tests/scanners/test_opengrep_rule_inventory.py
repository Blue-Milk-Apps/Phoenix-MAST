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
