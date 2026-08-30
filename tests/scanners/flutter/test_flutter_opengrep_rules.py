from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from domain.post_scan.flutter import FLUTTER_RULE_IDS


@pytest.mark.skipif(shutil.which("opengrep") is None, reason="OpenGrep is not installed")
def test_flutter_rules_match_positive_fixture_and_ignore_negative_fixture() -> None:
    root = Path(__file__).parents[3]
    rules_path = root / "rules" / "flutter"
    fixtures = Path(__file__).parent / "fixtures" / "opengrep"

    positive = _scan(rules_path, fixtures / "positive.dart")
    negative = _scan(rules_path, fixtures / "negative.dart")

    assert {finding["check_id"] for finding in positive["results"]} == set(FLUTTER_RULE_IDS)
    assert negative["results"] == []


def _scan(rules_path: Path, source_path: Path) -> dict[str, object]:
    completed = subprocess.run(
        [
            str(shutil.which("opengrep")),
            "scan",
            "--config",
            str(rules_path),
            str(source_path),
            "--json",
            "--no-rewrite-rule-ids",
            "--no-git-ignore",
            "--disable-version-check",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    assert completed.returncode in (0, 1), completed.stderr
    return json.loads(completed.stdout)
