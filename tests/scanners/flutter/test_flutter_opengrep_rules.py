from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from domain.post_scan.flutter import FLUTTER_RULE_IDS
from tests.rule_fixtures import private_rules

OPENGREP_AVAILABLE = all(shutil.which(executable) for executable in ("opengrep", "opengrep-core"))


@pytest.mark.skipif(
    not OPENGREP_AVAILABLE,
    reason="OpenGrep and opengrep-core are not both installed",
)
def test_flutter_rules_match_positive_fixture_and_ignore_negative_fixture() -> None:
    rules_path = private_rules("flutter")
    fixtures = Path(__file__).parent / "fixtures" / "opengrep"

    positive = _scan(rules_path, fixtures / "positive.dart")
    negative = _scan(rules_path, fixtures / "negative.dart")

    assert {finding["check_id"] for finding in positive["results"]} == set(FLUTTER_RULE_IDS)
    assert negative["results"] == []


def _scan(rules_path: Path, source_path: Path) -> dict[str, object]:
    # OpenGrep writes its diagnostic log below the process home directory.
    # Keep scanner tests isolated from a read-only or developer-specific home.
    with tempfile.TemporaryDirectory(prefix="phoenix-opengrep-home-") as home:
        environment = {**os.environ, "HOME": home}
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
            env=environment,
        )
    assert completed.returncode in (0, 1), completed.stderr
    return json.loads(completed.stdout)
