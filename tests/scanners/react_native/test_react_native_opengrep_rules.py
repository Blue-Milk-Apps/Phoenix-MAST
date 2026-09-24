from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from adapters.scanners.common.opengrep_scanner import OpenGrepScanner
from domain.post_scan.react_native import INVENTORY_RULE_ID_TO_KEY, REACT_NATIVE_RULE_IDS
from tests.rule_fixtures import private_rules

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "opengrep"
OPENGREP_AVAILABLE = all(shutil.which(executable) for executable in ("opengrep", "opengrep-core"))


def test_local_react_native_rule_ids_match_registry() -> None:
    rules_path = private_rules("react_native")
    assert set(OpenGrepScanner._configured_rule_ids(rules_path)) == set(REACT_NATIVE_RULE_IDS)


@pytest.mark.skipif(
    not OPENGREP_AVAILABLE,
    reason="OpenGrep and opengrep-core are not both installed",
)
def test_react_native_rules_match_positive_fixture_and_ignore_negative_fixture() -> None:
    rules_path = private_rules("react_native")
    positive = _scan(rules_path, FIXTURES_PATH / "positive.tsx")
    negative = _scan(rules_path, FIXTURES_PATH / "negative.tsx")

    assert {finding["check_id"] for finding in positive["results"]} == set(REACT_NATIVE_RULE_IDS)
    assert {finding["check_id"] for finding in negative["results"]} == {
        rule_id for rule_id, key in INVENTORY_RULE_ID_TO_KEY.items() if key == "url_literal"
    }


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
