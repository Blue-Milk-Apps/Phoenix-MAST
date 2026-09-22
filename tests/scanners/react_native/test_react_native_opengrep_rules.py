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

ROOT = Path(__file__).parents[3]
RULES_PATH = ROOT / "rules" / "react_native"
FIXTURES_PATH = Path(__file__).parent / "fixtures" / "opengrep"
OPENGREP_AVAILABLE = all(shutil.which(executable) for executable in ("opengrep", "opengrep-core"))


@pytest.mark.skipif(not RULES_PATH.is_dir(), reason="Local React Native rules are not installed")
def test_local_react_native_rule_ids_match_registry() -> None:
    assert set(OpenGrepScanner._configured_rule_ids(RULES_PATH)) == set(REACT_NATIVE_RULE_IDS)


@pytest.mark.skipif(
    not RULES_PATH.is_dir() or not OPENGREP_AVAILABLE,
    reason="Local React Native rules or both OpenGrep executables are not installed",
)
def test_react_native_rules_match_positive_fixture_and_ignore_negative_fixture() -> None:
    positive = _scan(FIXTURES_PATH / "positive.tsx")
    negative = _scan(FIXTURES_PATH / "negative.tsx")

    assert {finding["check_id"] for finding in positive["results"]} == set(REACT_NATIVE_RULE_IDS)
    assert {finding["check_id"] for finding in negative["results"]} == {
        rule_id for rule_id, key in INVENTORY_RULE_ID_TO_KEY.items() if key == "url_literal"
    }


def _scan(source_path: Path) -> dict[str, object]:
    # OpenGrep writes its diagnostic log below the process home directory.
    # Keep scanner tests isolated from a read-only or developer-specific home.
    with tempfile.TemporaryDirectory(prefix="phoenix-opengrep-home-") as home:
        environment = {**os.environ, "HOME": home}
        completed = subprocess.run(
            [
                str(shutil.which("opengrep")),
                "scan",
                "--config",
                str(RULES_PATH),
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
