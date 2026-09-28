from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from adapters.scanners.common.opengrep_scanner import CategoryOpenGrepScanner, validate_rule_inventory
from domain.models import ScanConfig
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

    assert {finding["check_id"] for finding in positive["results"]} == {
        rule["rule_id"] for rule in validate_rule_inventory(rules_path).catalog
    }
    assert negative["results"] == []


def _scan(rules_path: Path, source_path: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="phoenix-rule-test-") as output:
        config = ScanConfig(source_path, Path(output), opengrep_rules_path=rules_path)
        result = CategoryOpenGrepScanner(rules_path, [source_path], platform="flutter").scan(config)[0]
    assert result.success, result.error_message
    return json.loads(result.raw_output)
