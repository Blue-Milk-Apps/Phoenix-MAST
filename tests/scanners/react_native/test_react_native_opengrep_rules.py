from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest
import yaml

from adapters.scanners.common.opengrep_scanner import CategoryOpenGrepScanner, validate_rule_inventory
from domain.models import ScanConfig
from tests.rule_fixtures import private_rules

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "opengrep"
OPENGREP_AVAILABLE = all(shutil.which(executable) for executable in ("opengrep", "opengrep-core"))


def test_local_react_native_rule_ids_match_registry() -> None:
    rules_path = private_rules("react_native")
    catalog = validate_rule_inventory(rules_path).catalog
    assert catalog and len({item["rule_id"] for item in catalog}) == len(catalog)


@pytest.mark.skipif(
    not OPENGREP_AVAILABLE,
    reason="OpenGrep and opengrep-core are not both installed",
)
def test_react_native_rules_match_positive_fixture_and_ignore_negative_fixture() -> None:
    rules_path = private_rules("react_native")
    positive = _scan(rules_path, FIXTURES_PATH / "positive.tsx")
    negative = _scan(rules_path, FIXTURES_PATH / "negative.tsx")

    assert {finding["check_id"] for finding in positive["results"]} == {
        rule["id"]
        for path in rules_path.glob("*.yml")
        for rule in yaml.safe_load(path.read_text())["rules"]
        if "json" not in rule["languages"]
    }
    assert negative["results"] == []


def _scan(rules_path: Path, source_path: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="phoenix-rule-test-") as output:
        config = ScanConfig(source_path, Path(output), opengrep_rules_path=rules_path)
        result = CategoryOpenGrepScanner(rules_path, [source_path], platform="react_native").scan(config)[0]
    assert result.success, result.error_message
    return json.loads(result.raw_output)
