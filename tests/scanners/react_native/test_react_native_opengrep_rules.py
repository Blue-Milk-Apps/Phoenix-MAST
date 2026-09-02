"""Integration coverage for bundled React Native OpenGrep rules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adapters.scanners.common import OpenGrepScanner
from domain.models import ScanConfig
from domain.post_scan.react_native import REACT_NATIVE_RULE_IDS


def test_react_native_rules_match_positive_fixture_and_ignore_negative_fixture(tmp_path: Path) -> None:
    scanner = OpenGrepScanner()
    if not scanner.is_available():
        pytest.skip("OpenGrep and opengrep-core are not installed")

    root = Path(__file__).parents[3]
    rules_path = root / "rules" / "react_native"
    fixtures = Path(__file__).parent / "fixtures" / "opengrep"

    positive = _scan(rules_path, fixtures / "positive.tsx", tmp_path)
    negative = _scan(rules_path, fixtures / "negative.tsx", tmp_path)

    assert {finding["check_id"] for finding in positive["results"]} == set(REACT_NATIVE_RULE_IDS)
    assert negative["results"] == []


def _scan(rules_path: Path, source_path: Path, tmp_path: Path) -> dict[str, object]:
    config = ScanConfig(
        project_path=source_path.parent,
        output_path=tmp_path / "results",
        mode="source",
        platform="ANY",
        stack="REACT_NATIVE",
    )
    result = OpenGrepScanner(rules_path=rules_path, scan_paths=[source_path]).scan(config)[0]
    assert result.success, result.error_message
    return json.loads(result.raw_output)
