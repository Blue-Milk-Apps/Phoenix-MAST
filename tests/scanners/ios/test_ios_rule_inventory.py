from pathlib import Path

import pytest

from adapters.scanners.common.opengrep_scanner import RuleInventoryError, validate_rule_inventory
from tests.rule_fixtures import rule, write_rules


def test_categories_and_metadata_come_from_files(tmp_path: Path):
    write_rules(tmp_path / "code.yml", rule("example.code"))
    write_rules(tmp_path / "crypto.yml", rule("example.crypto", finding_type="review"))
    inventory = validate_rule_inventory(tmp_path)
    assert [(item.category, item.rule_ids) for item in inventory.files] == [
        ("code", ("example.code",)),
        ("crypto", ("example.crypto",)),
    ]
    assert inventory.catalog[1]["metadata"]["finding_type"] == "review"
    assert len(inventory.fingerprint) == 64
    assert "pattern-regex" not in inventory.catalog[0]


def test_duplicate_ids_are_rejected(tmp_path: Path):
    write_rules(tmp_path / "one.yml", rule())
    write_rules(tmp_path / "two.yml", rule())
    with pytest.raises(RuleInventoryError, match="duplicate rule IDs"):
        validate_rule_inventory(tmp_path)


@pytest.mark.parametrize(
    "field,value",
    [("finding_type", "vulnerability"), ("scope", None), ("category", "code"), ("capability_type", ["Source"])],
)
def test_invalid_metadata_is_rejected(tmp_path: Path, field, value):
    definition = rule()
    definition["metadata"][field] = value
    write_rules(tmp_path / "anything.yml", definition)
    with pytest.raises(RuleInventoryError):
        validate_rule_inventory(tmp_path)


def test_fingerprint_changes_when_metadata_changes(tmp_path: Path):
    write_rules(tmp_path / "custom.yml", rule())
    first = validate_rule_inventory(tmp_path).fingerprint
    write_rules(tmp_path / "custom.yml", rule(title="New title"))
    assert validate_rule_inventory(tmp_path).fingerprint != first


def test_missing_rule_directory_is_explicit(tmp_path: Path):
    with pytest.raises(RuleInventoryError, match="does not exist"):
        validate_rule_inventory(tmp_path / "absent")
