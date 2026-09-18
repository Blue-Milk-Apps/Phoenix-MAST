from pathlib import Path

import pytest

from adapters.scanners.ios.rule_inventory import IOSRuleInventory, IOSRuleInventoryError, validate_ios_rule_inventory

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def test_default_ios_rule_inventory_matches_registry() -> None:
    inventory = validate_ios_rule_inventory(REPOSITORY_ROOT / "rules" / "ios")

    assert [(rule_file.section.value, len(rule_file.rule_ids)) for rule_file in inventory.files] == [
        ("Code", 11),
        ("Functionality", 45),
        ("Network", 2),
        ("Permissions", 13),
        ("Data Evidence", 17),
    ]


def test_inventory_rejects_duplicate_rule_ids(tmp_path: Path) -> None:
    for file_name, section in (("code.yml", "Code"), ("network.yml", "Network")):
        (tmp_path / file_name).write_text(
            f"""rules:
  - id: duplicate-rule
    metadata:
      phoenix:
        report_section: {section}
""",
            encoding="utf-8",
        )

    inventory = IOSRuleInventory.from_directory(tmp_path)
    with pytest.raises(IOSRuleInventoryError, match="duplicate rule IDs"):
        inventory.validate(expected_rule_ids={"duplicate-rule"})


def test_inventory_rejects_section_metadata_mismatch(tmp_path: Path) -> None:
    (tmp_path / "code.yml").write_text(
        """rules:
  - id: code-rule
    metadata:
      phoenix:
        report_section: Functionality
""",
        encoding="utf-8",
    )

    with pytest.raises(IOSRuleInventoryError, match="expected 'Code'"):
        IOSRuleInventory.from_directory(tmp_path)
