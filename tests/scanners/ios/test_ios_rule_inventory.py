from pathlib import Path

import pytest

from adapters.scanners.ios.rule_inventory import IOSRuleInventory, IOSRuleInventoryError, validate_ios_rule_inventory

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def test_default_ios_rule_inventory_uses_current_section_files() -> None:
    inventory = validate_ios_rule_inventory(REPOSITORY_ROOT / "rules" / "ios")

    assert [(rule_file.section.value, len(rule_file.rule_ids)) for rule_file in inventory.files] == [
        ("Code", 11),
        ("Code", 13),
        ("Functionality", 36),
        ("Network", 7),
        ("Data Evidence", 41),
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


def test_inventory_derives_section_from_file_name(tmp_path: Path) -> None:
    (tmp_path / "code.yml").write_text(
        """rules:
  - id: code-rule
""",
        encoding="utf-8",
    )

    inventory = IOSRuleInventory.from_directory(tmp_path)

    assert inventory.files[0].section.value == "Code"
