from adapters.scanners.common.opengrep_scanner import validate_rule_inventory
from tests.rule_fixtures import private_rules


def test_bundled_react_native_rules_carry_the_complete_reporting_contract():
    catalog = validate_rule_inventory(private_rules("react_native")).catalog
    assert catalog
    for definition in catalog:
        metadata = definition["metadata"]
        assert not {"evidence_key", "report_section", "capability_type", "functionality_key"} & metadata.keys()
        if definition["category"] == "functionality":
            assert metadata["finding_type"] == "observation" and metadata["functionality"]
        assert "inventory_kind" not in metadata
    assert {r["category"] for r in catalog} == {"code", "crypto", "networking", "storage", "functionality"}
