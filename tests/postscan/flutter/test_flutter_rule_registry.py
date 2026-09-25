from adapters.scanners.common.opengrep_scanner import validate_rule_inventory
from tests.rule_fixtures import private_rules


def test_bundled_flutter_rules_carry_the_complete_reporting_contract():
    catalog = validate_rule_inventory(private_rules("flutter")).catalog
    assert catalog
    assert {r["category"] for r in catalog} == {"code", "crypto", "networking", "storage"}
    for definition in catalog:
        assert not {"evidence_key", "report_section", "capability_type"} & definition["metadata"].keys()
    channel = next(r for r in catalog if r["rule_id"] == "flutter.source.unsafe-platform-channel")
    assert channel["metadata"]["finding_type"] == "review"
