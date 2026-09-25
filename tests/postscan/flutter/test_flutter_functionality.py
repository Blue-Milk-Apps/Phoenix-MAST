from domain.post_scan.flutter import FlutterFunctionality, FlutterScanExtractionContext
from tests.rule_fixtures import assessment_payload, rule, scoped_payload


def _capability(rule_id, name="Camera"):
    definition = rule(rule_id, finding_type="observation", severity="INFO")
    definition["metadata"]["functionality"] = name
    return definition


def test_combines_scoped_yaml_capabilities_and_preserves_platform_evidence():
    output = scoped_payload(
        android=assessment_payload(
            _capability("customer.camera"),
            category="functionality",
            results=[{"check_id": "customer.camera", "path": "android/AndroidManifest.xml"}],
        ),
        ios=assessment_payload(_capability("other.camera"), category="functionality"),
    )
    model = FlutterFunctionality(FlutterScanExtractionContext({"opengrep": output}))
    assert model.items["Camera"]["present"] is True
    assert model.platform_assessments["Camera"]["android"]["status"] == "present"
    assert model.platform_assessments["Camera"]["ios"]["status"] == "not_present"
    assert model.platform_assessments["Camera"]["android"]["evidence"] == ["android/AndroidManifest.xml"]
    assert model.fully_assessed


def test_incomplete_rules_cannot_establish_functionality_absence():
    output = scoped_payload(
        android=assessment_payload(_capability("new.camera"), category="functionality", status="failed")
    )
    model = FlutterFunctionality(FlutterScanExtractionContext({"opengrep": output}))
    assert model.items["Camera"]["present"] is None
    assert not model.fully_assessed


def test_missing_catalog_does_not_invent_capabilities_from_metadata():
    model = FlutterFunctionality(
        FlutterScanExtractionContext(
            {"source_metadata": {"android": {"metadata": {"permissions": [{"name": "android.permission.CAMERA"}]}}}}
        )
    )
    assert model.items == {}
    assert not model.assessed
