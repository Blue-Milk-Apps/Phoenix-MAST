from domain.post_scan.react_native import ReactNativeFunctionality
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext
from tests.rule_fixtures import assessment_payload, rule, scoped_payload


def _capability(rule_id, label="Camera"):
    definition = rule(rule_id, finding_type="observation")
    definition["metadata"]["functionality"] = label
    return definition


def test_javascript_findings_keep_their_actual_scope_when_native_platforms_exist():
    output = scoped_payload(
        react_native=assessment_payload(
            _capability("runtime.camera"), category="functionality", results=[{"check_id": "runtime.camera"}]
        ),
        android=assessment_payload(_capability("manifest.camera"), category="functionality"),
        ios=assessment_payload(_capability("plist.camera"), category="functionality"),
    )
    model = ReactNativeFunctionality(ReactNativeScanExtractionContext({"opengrep": output}))
    assert model.items["Camera"]["present"] is True
    rows = model.platform_assessments["Camera"]
    assert rows["react_native"]["status"] == "present"
    assert rows["android"]["status"] == rows["ios"]["status"] == "not_present"


def test_absent_mobile_platform_does_not_block_negative_results():
    output = scoped_payload(react_native=assessment_payload(_capability("customer.camera"), category="functionality"))
    model = ReactNativeFunctionality(ReactNativeScanExtractionContext({"opengrep": output}))
    assert model.items["Camera"]["present"] is False
    assert model.fully_assessed


def test_missing_functionality_sources_remain_unknown():
    model = ReactNativeFunctionality(ReactNativeScanExtractionContext({}))
    assert model.items == {}
    assert not model.assessed


def test_failed_ios_rules_do_not_imply_a_clean_capability():
    output = scoped_payload(ios=assessment_payload(_capability("camera"), category="functionality", status="failed"))
    model = ReactNativeFunctionality(ReactNativeScanExtractionContext({"opengrep": output}))
    assert model.items["Camera"]["present"] is None
    assert not model.fully_assessed


def test_customer_functionality_labels_need_no_registry():
    output = scoped_payload(
        react_native=assessment_payload(
            _capability("new.id", "Custom capability"), category="functionality", results=[{"check_id": "new.id"}]
        )
    )
    model = ReactNativeFunctionality(ReactNativeScanExtractionContext({"opengrep": output}))
    assert model.items["Custom capability"]["present"] is True


def test_older_scan_without_catalog_does_not_claim_assessment():
    output = {"results": [{"check_id": "react-native.functionality.camera"}], "scan_metadata": {"status": "success"}}
    model = ReactNativeFunctionality(ReactNativeScanExtractionContext({"opengrep": output}))
    assert model.items == {}
    assert not model.fully_assessed


def test_dependency_declarations_are_reported_from_yaml_observations():
    definition = _capability("package.navigation", "Navigation")
    definition["metadata"].update(scope="app_declaration", description="Navigation dependency declared.")
    output = scoped_payload(
        react_native=assessment_payload(
            definition, category="functionality", results=[{"check_id": "package.navigation", "path": "package.json"}]
        )
    )
    model = ReactNativeFunctionality(ReactNativeScanExtractionContext({"opengrep": output}))
    assert model.items["Navigation"] == {"present": True, "explanation": "Navigation dependency declared."}


def test_dependencies_without_rule_observations_do_not_infer_functionality():
    model = ReactNativeFunctionality(
        ReactNativeScanExtractionContext({"source_metadata": {"dependencies": {"declared": [{"name": "axios"}]}}})
    )
    assert model.items == {}
