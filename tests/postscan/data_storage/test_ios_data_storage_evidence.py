"""iOS rule interpretation comes from metadata, not fixed storage evidence fields."""

from domain.post_scan.ios.common.data_storage_evidence import IOSDataStorageEvidence
from domain.post_scan.rule_assessment import rule_assessments
from tests.rule_fixtures import assessment_payload, rule


def test_storage_rule_keeps_location_and_dataflow_in_persisted_assessment():
    match = {
        "check_id": "example.storage",
        "path": "Storage.swift",
        "start": {"line": 12},
        "extra": {"message": "Example storage match", "dataflow_trace": {"intermediate_vars": ["example"]}},
    }
    output = assessment_payload(rule("example.storage"), results=[match])
    item = rule_assessments(output)["rules"][0]
    assert item["status"] == "present"
    assert item["matches"] == [match]


def test_positive_storage_control_does_not_cancel_a_weakness_in_another_scope():
    output = assessment_payload(
        rule("example.control", finding_type="control"),
        rule("example.weakness"),
        results=[{"check_id": "example.control"}, {"check_id": "example.weakness"}],
    )
    items = rule_assessments(output)["rules"]
    assert [item["status"] for item in items] == ["present", "present"]
    assert [item["metadata"]["finding_type"] for item in items] == ["control", "weakness"]


def test_binary_storage_markers_remain_triage_signals():
    evidence = IOSDataStorageEvidence(
        {
            "scan_metadata": {"target_type": "BINARY"},
            "strings_outputs": {"App.txt": "auth_token\nUserDefaults\npassword\nNSLog"},
        }
    )
    assert evidence.sensitive_data_stored_in_user_defaults.present is None
    assert evidence.sensitive_data_logged_insecurely.present is None


def test_unavailable_binary_rules_do_not_claim_file_protection_was_assessed():
    evidence = IOSDataStorageEvidence({"scan_metadata": {"target_type": "BINARY"}})
    assert evidence.weak_file_protection.present is None
