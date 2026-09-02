"""Tests for React Native rule and embedded-platform security evidence."""

from __future__ import annotations

from adapters.post_scan.react_native import ReactNativeScanDetailExtractor
from domain.post_scan.react_native import REACT_NATIVE_RULE_IDS


def test_maps_react_native_rule_findings_into_report_evidence() -> None:
    findings = [
        _finding("react-native.source.sql-injection", "src/database.ts", 10),
        _finding("react-native.source.weak-hash", "src/crypto.ts", 11),
        _finding("react-native.source.weak-cipher", "src/crypto.ts", 12),
        _finding("react-native.source.sensitive-log", "src/logger.ts", 13),
        _finding("react-native.source.cleartext-http", "src/api.ts", 14),
        _finding("react-native.source.disabled-tls-validation", "src/api.ts", 15),
        _finding("react-native.source.sensitive-async-storage", "src/storage.ts", 16),
    ]
    sections = ReactNativeScanDetailExtractor().extract_sections(
        {
            "scan_metadata": {"project_path": "/workspace/app", "target_type": "SOURCE"},
            "source_metadata": _source_metadata(),
            "opengrep": {
                "results": findings,
                "scan_metadata": {
                    "scopes": {
                        "react_native": {
                            "status": "success",
                            "configured_rule_ids": sorted(REACT_NATIVE_RULE_IDS),
                        }
                    }
                },
            },
        }
    )

    assert sections["code_evidence"]["contains_potential_sql_injection"]["present"] is True
    assert sections["code_evidence"]["encodes_data_using_insecure_cryptography"]["present"] is True
    assert sections["code_evidence"]["utilizes_insecure_cryptography"]["present"] is True
    assert sections["code_evidence"]["writes_sensitive_information_to_system_log"]["present"] is True
    assert sections["network_evidence"]["sensitive_information_unencrypted_in_transit"]["present"] is True
    assert sections["network_evidence"]["weak_certificate_validation_enables_mitm"]["present"] is True
    assert sections["data_storage_evidence"]["sensitive_values_stored_insecurely"]["present"] is True
    assert "src/database.ts:10" in sections["code_evidence"]["contains_potential_sql_injection"]["evidence"]


def test_successful_react_native_scope_records_configured_rules_as_not_present() -> None:
    sections = ReactNativeScanDetailExtractor().extract_sections(
        {
            "source_metadata": _source_metadata(),
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "react_native": {
                            "status": "success",
                            "configured_rule_ids": sorted(REACT_NATIVE_RULE_IDS),
                        }
                    }
                },
            },
        }
    )

    assert sections["code_evidence"]["contains_potential_sql_injection"]["present"] is False
    assert sections["network_evidence"]["sensitive_information_unencrypted_in_transit"]["present"] is False
    assert sections["data_storage_evidence"]["sensitive_values_stored_insecurely"]["present"] is False
    assert sections["resilience_evidence"]["biometric_local_authentication_bypass_possible"]["present"] is None


def test_failed_react_native_scope_does_not_produce_clean_evidence() -> None:
    sections = ReactNativeScanDetailExtractor().extract_sections(
        {
            "source_metadata": _source_metadata(),
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "react_native": {
                            "status": "failed",
                            "configured_rule_ids": sorted(REACT_NATIVE_RULE_IDS),
                        }
                    }
                },
            },
        }
    )

    assert sections["code_evidence"]["contains_potential_sql_injection"]["present"] is None
    assert sections["network_evidence"]["sensitive_information_unencrypted_in_transit"]["present"] is None
    assert sections["data_storage_evidence"]["sensitive_values_stored_insecurely"]["present"] is None


def _finding(rule_id: str, path: str, line: int) -> dict[str, object]:
    return {
        "check_id": rule_id,
        "phoenix_scope": "react_native",
        "path": path,
        "start": {"line": line},
        "extra": {"message": "fixture finding"},
    }


def _source_metadata() -> dict[str, object]:
    return {
        "platforms": {"android": False, "ios": False},
        "android": {"available": False, "metadata": None},
        "ios": {"available": False, "metadata": None},
    }
