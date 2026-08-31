"""Tests for conditional Flutter vulnerability-evidence report sections."""

from __future__ import annotations

import json

from adapters.post_scan.flutter import FlutterScanDetailExtractor


def test_emits_positive_evidence_from_partial_scoped_scans() -> None:
    loaded_outputs = {
        "scan_metadata": {"project_path": "/workspace/app"},
        "source_metadata": {
            "platforms": {"android": True},
            "android": {"available": True, "metadata": {}},
        },
        "opengrep": {
            "results": [
                {
                    "check_id": "flutter.source.sql-injection",
                    "phoenix_scope": "flutter",
                    "path": "/workspace/app/lib/database.dart",
                    "start": {"line": 12},
                },
                {
                    "check_id": "flutter.source.cleartext-http",
                    "phoenix_scope": "flutter",
                    "path": "/workspace/app/lib/client.dart",
                    "start": {"line": 18},
                },
                {
                    "check_id": "flutter.source.sensitive-hive-storage",
                    "phoenix_scope": "flutter",
                    "path": "/workspace/app/lib/storage.dart",
                    "start": {"line": 24},
                },
                {
                    "check_id": "android.source.unsafe-biometric-auth",
                    "phoenix_scope": "android",
                    "path": "/workspace/app/android/app/Auth.kt",
                    "start": {"line": 30},
                },
            ],
            "scan_metadata": {
                "scopes": {
                    "flutter": {"status": "failed"},
                    "android": {"status": "failed"},
                }
            },
        },
    }

    sections = FlutterScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["code_evidence"]["contains_potential_sql_injection"] == {
        "present": True,
        "evidence": "lib/database.dart:12",
        "details": ["lib/database.dart:12"],
    }
    assert sections["network_evidence"]["sensitive_information_unencrypted_in_transit"] == {
        "present": True,
        "evidence": "lib/client.dart:18",
        "details": ["lib/client.dart:18"],
    }
    assert sections["data_storage_evidence"]["sensitive_values_stored_insecurely"] == {
        "present": True,
        "evidence": "lib/storage.dart:24",
        "details": ["lib/storage.dart:24"],
    }
    assert sections["resilience_evidence"]["biometric_local_authentication_bypass_possible"] == {
        "present": True,
        "evidence": "android/app/Auth.kt:30",
        "details": ["android/app/Auth.kt:30"],
    }
    for section_name in (
        "code_evidence",
        "network_evidence",
        "data_storage_evidence",
        "resilience_evidence",
    ):
        assert "assessed" not in sections[section_name]
    json.dumps(sections)


def test_emits_clean_evidence_only_for_a_completed_relevant_rule() -> None:
    loaded_outputs = {
        "opengrep": {
            "results": [],
            "scan_metadata": {
                "scopes": {
                    "flutter": {
                        "status": "success",
                        "configured_rule_ids": ["flutter.source.sql-injection"],
                    }
                }
            },
        }
    }

    sections = FlutterScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["code_evidence"]["contains_potential_sql_injection"] == {
        "present": False,
        "evidence": "no_contains_potential_sql_injection_hits",
        "details": [],
    }
    assert "network_evidence" not in sections
    assert "data_storage_evidence" not in sections
    assert "resilience_evidence" not in sections


def test_omits_unassessed_empty_evidence_sections() -> None:
    sections = FlutterScanDetailExtractor().extract_sections({})

    assert "code_evidence" not in sections
    assert "network_evidence" not in sections
    assert "data_storage_evidence" not in sections
    assert "resilience_evidence" not in sections
