"""Tests for shared Flutter security-evidence helpers."""

from __future__ import annotations

from domain.post_scan.flutter import (
    FlutterEvidenceEntry,
    FlutterScanExtractionContext,
    combine_evidence_entries,
    optional_bool_entry,
    scoped_opengrep_entry,
)


def test_scoped_opengrep_entry_isolates_scope_and_normalizes_evidence() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/app"},
            "opengrep": {
                "results": [
                    {
                        "check_id": "flutter.source.cleartext-http",
                        "phoenix_scope": "flutter",
                        "path": "/workspace/app/lib/client.dart",
                        "start": {"line": 12},
                        "extra": {"message": "Cleartext request"},
                    },
                    {
                        "check_id": "android.source.cleartext-http",
                        "phoenix_scope": "android",
                        "path": "/workspace/app/android/Client.kt",
                        "start": {"line": 8},
                        "extra": {"message": "Android cleartext request"},
                    },
                ],
                "scan_metadata": {
                    "scopes": {
                        "flutter": {
                            "status": "success",
                            "configured_rule_ids": ["flutter.source.cleartext-http"],
                        },
                        "android": {
                            "status": "success",
                            "configured_rule_ids": ["android.source.cleartext-http"],
                        },
                    }
                },
            },
        }
    )

    entry = scoped_opengrep_entry(
        context,
        scope="flutter",
        rule_ids=frozenset({"flutter.source.cleartext-http"}),
        absent_evidence="no_cleartext_http_hits",
    )

    assert entry == FlutterEvidenceEntry(
        True,
        "lib/client.dart:12: Cleartext request",
        ["lib/client.dart:12: Cleartext request"],
    )


def test_scoped_opengrep_entry_reports_absence_only_when_every_rule_ran() -> None:
    required = frozenset({"flutter.source.first", "flutter.source.second"})
    complete = _context_with_scope(
        status="success",
        configured_rule_ids=["flutter.source.first", "flutter.source.second"],
    )
    incomplete = _context_with_scope(
        status="success",
        configured_rule_ids=["flutter.source.first"],
    )
    failed = _context_with_scope(
        status="failed",
        configured_rule_ids=["flutter.source.first", "flutter.source.second"],
    )

    assert scoped_opengrep_entry(
        complete,
        scope="flutter",
        rule_ids=required,
        absent_evidence="no_hits",
    ) == FlutterEvidenceEntry(False, "no_hits", [])
    assert scoped_opengrep_entry(
        incomplete,
        scope="flutter",
        rule_ids=required,
        absent_evidence="no_hits",
    ) == FlutterEvidenceEntry(None)
    assert scoped_opengrep_entry(
        failed,
        scope="flutter",
        rule_ids=required,
        absent_evidence="no_hits",
    ) == FlutterEvidenceEntry(None)


def test_positive_finding_remains_evidence_when_scope_metadata_is_incomplete() -> None:
    context = FlutterScanExtractionContext(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "ios-weak-crypto-md5",
                        "phoenix_scope": "ios",
                        "path": "ios/Runner/Crypto.swift",
                    }
                ],
                "scan_metadata": {"scopes": {"ios": {"status": "failed"}}},
            }
        }
    )

    entry = scoped_opengrep_entry(
        context,
        scope="ios",
        rule_ids=frozenset({"ios-weak-crypto-md5"}),
        absent_evidence="no_weak_crypto_hits",
    )

    assert entry.present is True
    assert entry.details == ["ios/Runner/Crypto.swift"]


def test_combines_positive_false_and_unknown_entries_without_false_clean_result() -> None:
    detected = FlutterEvidenceEntry(True, "lib/a.dart:1", ["lib/a.dart:1", "shared"])
    duplicate = FlutterEvidenceEntry(True, "lib/a.dart:1", ["shared", "lib/b.dart:2"])
    absent = FlutterEvidenceEntry(False, "no_hits", [])
    unknown = FlutterEvidenceEntry(None)

    assert combine_evidence_entries(
        [detected, duplicate, unknown],
        absent_evidence="no_combined_hits",
    ) == FlutterEvidenceEntry(
        True,
        "lib/a.dart:1",
        ["lib/a.dart:1", "shared", "lib/b.dart:2"],
    )
    assert combine_evidence_entries(
        [absent, unknown],
        absent_evidence="no_combined_hits",
    ) == FlutterEvidenceEntry(None)
    assert combine_evidence_entries(
        [absent, FlutterEvidenceEntry(False, "none", [])],
        absent_evidence="no_combined_hits",
    ) == FlutterEvidenceEntry(False, "no_combined_hits", [])
    assert combine_evidence_entries([], absent_evidence="no_combined_hits") == FlutterEvidenceEntry(None)


def test_optional_bool_entry_preserves_unknown_and_inversion_semantics() -> None:
    assert optional_bool_entry(True, label="debuggable") == FlutterEvidenceEntry(
        True,
        "debuggable=true",
        [],
    )
    assert optional_bool_entry(False, label="secure", invert=True) == FlutterEvidenceEntry(
        True,
        "secure=false",
        [],
    )
    assert optional_bool_entry("false", label="debuggable") == FlutterEvidenceEntry(None)


def _context_with_scope(*, status: str, configured_rule_ids: list[str]) -> FlutterScanExtractionContext:
    return FlutterScanExtractionContext(
        {
            "opengrep": {
                "results": [],
                "scan_metadata": {
                    "scopes": {
                        "flutter": {
                            "status": status,
                            "configured_rule_ids": configured_rule_ids,
                        }
                    }
                },
            }
        }
    )
