"""Tests for conditional Flutter supporting report sections."""

from __future__ import annotations

import json

from adapters.post_scan.flutter import FlutterScanDetailExtractor


def test_emits_assessed_functionality_secrets_and_manual_review_sections() -> None:
    loaded_outputs = {
        "scan_metadata": {"project_path": "/workspace/app"},
        "source_metadata": {
            "platforms": {"android": True},
            "android": {
                "available": True,
                "metadata": {"permissions": [{"name": "android.permission.CAMERA"}]},
            },
        },
        "gitleaks_outputs": {"gitleaks_report.json": []},
        "opengrep": {
            "results": [],
            "scan_metadata": {
                "scopes": {
                    "flutter": {
                        "status": "success",
                        "configured_rule_ids": ["flutter.source.unsafe-platform-channel"],
                    }
                }
            },
        },
    }

    sections = FlutterScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["functionality"]["Camera"] == {
        "present": True,
        "explanation": "Declared Android permission: android.permission.CAMERA.",
    }
    assert sections["functionality"]["SMS"]["present"] is None
    assert sections["hardcoded_values"] == {"urls": [], "emails": [], "secrets": []}
    assert sections["endpoints"] == []
    assert sections["manual_review"] == {
        "findings": [],
        "assessed_scopes": ["flutter"],
        "assessed": True,
        "fully_assessed": True,
    }
    json.dumps(sections)


def test_preserves_positive_legacy_secret_and_raw_finding_from_partial_outputs() -> None:
    raw_secret = "must-not-reach-extracted-sections"  # pragma: allowlist secret
    loaded_outputs = {
        "scan_metadata": {"project_path": "/workspace/app"},
        "trufflehog_outputs": {
            "trufflehog_results.json": {
                "findings": [
                    {
                        "DetectorName": "Legacy token",
                        "Raw": raw_secret,
                        "SourceMetadata": {
                            "Data": {"Filesystem": {"file": "/workspace/app/lib/config.dart", "line": 5}}
                        },
                    }
                ]
            }
        },
        "opengrep": {
            "results": [
                {
                    "check_id": "flutter.source.unsafe-platform-channel",
                    "phoenix_scope": "flutter",
                    "path": "/workspace/app/lib/channel.dart",
                    "start": {"line": 9},
                }
            ],
            "scan_metadata": {"scopes": {"flutter": {"status": "failed"}}},
        },
    }

    sections = FlutterScanDetailExtractor().extract_sections(loaded_outputs)
    serialized = json.dumps(sections)

    assert sections["hardcoded_values"]["secrets"] == [
        {"value": "Legacy token credential (redacted)", "location": "lib/config.dart:5"}
    ]
    assert sections["endpoints"] == []
    assert sections["manual_review"]["assessed"] is False
    assert sections["manual_review"]["fully_assessed"] is False
    assert sections["manual_review"]["findings"][0]["rule_id"] == ("flutter.source.unsafe-platform-channel")
    assert raw_secret not in serialized


def test_omits_unassessed_empty_supporting_sections() -> None:
    sections = FlutterScanDetailExtractor().extract_sections({})

    assert "functionality" not in sections
    assert "hardcoded_values" not in sections
    assert "endpoints" not in sections
    assert "manual_review" not in sections
