"""Tests for conditional Flutter supporting report sections."""

from __future__ import annotations

import json

from adapters.post_scan.flutter import FlutterScanDetailExtractor


def test_does_not_infer_functionality_from_legacy_metadata() -> None:
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

    assert sections["functionality"] == {}
    assert sections["hardcoded_values"] == {"urls": [], "emails": [], "secrets": []}
    assert sections["endpoints"] == []
    assert "manual_review" not in sections
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
    assert "manual_review" not in sections
    assert raw_secret not in serialized


def test_emits_unassessed_empty_supporting_sections() -> None:
    sections = FlutterScanDetailExtractor().extract_sections({})

    assert "functionality" in sections
    assert sections["functionality"] == {}
    assert "hardcoded_values" not in sections
    assert "endpoints" not in sections
    assert "manual_review" not in sections
