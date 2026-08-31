"""Tests for redacted Flutter secret evidence."""

from __future__ import annotations

import json
from dataclasses import asdict

from domain.post_scan.flutter import FlutterHardcodedValues, FlutterScanExtractionContext


def test_normalizes_redacts_and_deduplicates_secret_findings() -> None:
    context = FlutterScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/example"},
            "gitleaks_outputs": {
                "gitleaks_report.json": [
                    {
                        "Description": "AWS",
                        "RuleID": "aws-access-token",
                        "File": "/workspace/example/lib/config.dart",
                        "StartLine": 7,
                        "Secret": "gitleaks-raw-secret",  # pragma: allowlist secret
                    },
                    {
                        "Description": "Database password",
                        "File": "lib/database.dart",
                        "StartLine": 11,
                        "Secret": "database-password",  # pragma: allowlist secret
                    },
                ]
            },
            "trufflehog_outputs": {
                "trufflehog_results.json": [
                    {
                        "DetectorName": "AWS",
                        "Raw": "trufflehog-raw-secret",
                        "SourceMetadata": {
                            "Data": {
                                "Filesystem": {
                                    "file": "/workspace/example/lib/config.dart",
                                    "line": 7,
                                }
                            }
                        },
                    },
                    {
                        "DetectorName": "API token",
                        "Raw": "api-token-value",
                        "SourceMetadata": {"Data": {"Filesystem": {"file": "lib/api.dart", "line": 19}}},
                    },
                ]
            },
        }
    )

    model = FlutterHardcodedValues(context)
    serialized = json.dumps(asdict(model))

    assert asdict(model) == {
        "urls": [],
        "emails": [],
        "secrets": [
            {"value": "AWS credential (redacted)", "location": "lib/config.dart:7"},
            {"value": "Database password credential (redacted)", "location": "lib/database.dart:11"},
            {"value": "API token credential (redacted)", "location": "lib/api.dart:19"},
        ],
        "gitleaks_assessed": True,
        "trufflehog_assessed": True,
        "assessed": True,
    }
    assert "gitleaks-raw-secret" not in serialized
    assert "trufflehog-raw-secret" not in serialized
    assert "database-password" not in serialized
    assert "api-token-value" not in serialized


def test_successful_empty_scanner_output_is_assessed_without_findings() -> None:
    context = FlutterScanExtractionContext(
        {
            "gitleaks_outputs": {"gitleaks_report.json": []},
            "trufflehog_outputs": {},
        }
    )

    model = FlutterHardcodedValues(context)

    assert model.gitleaks_assessed is True
    assert model.trufflehog_assessed is False
    assert model.assessed is True
    assert model.secrets == []


def test_legacy_finding_remains_visible_without_claiming_scanner_assessment() -> None:
    context = FlutterScanExtractionContext(
        {
            "trufflehog_outputs": {
                "trufflehog_results.json": {
                    "findings": [
                        {
                            "DetectorName": "Legacy token",
                            "Raw": "legacy-raw-value",
                            "SourceMetadata": {"Data": {"Filesystem": {"file": "lib/legacy.dart"}}},
                        }
                    ]
                }
            }
        }
    )

    model = FlutterHardcodedValues(context)

    assert model.gitleaks_assessed is False
    assert model.trufflehog_assessed is False
    assert model.assessed is False
    assert model.secrets == [{"value": "Legacy token credential (redacted)", "location": "lib/legacy.dart"}]
    assert "legacy-raw-value" not in json.dumps(asdict(model))


def test_missing_or_malformed_scanner_outputs_remain_unassessed() -> None:
    model = FlutterHardcodedValues(
        FlutterScanExtractionContext(
            {
                "gitleaks_outputs": {"gitleaks_report.json": None},
                "trufflehog_outputs": {"trufflehog_results.json": None},
            }
        )
    )

    assert model.gitleaks_assessed is False
    assert model.trufflehog_assessed is False
    assert model.assessed is False
    assert model.urls == []
    assert model.emails == []
    assert model.secrets == []
