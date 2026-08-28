from __future__ import annotations

import json
from pathlib import Path

from adapters.post_scan import NativeAndroidScanDetailExtractor
from domain.post_scan.android.native import (
    NativeAndroidFunctionality,
    NativeAndroidHardcodedValues,
    NativeAndroidScanExtractionContext,
)


def test_android_rules_use_phoenix_metadata() -> None:
    rules = (Path(__file__).parents[4] / "rules" / "android" / "android_rules.yml").read_text(encoding="utf-8")

    assert "appcritiq:" not in rules
    assert rules.count("\n      phoenix:") == 27


def test_functionality_combines_manifest_permissions_and_phoenix_opengrep_metadata() -> None:
    context = NativeAndroidScanExtractionContext(
        {
            "source_metadata": {
                "permissions": [{"name": "android.permission.CAMERA"}],
            },
            "opengrep": {
                "success": True,
                "results": [
                    {
                        "check_id": "android.camera.usage.present",
                        "path": "app/src/main/java/Camera.kt",
                        "start": {"line": 12},
                        "extra": {
                            "message": "Camera API matched.",
                            "metadata": {
                                "phoenix": {
                                    "check_id": 53,
                                    "description": "Camera functionality detected.",
                                }
                            },
                        },
                    },
                    {
                        "check_id": "android.maps.usage.present",
                        "extra": {
                            "metadata": {
                                "phoenix": {
                                    "check_id": 62,
                                    "title": "Maps usage detected.",
                                }
                            }
                        },
                    },
                ],
            },
        }
    )

    functionality = NativeAndroidFunctionality(context)

    assert functionality.assessed is True
    assert functionality.items["Camera"] == {
        "present": True,
        "explanation": ("Camera functionality detected. Declared permission: android.permission.CAMERA."),
    }
    assert functionality.items["Maps"] == {
        "present": True,
        "explanation": "Maps usage detected.",
    }
    assert functionality.items["Networking"]["present"] is False


def test_functionality_is_unknown_when_source_evidence_is_unavailable() -> None:
    functionality = NativeAndroidFunctionality(NativeAndroidScanExtractionContext({}))

    assert functionality.assessed is False
    assert all(item["present"] is None for item in functionality.items.values())
    assert "functionality" not in NativeAndroidScanDetailExtractor().extract_sections({})


def test_successful_empty_opengrep_is_assessed() -> None:
    loaded_outputs = {"opengrep": {"success": True, "results": []}}
    context = NativeAndroidScanExtractionContext(loaded_outputs)

    assert context.opengrep_assessed is True
    sections = NativeAndroidScanDetailExtractor().extract_sections(loaded_outputs)
    assert all(item["present"] is False for item in sections["functionality"].values())


def test_secret_findings_are_redacted_normalized_and_deduplicated() -> None:
    raw_gitleaks_secret = "gitleaks-super-secret-value"  # pragma: allowlist secret
    raw_trufflehog_secret = "trufflehog-super-secret-value"  # pragma: allowlist secret
    loaded_outputs = {
        "scan_metadata": {"project_path": "/workspace/project"},
        "gitleaks_outputs": {
            "gitleaks_report.json": [
                {
                    "Description": "Generic API key",
                    "RuleID": "generic-api-key",
                    "File": "/workspace/project/app/src/main/Secrets.kt",
                    "StartLine": 8,
                    "Secret": raw_gitleaks_secret,
                    "Match": f'apiKey = "{raw_gitleaks_secret}"',
                },
                {
                    "Description": "Generic API key",
                    "RuleID": "generic-api-key",
                    "File": "/workspace/project/app/src/main/Secrets.kt",
                    "StartLine": 8,
                    "Secret": raw_gitleaks_secret,
                },
            ]
        },
        "trufflehog_outputs": {
            "trufflehog_results.json": [
                {
                    "DetectorName": "GCP",
                    "Raw": raw_trufflehog_secret,
                    "RawV2": f'{{"private_key":"{raw_trufflehog_secret}"}}',
                    "SourceMetadata": {
                        "Data": {
                            "Filesystem": {
                                "file": "/workspace/project/docs/setup.md",
                                "line": 61,
                            }
                        }
                    },
                }
            ]
        },
    }

    context = NativeAndroidScanExtractionContext(loaded_outputs)
    hardcoded_values = NativeAndroidHardcodedValues(context)
    sections = NativeAndroidScanDetailExtractor().extract_sections(loaded_outputs)
    serialized = json.dumps(sections)

    assert context.gitleaks_assessed is True
    assert context.trufflehog_assessed is True
    assert hardcoded_values.assessed is True
    assert hardcoded_values.secrets == [
        {
            "value": "Generic API key (redacted)",
            "location": "app/src/main/Secrets.kt:8",
        },
        {
            "value": "GCP credential (redacted)",
            "location": "docs/setup.md:61",
        },
    ]
    assert raw_gitleaks_secret not in serialized
    assert raw_trufflehog_secret not in serialized
    assert sections["hardcoded_values"]["urls"] == []
    assert sections["hardcoded_values"]["emails"] == []
    assert sections["endpoints"] == []


def test_missing_and_error_secret_reports_are_unassessed() -> None:
    loaded_outputs = {
        "gitleaks_outputs": {
            "gitleaks_report.json": {"error": "tool failed", "success": False},
        },
        "trufflehog_outputs": {},
        "source_metadata": {
            "deep_links": [{"scheme": "example", "host": "open"}],
        },
    }
    context = NativeAndroidScanExtractionContext(loaded_outputs)
    sections = NativeAndroidScanDetailExtractor().extract_sections(loaded_outputs)

    assert context.gitleaks_assessed is False
    assert context.trufflehog_assessed is False
    assert "hardcoded_values" not in sections
    assert "endpoints" not in sections


def test_successful_empty_secret_report_emits_assessed_empty_sections() -> None:
    loaded_outputs = {
        "gitleaks_outputs": {"gitleaks_report.json": []},
    }

    sections = NativeAndroidScanDetailExtractor().extract_sections(loaded_outputs)

    assert sections["hardcoded_values"] == {"urls": [], "emails": [], "secrets": []}
    assert sections["endpoints"] == []
