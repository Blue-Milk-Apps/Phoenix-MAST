from __future__ import annotations

import json

import yaml

from adapters.post_scan import NativeAndroidScanDetailExtractor
from domain.post_scan.android.native import (
    NativeAndroidFunctionality,
    NativeAndroidHardcodedValues,
    NativeAndroidScanExtractionContext,
)
from tests.rule_fixtures import assessment_payload, private_rules, rule


def test_android_rules_use_flat_metadata() -> None:
    rules = yaml.safe_load((private_rules("android") / "functionality.yml").read_text())["rules"]
    assert len(rules) == 48
    for definition in rules:
        metadata = definition["metadata"]
        assert metadata["finding_type"] == "observation"
        assert metadata.get("functionality") or (
            metadata["scope"] == "app_declaration" and "(?P<PERMISSION>" in definition["patterns"][0]["pattern-regex"]
        )
        assert not {"appcritiq", "phoenix", "report_section", "capability_type", "category"} & metadata.keys()


def test_functionality_uses_opengrep_metadata_without_python_permission_mapping() -> None:
    camera = rule("example.camera", finding_type="observation")
    camera["metadata"].update(functionality="Camera", description="Camera functionality detected.")
    maps = rule("example.maps", finding_type="observation")
    maps["metadata"].update(functionality="Maps", description="Maps usage detected.")
    custom = rule("example.custom", finding_type="observation")
    custom["metadata"].update(functionality="Custom Capability")
    opengrep = assessment_payload(
        camera,
        maps,
        custom,
        platform="android",
        category="functionality",
        results=[
            {"check_id": "example.camera"},
            {"check_id": "example.maps"},
        ],
    )
    context = NativeAndroidScanExtractionContext(
        {
            "source_metadata": {"permissions": [{"name": "android.permission.NFC"}]},
            "opengrep": opengrep,
        }
    )
    functionality = NativeAndroidFunctionality(context)
    assert functionality.assessed is True
    assert functionality.items["Camera"] == {
        "present": True,
        "explanation": "Camera functionality detected.",
    }
    assert functionality.items["Maps"] == {"present": True, "explanation": "Maps usage detected."}
    assert set(functionality.items) == {"Camera", "Maps", "Custom Capability"}
    assert functionality.items["Custom Capability"]["present"] is False


def test_functionality_is_unknown_when_source_evidence_is_unavailable() -> None:
    loaded = {"source_metadata": {"permissions": [{"name": "android.permission.CAMERA"}]}}
    functionality = NativeAndroidFunctionality(NativeAndroidScanExtractionContext(loaded))

    assert functionality.assessed is False
    assert functionality.items == {}
    sections = NativeAndroidScanDetailExtractor().extract_sections({})
    assert sections["functionality"] == functionality.items
    camera = rule("example.camera", finding_type="observation")
    camera["metadata"]["functionality"] = "Camera"
    loaded["opengrep"] = assessment_payload(camera, status="failed", platform="android", category="functionality")
    assert NativeAndroidFunctionality(NativeAndroidScanExtractionContext(loaded)).items["Camera"]["present"] is None


def test_empty_opengrep_without_rule_coverage_cannot_establish_functionality_absence() -> None:
    loaded_outputs = {"opengrep": {"success": True, "results": []}}
    context = NativeAndroidScanExtractionContext(loaded_outputs)

    assert context.opengrep_assessed is True
    sections = NativeAndroidScanDetailExtractor().extract_sections(loaded_outputs)
    assert sections["functionality"] == {}


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
