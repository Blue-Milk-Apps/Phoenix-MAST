"""Tests for Flutter source detail extraction."""

from __future__ import annotations

import json

from adapters.post_scan.flutter import FlutterScanDetailExtractor


def test_extracts_core_flutter_metadata_and_inventory_sections() -> None:
    loaded_outputs = {
        "scan_output_path": "/results/SAST_flutter_source_2026-08-30_12-34-56",
        "scan_metadata": {
            "project_path": "/workspace/example_app",
            "target_type": "SOURCE",
        },
        "source_metadata": {
            "extraction": {"status": "complete", "warnings": []},
            "project": {
                "pubspec_path": "pubspec.yaml",
                "pubspec_lock_path": "pubspec.lock",
            },
            "identity": {
                "package_name": "example_app",
                "description": "Example Flutter application",
                "version_name": "1.2.3",
                "version_code": "42",
                "homepage": "https://example.com",
                "repository": "https://example.com/source",
            },
            "sdk": {
                "dart_constraint": ">=3.3.0 <4.0.0",
                "flutter_constraint": ">=3.22.0",
            },
            "platforms": {
                "android": True,
                "ios": True,
                "web": True,
                "linux": False,
                "macos": False,
                "windows": False,
            },
            "android": {
                "available": True,
                "metadata": {
                    "identity": {
                        "app_name": "Example App",
                        "package_name": "com.example.android",
                        "target_sdk": "35",
                        "min_sdk": "24",
                    }
                },
            },
            "ios": {
                "available": True,
                "metadata": {
                    "identity": {
                        "display_name": "Example iOS App",
                        "bundle_identifier": "com.example.ios",
                        "minimum_os": "13.0",
                    }
                },
            },
            "dependencies": {
                "direct": [{"name": "http", "constraint": "^1.2.0", "source": "hosted"}],
                "development": [],
                "resolved": [
                    {
                        "name": "http",
                        "version": "1.2.0",
                        "source": "hosted",
                        "dependency_kind": "direct",
                    }
                ],
            },
        },
        "syft_outputs": {"sbom.json": {"artifacts": [{"name": "http", "version": "1.2.0"}]}},
    }

    sections = FlutterScanDetailExtractor().extract_sections(loaded_outputs)

    assert set(sections) == {
        "meta",
        "file_info",
        "app_info",
        "platform_inventory",
        "dependency_inventory",
        "application",
        "app_components",
        "permissions",
        "deep_links",
        "url_schemes",
        "queried_url_schemes",
        "code_evidence",
    }
    assert sections["meta"] == {
        "app_display_name": "Example App",
        "file_name": "example_app",
        "package_name": "example_app",
        "platform": "Flutter",
        "reviewer_org": "Phoenix Security Report",
        "scan_date": "2026-08-30 12:34:56",
        "target_type": "SOURCE",
        "version_code": "42",
        "version_name": "1.2.3",
    }
    assert sections["file_info"] == {
        "filename": "example_app",
        "size": "",
        "md5": "",
        "sha1": "",
        "sha256": "",
        "pubspec_path": "pubspec.yaml",
        "pubspec_lock_path": "pubspec.lock",
    }
    assert sections["app_info"]["android_application_id"] == "com.example.android"
    assert sections["app_info"]["ios_bundle_identifier"] == "com.example.ios"
    assert sections["platform_inventory"]["android"]["metadata_assessed"] is True
    assert sections["platform_inventory"]["ios"]["metadata_assessed"] is True
    assert sections["platform_inventory"]["web_detected"] is True
    assert sections["dependency_inventory"]["metadata_assessed"] is True
    assert sections["dependency_inventory"]["sbom_assessed"] is True
    assert sections["dependency_inventory"]["declared"] == [
        {"name": "http", "constraint": "^1.2.0", "source": "hosted", "scope": "direct"}
    ]
    assert sections["dependency_inventory"]["sbom_packages"] == [
        {"name": "http", "version": "1.2.0", "output_path": "sbom.json"}
    ]
    assert sections["code_evidence"]["insecure_nanopb_library"] == {
        "present": False,
        "evidence": "no_insecure_nanopb_library_hits",
        "details": [],
    }
    assert sections["application"] == {
        "debuggable": None,
        "allow_backup": None,
        "uses_cleartext_traffic": None,
    }
    assert all(value is None for value in sections["app_components"].values())
    assert sections["permissions"] == []
    assert sections["deep_links"] == {"deep_links": None}
    assert sections["url_schemes"] == []
    assert sections["queried_url_schemes"] == []
    json.dumps(sections)


def test_missing_flutter_metadata_preserves_empty_unassessed_core_sections() -> None:
    sections = FlutterScanDetailExtractor().extract_sections(
        {
            "scan_metadata": {
                "project_path": "/workspace/FallbackProject",
                "target_type": "SOURCE",
            },
            "source_metadata": None,
            "syft_outputs": {"sbom.json": None},
        }
    )

    assert sections["meta"]["app_display_name"] == "FallbackProject"
    assert sections["meta"]["file_name"] == "FallbackProject"
    assert sections["meta"]["package_name"] == ""
    assert sections["app_info"]["name"] == "FallbackProject"
    assert sections["file_info"]["pubspec_path"] == ""
    assert sections["platform_inventory"]["source_metadata_assessed"] is False
    assert sections["platform_inventory"]["android"]["detected"] is False
    assert sections["platform_inventory"]["ios"]["detected"] is False
    assert sections["dependency_inventory"] == {
        "metadata_assessed": False,
        "sbom_assessed": False,
        "declared": [],
        "resolved": [],
        "sbom_packages": [],
    }
    assert all(value is None for value in sections["app_components"].values())
    assert sections["permissions"] == []
    assert sections["deep_links"] == {"deep_links": None}
