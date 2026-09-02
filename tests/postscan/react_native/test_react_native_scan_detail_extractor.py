"""Tests for React Native source detail extraction and report models."""

from __future__ import annotations

import json

from adapters.post_scan.react_native import ReactNativeScanDetailExtractor


def test_extracts_react_native_report_sections() -> None:
    loaded_outputs = {
        "scan_output_path": "/results/SAST_react_native_source_2026-09-02_12-34-56",
        "scan_metadata": {
            "project_path": "/workspace/example-app",
            "target_type": "SOURCE",
        },
        "source_metadata": {
            "extraction": {"status": "complete", "warnings": []},
            "project": {
                "package_json_path": "package.json",
                "app_json_path": "app.json",
                "lockfiles": ["yarn.lock"],
                "package_manager": "yarn",
            },
            "identity": {
                "package_name": "example-app",
                "display_name": "Example App",
                "description": "Example React Native application",
                "version": "1.2.3",
            },
            "framework": {
                "react_native_version": "0.81.0",
                "react_version": "19.1.0",
                "expo_version": "~54.0.0",
                "typescript": True,
            },
            "engines": {"node": ">=20", "npm": "", "yarn": ">=4", "pnpm": ""},
            "entrypoints": {
                "package_main": "src/main.tsx",
                "files": ["src/main.tsx", "index.js"],
                "expo_router_path": "app",
            },
            "platforms": {"android": True, "ios": True},
            "dependencies": {
                "direct": [{"name": "react-native", "constraint": "0.81.0", "source": "registry"}],
                "development": [{"name": "jest", "constraint": "^30", "source": "registry"}],
            },
            "android": {
                "available": True,
                "metadata": {
                    "identity": {
                        "app_name": "Example Android",
                        "package_name": "com.example.android",
                        "namespace": "com.example",
                        "main_activity": "com.example.MainActivity",
                        "compile_sdk": "35",
                        "min_sdk": "24",
                        "target_sdk": "35",
                        "version_name": "1.2.3",
                        "version_code": "42",
                    },
                    "application": {
                        "icon": "android/app/src/main/res/mipmap/ic_launcher.png",
                        "debuggable": False,
                        "allow_backup": True,
                        "uses_cleartext_traffic": False,
                    },
                    "components": {
                        "activities": [{"name": ".MainActivity", "exported": True}],
                        "services": [],
                        "receivers": [],
                        "providers": [],
                    },
                    "permissions": [{"name": "android.permission.CAMERA"}],
                    "deep_links": [{"scheme": "https", "host": "example.com"}],
                },
            },
            "ios": {
                "available": True,
                "metadata": {
                    "identity": {
                        "display_name": "Example iOS",
                        "bundle_name": "Example",
                        "bundle_identifier": "com.example.ios",
                        "executable": "Example",
                        "minimum_os": "15.0",
                        "version": "1.2.3",
                        "build": "43",
                    },
                    "permissions": [{"key": "NSCameraUsageDescription", "purpose": "Take photos"}],
                    "url_schemes": {
                        "declared_schemes": ["example"],
                        "queried_schemes": ["partner-app"],
                    },
                },
            },
        },
        "syft_outputs": {"sbom.json": {"artifacts": [{"name": "react-native", "version": "0.81.0"}]}},
        "gitleaks_outputs": {"gitleaks_report.json": []},
        "trufflehog_outputs": {},
    }

    sections = ReactNativeScanDetailExtractor().extract_sections(loaded_outputs)

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
        "hardcoded_values",
        "endpoints",
        "code_evidence",
        "network_evidence",
        "data_storage_evidence",
        "resilience_evidence",
    }
    assert sections["meta"] == {
        "app_display_name": "Example App",
        "file_name": "example-app",
        "package_name": "example-app",
        "platform": "React Native",
        "reviewer_org": "Phoenix Security Report",
        "scan_date": "2026-09-02 12:34:56",
        "target_type": "SOURCE",
        "version_code": "42",
        "version_name": "1.2.3",
    }
    assert sections["file_info"] == {
        "filename": "example-app",
        "size": "",
        "md5": "",
        "sha1": "",
        "sha256": "",
        "package_json_path": "package.json",
        "app_json_path": "app.json",
        "lockfiles": ["yarn.lock"],
        "package_manager": "yarn",
    }
    assert sections["app_info"]["react_native_version"] == "0.81.0"
    assert sections["app_info"]["android_application_id"] == "com.example.android"
    assert sections["app_info"]["ios_bundle_identifier"] == "com.example.ios"
    assert sections["platform_inventory"]["source_metadata_assessed"] is True
    assert sections["platform_inventory"]["framework"]["typescript"] is True
    assert sections["platform_inventory"]["android"]["metadata_assessed"] is True
    assert sections["platform_inventory"]["ios"]["metadata_assessed"] is True
    assert sections["dependency_inventory"] == {
        "metadata_assessed": True,
        "sbom_assessed": True,
        "declared": [
            {
                "name": "react-native",
                "constraint": "0.81.0",
                "source": "registry",
                "scope": "direct",
            },
            {"name": "jest", "constraint": "^30", "source": "registry", "scope": "development"},
        ],
        "sbom_packages": [{"name": "react-native", "version": "0.81.0", "output_path": "sbom.json"}],
    }
    assert sections["application"] == {
        "debuggable": False,
        "allow_backup": True,
        "uses_cleartext_traffic": False,
    }
    assert sections["app_components"] == {
        "activities": 1,
        "services": 0,
        "receivers": 0,
        "providers": 0,
        "exported_activities": 1,
        "exported_services": 0,
        "exported_receivers": 0,
        "exported_providers": 0,
    }
    assert {item["platform"] for item in sections["permissions"]} == {"Android", "iOS"}
    assert sections["deep_links"] == {"deep_links": [{"scheme": "https", "host": "example.com"}]}
    assert sections["url_schemes"] == [{"url_name": "Example iOS", "schemes": ["example"]}]
    assert sections["queried_url_schemes"] == ["partner-app"]
    assert sections["hardcoded_values"] == {"urls": [], "emails": [], "secrets": []}
    assert sections["endpoints"] == []
    assert sections["code_evidence"]["app_is_debuggable"] == {
        "present": False,
        "evidence": "debuggable=false",
        "details": [],
    }
    assert sections["code_evidence"]["activities_accessible_to_other_apps"] == {
        "present": True,
        "evidence": "exported_activities=1",
        "details": [".MainActivity"],
    }
    assert sections["code_evidence"]["application_data_can_be_backed_up"]["present"] is True
    assert sections["network_evidence"]["allows_cleartext_traffic_for_all_domains"]["present"] is False
    assert sections["data_storage_evidence"]["accesses_external_storage"]["present"] is False
    assert all(entry["present"] is None for entry in sections["resilience_evidence"].values())
    json.dumps(sections)


def test_missing_metadata_preserves_unassessed_report_sections() -> None:
    sections = ReactNativeScanDetailExtractor().extract_sections(
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
    assert sections["meta"]["package_name"] == ""
    assert sections["file_info"]["package_json_path"] == ""
    assert sections["app_info"]["name"] == "FallbackProject"
    assert sections["platform_inventory"]["source_metadata_assessed"] is False
    assert sections["platform_inventory"]["android"]["detected"] is False
    assert sections["platform_inventory"]["ios"]["detected"] is False
    assert sections["dependency_inventory"] == {
        "metadata_assessed": False,
        "sbom_assessed": False,
        "declared": [],
        "sbom_packages": [],
    }
    assert all(value is None for value in sections["app_components"].values())
    assert sections["permissions"] == []
    assert sections["deep_links"] == {"deep_links": None}
    assert "hardcoded_values" not in sections
    assert "endpoints" not in sections
    for section_name in (
        "code_evidence",
        "network_evidence",
        "data_storage_evidence",
        "resilience_evidence",
    ):
        assert section_name in sections
        assert all(entry["present"] is None for entry in sections[section_name].values())


def test_extracts_redacted_secret_evidence_without_exposing_raw_secret() -> None:
    sections = ReactNativeScanDetailExtractor().extract_sections(
        {
            "scan_metadata": {"project_path": "/workspace/example-app"},
            "gitleaks_outputs": {
                "gitleaks_report.json": [
                    {
                        "RuleID": "generic-api-key",
                        "Secret": "do-not-expose",  # pragma: allowlist secret
                        "File": "/workspace/example-app/src/config.ts",
                        "StartLine": 7,
                    }
                ]
            },
        }
    )

    assert sections["hardcoded_values"]["secrets"] == [
        {
            "value": "generic-api-key credential (redacted)",
            "location": "src/config.ts:7",
        }
    ]
    assert "do-not-expose" not in json.dumps(sections)
