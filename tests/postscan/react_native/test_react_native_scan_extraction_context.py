from __future__ import annotations

from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


def test_exposes_project_and_source_metadata() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "scan_metadata": {"project_path": "/workspace/example", "scan_date": "2026-09-02"},
            "source_metadata": {
                "extraction": {"warnings": ["partial metadata", "partial metadata"]},
                "project": {"project_path": "/fallback/project", "package_manager": "yarn"},
                "identity": {"package_name": "example-app"},
                "framework": {"react_native_version": "0.81.0"},
                "engines": {"node": ">=20"},
                "entrypoints": {"files": ["index.ts"]},
                "platforms": {"android": True, "ios": False, "invalid": "yes"},
                "dependencies": {
                    "direct": [{"name": "react-native"}, "invalid"],
                    "development": [{"name": "typescript"}],
                },
            },
        }
    )

    assert context.source_metadata_assessed is True
    assert context.project_path.as_posix() == "/workspace/example"
    assert context.scan_date == "2026-09-02"
    assert context.warnings == ["partial metadata"]
    assert context.project["package_manager"] == "yarn"
    assert context.identity == {"package_name": "example-app"}
    assert context.framework == {"react_native_version": "0.81.0"}
    assert context.engines == {"node": ">=20"}
    assert context.entrypoints == {"files": ["index.ts"]}
    assert context.platforms == {"android": True, "ios": False}
    assert context.dependencies == {
        "direct": [{"name": "react-native"}],
        "development": [{"name": "typescript"}],
    }
    assert context.dependencies_assessed is True


def test_exposes_android_metadata() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "source_metadata": {
                "android": {
                    "available": True,
                    "metadata": {
                        "identity": {"package_name": "com.example.app"},
                        "application": {"allow_backup": False},
                        "permissions": [{"name": "android.permission.CAMERA"}, "invalid"],
                        "components": {
                            "activities": [{"name": "com.example.MainActivity"}],
                            "services": "invalid",
                        },
                        "deep_links": [{"scheme": "example"}],
                    },
                }
            }
        }
    )

    assert context.android_available is True
    assert context.android_metadata_assessed is True
    assert context.android_identity == {"package_name": "com.example.app"}
    assert context.android_application == {"allow_backup": False}
    assert context.android_permissions == [{"name": "android.permission.CAMERA"}]
    assert context.android_components == {
        "activities": [{"name": "com.example.MainActivity"}],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    assert context.android_deep_links == [{"scheme": "example"}]


def test_exposes_ios_metadata() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "source_metadata": {
                "ios": {
                    "available": True,
                    "metadata": {
                        "identity": {"bundle_identifier": "com.example.app"},
                        "permissions": [{"key": "NSCameraUsageDescription"}],
                        "app_transport_security": {"allows_arbitrary_loads": False},
                        "url_schemes": {"declared_schemes": ["example"]},
                        "background_modes": ["fetch", "fetch", 1],
                        "entitlements": [{"path": "Example.entitlements"}],
                        "privacy_manifests": [{"path": "PrivacyInfo.xcprivacy"}],
                    },
                }
            }
        }
    )

    assert context.ios_available is True
    assert context.ios_metadata_assessed is True
    assert context.ios_identity == {"bundle_identifier": "com.example.app"}
    assert context.ios_permissions == [{"key": "NSCameraUsageDescription"}]
    assert context.ios_app_transport_security == {"allows_arbitrary_loads": False}
    assert context.ios_url_schemes == {"declared_schemes": ["example"]}
    assert context.ios_background_modes == ["fetch", "1"]
    assert context.ios_entitlements == [{"path": "Example.entitlements"}]
    assert context.ios_privacy_manifests == [{"path": "PrivacyInfo.xcprivacy"}]


def test_filters_plist_outputs_by_index_role() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "plist_outputs": {
                "Example/Info.json": {"app_meta": {}},
                "Framework/Info.json": {"framework_meta": {}},
                "broken.json": None,
            },
            "plist_index": {
                "plists": [
                    {"output_path": "Example/Info.json", "role": "app"},
                    {"output_path": "Framework/Info.json", "role": "framework"},
                    "invalid",
                ]
            },
        }
    )

    assert context.plist_assessed is True
    assert set(context.plist_outputs) == {"Example/Info.json", "Framework/Info.json"}
    assert context.plist_outputs_for_role("app") == {"Example/Info.json": {"app_meta": {}}}


def test_exposes_opengrep_scope_assessment_and_results() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "opengrep": {
                "results": [
                    {"check_id": "react-native.source.example"},
                    {"check_id": "android.source.example"},
                    {"check_id": "ios.source.example", "phoenix_scope": "ios"},
                    "invalid",
                ],
                "scan_metadata": {
                    "scopes": {
                        "react_native": {
                            "status": "success",
                            "configured_rule_ids": ["react-native.source.example"],
                        },
                        "android": {"status": "skipped"},
                    }
                },
            }
        }
    )

    assert context.opengrep_scope_completed("react_native") is True
    assert context.opengrep_scope_assessed("react_native") is True
    assert context.opengrep_configured_rule_ids("react_native") == {"react-native.source.example"}
    assert context.opengrep_scope_completed("android") is False
    assert context.opengrep_scope_assessed("android") is False
    assert context.opengrep_results_for_scope("react_native") == [{"check_id": "react-native.source.example"}]
    assert context.opengrep_results_for_scope("android") == [{"check_id": "android.source.example"}]
    assert context.opengrep_results_for_scope("ios") == [{"check_id": "ios.source.example", "phoenix_scope": "ios"}]


def test_exposes_secret_scanner_findings_and_assessment() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "gitleaks_outputs": {
                "gitleaks_report.json": [{"RuleID": "generic-api-key"}, "invalid"],
            },
            "trufflehog_outputs": {
                "trufflehog_results.json": {"results": [{"DetectorName": "AWS"}, "invalid"]},
            },
        }
    )

    assert context.gitleaks_assessed is True
    assert context.trufflehog_assessed is False
    assert context.gitleaks_findings == [{"RuleID": "generic-api-key"}]
    assert context.trufflehog_findings == [{"DetectorName": "AWS"}]


def test_exposes_syft_packages_and_assessment() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "syft_outputs": {
                "sbom.json": {
                    "artifacts": [
                        {"name": "react-native", "version": "0.81.0"},
                        {"name": "react-native", "version": "0.81.0"},
                        {"name": "react", "version": "19.1.0"},
                        "invalid",
                    ]
                }
            }
        }
    )

    assert context.syft_assessed is True
    assert context.syft_packages == [
        ("sbom.json", "react-native", "0.81.0"),
        ("sbom.json", "react", "19.1.0"),
    ]


def test_empty_and_malformed_outputs_return_safe_defaults() -> None:
    context = ReactNativeScanExtractionContext(
        {
            "scan_metadata": [],
            "source_metadata": "invalid",
            "plist_outputs": [],
            "plist_index": {"plists": "invalid"},
            "opengrep": [],
            "gitleaks_outputs": {"gitleaks_report.json": None},
            "trufflehog_outputs": {},
            "syft_outputs": {"sbom.json": {"success": False, "artifacts": []}},
        }
    )

    assert context.source_metadata_assessed is False
    assert context.project_path.as_posix() == "."
    assert context.scan_date == ""
    assert context.warnings == []
    assert context.identity == {}
    assert context.framework == {}
    assert context.platforms == {}
    assert context.dependencies == {"direct": [], "development": []}
    assert context.dependencies_assessed is False
    assert context.android_metadata_assessed is False
    assert context.ios_metadata_assessed is False
    assert context.plist_assessed is False
    assert context.opengrep_results == []
    assert context.gitleaks_assessed is False
    assert context.trufflehog_assessed is False
    assert context.syft_assessed is False


def test_scan_date_falls_back_to_timestamped_output_directory() -> None:
    context = ReactNativeScanExtractionContext(
        {"scan_output_path": "/results/SAST_react_native_source_2026-09-02_13-14-15"}
    )

    assert context.scan_date == "2026-09-02 13:14:15"
