import json
import plistlib
from pathlib import Path

from adapters.output.phoenix_report.generate_report import generate_report, load_report_data
from adapters.post_scan.react_native import ReactNativeScanDetailExtractor
from adapters.scanners.react_native.react_native_source_metadata_scanner import (
    ReactNativeSourceMetadataScanner,
)
from application.mobile_analysis_workflow_service import MobileAnalysisWorkflowService
from domain.models import ScanConfig
from domain.post_scan.react_native import INVENTORY_RULE_ID_TO_KEY, REACT_NATIVE_RULE_IDS


def test_react_native_extractor_builds_mobile_only_report_and_pdf(tmp_path: Path) -> None:
    project = tmp_path / "mobile"
    loaded = {
        "scan_output_path": str(tmp_path / "SAST_react_native_source_2026-01-02_03-04-05"),
        "scan_metadata": {"project_path": str(project), "target_type": "SOURCE"},
        "source_metadata": {
            "extraction": {"status": "complete", "warnings": []},
            "project": {"project_path": str(project)},
            "identity": {"package_name": "mobile", "display_name": "Mobile", "version": "1.2.3"},
            "runtime": {"react_native_constraint": "0.80.0", "node_constraint": ">=20"},
            "platforms": {"android": True, "ios": False, "web": True},
            "dependencies": {
                "declared": [{"name": "react-native", "constraint": "0.80.0", "scope": "direct"}],
                "resolved": [{"name": "react-native", "version": "0.80.0", "scope": "resolved"}],
            },
            "android": {
                "available": True,
                "metadata": {
                    "identity": {
                        "app_name": "Mobile",
                        "package_name": "com.example.mobile",
                        "main_activity": "com.example.mobile.MainActivity",
                        "min_sdk": "24",
                        "target_sdk": "35",
                    },
                    "application": {"debuggable": False},
                    "permissions": [
                        {"name": "android.permission.INTERNET"},
                        {"name": "android.permission.CAMERA"},
                    ],
                    "components": {"activities": [], "services": [], "receivers": [], "providers": []},
                    "deep_links": [],
                },
            },
            "ios": {"available": False, "metadata": None},
        },
        "opengrep": {
            "results": [
                {
                    "check_id": "react-native.source.cleartext-http",
                    "phoenix_scope": "react_native",
                    "path": str(project / "src" / "api.ts"),
                    "start": {"line": 4},
                },
                {
                    "check_id": "react-native.source.webview-message-bridge",
                    "phoenix_scope": "react_native",
                    "path": str(project / "src" / "Web.tsx"),
                    "start": {"line": 8},
                },
            ],
            "scan_metadata": {
                "scopes": {
                    "react_native": {
                        "status": "success",
                        "applicable": True,
                        "configured_rule_ids": sorted(REACT_NATIVE_RULE_IDS),
                    },
                    "android": {"status": "skipped", "applicable": True, "configured_rule_ids": []},
                    "ios": {"status": "skipped", "applicable": False, "configured_rule_ids": []},
                }
            },
        },
        "gitleaks_outputs": {"gitleaks_report.json": []},
        "trufflehog_outputs": {"trufflehog_results.json": []},
        "syft_outputs": {"sbom.json": {"artifacts": [{"name": "react-native", "version": "0.80.0"}]}},
        "plist_outputs": {},
        "plist_index": None,
    }

    report = ReactNativeScanDetailExtractor().extract_sections(loaded)

    assert report["meta"]["platform"] == "React Native"
    assert set(report["platform_inventory"]) == {
        "source_metadata_assessed",
        "runtime",
        "android",
        "ios",
        "warnings",
    }
    assert report["network_evidence"]["sensitive_information_unencrypted_in_transit"]["present"] is True
    assert report["code_evidence"]["contains_potential_sql_injection"]["present"] is None
    assert report["code_evidence"]["uses_dynamic_code_execution"]["present"] is False
    assert report["code_evidence"]["app_is_debuggable"]["present"] is False
    assert report["code_evidence"]["activities_accessible_to_other_apps"]["present"] is False
    assert report["code_evidence"]["contains_reflection_code"]["present"] is None
    assert report["code_evidence"]["contains_potential_hard_coded_password"]["present"] is False
    assert report["code_evidence"]["insecure_nanopb_library"]["present"] is False
    assert "uses_uiwebview" not in report["code_evidence"]
    assert "copies_sensitive_information_into_clipboard_without_user_consent" not in report["code_evidence"]
    assert "copies_sensitive_information_into_clipboard_without_user_consent" in report["data_storage_evidence"]
    assert report["functionality"]["Camera"]["present"] is True
    assert report["functionality"]["SMS"]["present"] is None
    assert report["manual_review"]["findings"][0]["rule_id"] == "react-native.source.webview-message-bridge"

    canonical = load_report_data(report)
    checks = {
        section["section_name"]: {item["check"]: item for item in section["checks"]}
        for section in canonical["vulnerability_sections"]
    }
    assert checks["Code"]["App is Debuggable"]["result"] == "Not Present"
    assert checks["Code"]["Contains Reflection Code"]["result"] == "Not Evaluated"
    assert checks["Network"]["Contains HostnameVerifier That Accepts All Hostnames"]["result"] == ("Not Evaluated")
    assert checks["Data Storage"]["Accesses External Storage"]["result"] == "Not Present"

    pdf_path = generate_report(report, tmp_path / "react-native-report.pdf")
    assert pdf_path.is_file()
    assert pdf_path.stat().st_size > 0


def test_react_native_extractor_derives_native_metadata_secret_and_sbom_evidence(tmp_path: Path) -> None:
    project = tmp_path / "mobile"
    loaded = {
        "scan_metadata": {"project_path": str(project), "target_type": "SOURCE"},
        "source_metadata": {
            "project": {"project_path": str(project)},
            "runtime": {"react_native_constraint": "0.80.0"},
            "platforms": {"android": True, "ios": True},
            "dependencies": {"declared": [], "resolved": []},
            "android": {
                "available": True,
                "metadata": {
                    "application": {
                        "debuggable": True,
                        "allow_backup": True,
                        "uses_cleartext_traffic": True,
                    },
                    "components": {
                        "activities": [{"name": ".PublicActivity", "exported": True}],
                        "services": [],
                        "receivers": [],
                        "providers": [],
                    },
                    "deep_links": [{"scheme": "mobile", "host": "open"}],
                    "permissions": [{"name": "android.permission.MANAGE_EXTERNAL_STORAGE"}],
                },
            },
            "ios": {
                "available": True,
                "metadata": {
                    "app_transport_security": {
                        "allows_arbitrary_loads": True,
                        "allows_arbitrary_loads_for_media": False,
                        "allows_arbitrary_loads_in_web_content": False,
                        "exception_domains": [
                            {
                                "domain": "api.example.com",
                                "allows_insecure_http_loads": True,
                                "minimum_tls_version": "TLSv1.0",
                                "requires_forward_secrecy": False,
                            }
                        ],
                    },
                    "url_schemes": {"declared_schemes": ["mobile"]},
                    "entitlements": [
                        {
                            "path": "Mobile.entitlements",
                            "metadata": {"security_risk_keys": ["get-task-allow"]},
                        }
                    ],
                },
            },
        },
        "opengrep": {
            "results": [
                {
                    "check_id": "react-native.source.sha1-hash",
                    "phoenix_scope": "react_native",
                    "path": str(project / "src" / "crypto.ts"),
                    "start": {"line": 5},
                },
                {
                    "check_id": "react-native.source.cookie-missing-secure",
                    "phoenix_scope": "react_native",
                    "path": str(project / "src" / "cookies.ts"),
                    "start": {"line": 8},
                },
                {
                    "check_id": "react-native.source.keyboard-cache-exposure",
                    "phoenix_scope": "react_native",
                    "path": str(project / "src" / "Login.tsx"),
                    "start": {"line": 13},
                },
            ],
            "scan_metadata": {
                "scopes": {
                    "react_native": {
                        "status": "success",
                        "applicable": True,
                        "configured_rule_ids": sorted(REACT_NATIVE_RULE_IDS),
                    }
                }
            },
        },
        "gitleaks_outputs": {
            "gitleaks_report.json": [
                {
                    "Description": "Potential password",
                    "File": str(project / "src" / "config.ts"),
                    "StartLine": 7,
                },
                {
                    "Description": "API key",
                    "File": str(project / "src" / "api.ts"),
                    "StartLine": 4,
                },
            ]
        },
        "trufflehog_outputs": {"trufflehog_results.json": []},
        "syft_outputs": {"sbom.json": {"artifacts": [{"name": "nanopb", "version": "1.0.0"}]}},
    }

    report = ReactNativeScanDetailExtractor().extract_sections(loaded)

    assert report["code_evidence"]["app_is_debuggable"]["present"] is True
    assert report["code_evidence"]["application_data_can_be_backed_up"]["present"] is True
    assert report["code_evidence"]["activities_accessible_to_other_apps"]["present"] is True
    assert report["code_evidence"]["application_uses_custom_url_schemes_or_deep_links"]["present"] is True
    assert report["code_evidence"]["contains_potential_hard_coded_password"]["present"] is True
    assert report["code_evidence"]["hardcoded_api_keys_in_bundle"]["present"] is True
    assert report["code_evidence"]["insecure_nanopb_library"]["present"] is True
    assert report["code_evidence"]["insecure_entitlements"]["present"] is True
    assert report["code_evidence"]["uses_sha1_hashing_algorithm"]["present"] is True
    assert report["network_evidence"]["allows_cleartext_traffic_for_all_domains"]["present"] is True
    assert report["network_evidence"]["ats_disabled"]["present"] is True
    assert report["network_evidence"]["ats_exceptions_configured"]["present"] is True
    assert report["network_evidence"]["cookie_missing_secure_flag"]["present"] is True
    assert report["network_evidence"]["certificate_pinning_not_implemented"]["present"] is None
    assert report["data_storage_evidence"]["accesses_external_storage"]["present"] is True
    assert report["data_storage_evidence"]["keyboard_cache_exposure"]["present"] is True


def test_react_native_metadata_preserves_risky_entitlement_names(tmp_path: Path) -> None:
    project = tmp_path / "mobile"
    ios_app = project / "ios" / "Mobile"
    ios_app.mkdir(parents=True)
    (project / "package.json").write_text(
        json.dumps({"name": "mobile", "dependencies": {"react-native": "0.80.0"}}),
        encoding="utf-8",
    )
    (ios_app / "Info.plist").write_bytes(plistlib.dumps({"CFBundleName": "Mobile"}))
    (ios_app / "Mobile.entitlements").write_bytes(
        plistlib.dumps(
            {
                "get-task-allow": True,
                "com.apple.private.example": True,
                "application-identifier": "TEAM.mobile",
            }
        )
    )
    config = ScanConfig(
        project_path=project,
        output_path=tmp_path / "output",
        mode="source",
        platform="ANY",
        stack="REACT_NATIVE",
    )

    result = ReactNativeSourceMetadataScanner().scan(config)[0]
    metadata = json.loads(result.raw_output)
    entitlement_metadata = metadata["ios"]["metadata"]["entitlements"][0]["metadata"]

    assert entitlement_metadata["security_risk_keys"] == [
        "com.apple.private.example",
        "get-task-allow",
    ]


def test_react_native_metadata_preserves_expo_permission_configuration(tmp_path: Path) -> None:
    project = tmp_path / "mobile"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"name": "mobile", "dependencies": {"react-native": "0.80.0"}}),
        encoding="utf-8",
    )
    (project / "app.json").write_text(
        json.dumps(
            {
                "expo": {
                    "name": "Mobile",
                    "plugins": ["expo-location", ["expo-camera", {"cameraPermission": "Take photos"}]],
                    "android": {
                        "permissions": ["CAMERA"],
                        "blockedPermissions": ["android.permission.RECORD_AUDIO"],
                    },
                    "ios": {"infoPlist": {"NSCameraUsageDescription": "Take photos"}},
                }
            }
        ),
        encoding="utf-8",
    )
    config = ScanConfig(
        project_path=project,
        output_path=tmp_path / "output",
        mode="source",
        platform="ANY",
        stack="REACT_NATIVE",
    )

    result = ReactNativeSourceMetadataScanner().scan(config)[0]
    expo = json.loads(result.raw_output)["expo"]

    assert expo["plugins"] == [
        {"name": "expo-location", "options": {}},
        {"name": "expo-camera", "options": {"cameraPermission": "Take photos"}},
    ]
    assert expo["android"]["permissions"] == ["CAMERA"]
    assert expo["android"]["blocked_permissions"] == ["android.permission.RECORD_AUDIO"]
    assert expo["ios"]["info_plist"] == {"NSCameraUsageDescription": "Take photos"}


def test_react_native_endpoint_inventory_redacts_classifies_and_deduplicates(tmp_path: Path) -> None:
    project = tmp_path / "mobile"
    findings = [
        {
            "check_id": "react-native.inventory.url-literal",
            "phoenix_scope": "react_native",
            "path": str(project / "src" / "api.ts"),
            "start": {"line": 4},
            "extra": {
                "lines": 'fetch("https://user:password@api.example.com/users?token=secret&limit=5")'  # pragma: allowlist secret
            },  # pragma: allowlist secret
        },
        {
            "check_id": "react-native.inventory.url-literal",
            "phoenix_scope": "react_native",
            "path": str(project / "src" / "socket.ts"),
            "start": {"line": 8},
            "extra": {"lines": 'new WebSocket("ws://stream.example.com/events")'},
        },
        {
            "check_id": "react-native.inventory.url-literal",
            "phoenix_scope": "react_native",
            "path": str(project / "src" / "dev.ts"),
            "start": {"line": 3},
            "extra": {"lines": 'fetch("http://localhost:8080/health")'},
        },
        {
            "check_id": "react-native.inventory.environment-endpoint",
            "phoenix_scope": "react_native",
            "path": str(project / "src" / "config.ts"),
            "start": {"line": 2},
            "extra": {"lines": "const endpoint = process.env.API_URL"},
        },
        {
            "check_id": "react-native.inventory.dynamic-base-url",
            "phoenix_scope": "react_native",
            "path": str(project / "src" / "client.ts"),
            "start": {"line": 6},
            "extra": {"lines": "axios.create({ baseURL: API_BASE })"},
        },
    ]
    loaded = {
        "scan_metadata": {"project_path": str(project), "target_type": "SOURCE"},
        "source_metadata": {
            "project": {"project_path": str(project)},
            "runtime": {"react_native_constraint": "0.80.0"},
            "platforms": {"android": False, "ios": False},
            "dependencies": {"declared": [], "resolved": []},
        },
        "opengrep": {
            "results": findings,
            "scan_metadata": {
                "scopes": {
                    "react_native": {
                        "status": "success",
                        "applicable": True,
                        "configured_rule_ids": sorted(INVENTORY_RULE_ID_TO_KEY),
                    }
                }
            },
        },
    }

    report = ReactNativeScanDetailExtractor().extract_sections(loaded)
    endpoints = {item["endpoint"]: item for item in report["endpoints"]}

    redacted = "https://[REDACTED]@api.example.com/users?token=[REDACTED]&limit=5"
    assert set(endpoints) == {
        redacted,
        "ws://stream.example.com/events",
        "http://localhost:8080/health",
        "process.env.API_URL",
        "API_BASE",
    }
    assert "password" not in redacted and "secret" not in redacted
    assert endpoints[redacted]["connection_type"] == "fetch"
    assert endpoints[redacted]["transport_security"] == "encrypted"
    assert endpoints["ws://stream.example.com/events"]["transport_security"] == "cleartext"
    assert endpoints["http://localhost:8080/health"]["transport_security"] == "local"
    assert endpoints["process.env.API_URL"]["confidence"] == "dynamic"
    assert {item["url"] for item in report["hardcoded_values"]["urls"]} == {
        redacted,
        "ws://stream.example.com/events",
        "http://localhost:8080/health",
    }


def test_workflow_registers_react_native_post_scan_service(tmp_path: Path) -> None:
    config = ScanConfig(
        project_path=tmp_path / "project",
        output_path=tmp_path / "output",
        mode="source",
        platform="ANY",
        stack="REACT_NATIVE",
    )

    service = MobileAnalysisWorkflowService._build_post_scan_processing_service(config)

    assert service is not None
