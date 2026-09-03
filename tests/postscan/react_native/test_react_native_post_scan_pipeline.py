from pathlib import Path

from adapters.output.phoenix_report.generate_report import generate_report
from adapters.post_scan.react_native import ReactNativeScanDetailExtractor
from application.mobile_analysis_workflow_service import MobileAnalysisWorkflowService
from domain.models import ScanConfig
from domain.post_scan.react_native import REACT_NATIVE_RULE_IDS


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
                    "permissions": [{"name": "android.permission.INTERNET"}],
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
    assert report["manual_review"]["findings"][0]["rule_id"] == "react-native.source.webview-message-bridge"

    pdf_path = generate_report(report, tmp_path / "react-native-report.pdf")
    assert pdf_path.is_file()
    assert pdf_path.stat().st_size > 0


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
