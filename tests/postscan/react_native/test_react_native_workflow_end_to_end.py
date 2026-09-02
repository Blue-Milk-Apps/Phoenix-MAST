"""End-to-end React Native workflow coverage with external scanners mocked."""

from __future__ import annotations

import json
from pathlib import Path

from application import mobile_analysis_workflow_service as workflow
from domain.models import ScanConfig, ScanResult, ScanType
from domain.post_scan.react_native import REACT_NATIVE_RULE_IDS


class _ArtifactScanner:
    name = "React Native fixture scanners"

    def __init__(self, results: list[ScanResult]) -> None:
        self._results = results

    @property
    def scan_type(self) -> ScanType:
        return self._results[0].scan_type

    def is_available(self) -> bool:
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        return self._results


def test_react_native_workflow_persists_post_scan_output_and_requests_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_path = tmp_path / "example-app"
    project_path.mkdir()
    output_path = tmp_path / "results"
    config = ScanConfig(
        project_path=project_path,
        output_path=output_path,
        mode="source",
        scan_label="React Native source",
        platform="ANY",
        stack="REACT_NATIVE",
    )
    scanner_results = [
        ScanResult(
            scanner_name="React Native Metadata Scanner",
            scan_type=ScanType.REACT_NATIVE_METADATA,
            raw_output=json.dumps(
                {
                    "extraction": {"status": "complete", "warnings": []},
                    "project": {
                        "package_json_path": "package.json",
                        "lockfiles": ["package-lock.json"],
                        "package_manager": "npm",
                    },
                    "identity": {
                        "package_name": "example-app",
                        "display_name": "Example App",
                        "version": "1.0.0",
                    },
                    "framework": {
                        "react_native_version": "0.81.0",
                        "react_version": "19.1.0",
                        "expo_version": "",
                        "typescript": True,
                    },
                    "engines": {"node": ">=20"},
                    "entrypoints": {"package_main": "index.js", "files": ["index.js"]},
                    "platforms": {"android": False, "ios": False},
                    "android": {"available": False, "metadata": None},
                    "ios": {"available": False, "metadata": None},
                    "dependencies": {
                        "direct": [
                            {
                                "name": "react-native",
                                "constraint": "0.81.0",
                                "source": "registry",
                            }
                        ],
                        "development": [],
                    },
                }
            ),
            relative_target_path="project_metadata.json",
        ),
        ScanResult(
            scanner_name="Gitleaks",
            scan_type=ScanType.GITLEAKS,
            raw_output="[]",
            relative_target_path="gitleaks_report.json",
        ),
        ScanResult(
            scanner_name="Syft",
            scan_type=ScanType.SYFT,
            raw_output=json.dumps({"artifacts": [{"name": "react-native", "version": "0.81.0"}]}),
            relative_target_path="sbom.json",
        ),
    ]
    opengrep_result = ScanResult(
        scanner_name="React Native Scoped OpenGrep Scanner",
        scan_type=ScanType.OPENGREP_SOURCE,
        raw_output=json.dumps(
            {
                "success": True,
                "results": [
                    {
                        "check_id": "react-native.source.cleartext-http",
                        "phoenix_scope": "react_native",
                        "path": str(project_path / "src" / "api.ts"),
                        "start": {"line": 12},
                        "extra": {"message": "Cleartext HTTP endpoint"},
                    }
                ],
                "errors": [],
                "scan_metadata": {
                    "scopes": {
                        "react_native": {
                            "status": "success",
                            "configured_rule_ids": sorted(REACT_NATIVE_RULE_IDS),
                        }
                    }
                },
            }
        ),
        relative_target_path="opengrep_results.json",
    )
    generated_reports: list[tuple[dict, Path]] = []

    monkeypatch.setattr(
        workflow.MobileScannerFactory,
        "build_scanner_list",
        lambda self, scan_config: [_ArtifactScanner(scanner_results)],
    )
    monkeypatch.setattr(
        workflow.MobileAnalysisWorkflowService,
        "_perform_opengrep_scan",
        lambda self, scan_config, scan_output_method: [opengrep_result],
    )

    def fake_generate_report(data: dict, report_path: Path) -> Path:
        generated_reports.append((data, report_path))
        report_path.write_bytes(b"%PDF-fake")
        return report_path

    monkeypatch.setattr(workflow, "generate_report", fake_generate_report)

    workflow.MobileAnalysisWorkflowService().run(config)

    assert (output_path / "react_native_metadata" / "project_metadata.json").is_file()
    post_scan_path = output_path / workflow.MobileAnalysisWorkflowService.POST_SCAN_OUTPUT_FILE_NAME
    post_scan = json.loads(post_scan_path.read_text(encoding="utf-8"))
    assert post_scan["meta"]["platform"] == "React Native"
    assert post_scan["meta"]["app_display_name"] == "Example App"
    assert post_scan["meta"]["target_type"] == "SOURCE"
    assert post_scan["app_info"]["react_native_version"] == "0.81.0"
    assert post_scan["dependency_inventory"]["declared"][0]["name"] == "react-native"
    assert post_scan["dependency_inventory"]["sbom_packages"] == [
        {"name": "react-native", "output_path": "sbom.json", "version": "0.81.0"}
    ]
    assert post_scan["hardcoded_values"] == {"emails": [], "secrets": [], "urls": []}
    assert post_scan["network_evidence"]["sensitive_information_unencrypted_in_transit"] == {
        "details": ["src/api.ts:12: Cleartext HTTP endpoint"],
        "evidence": "src/api.ts:12: Cleartext HTTP endpoint",
        "present": True,
    }
    assert post_scan["code_evidence"]["contains_potential_sql_injection"]["present"] is False
    assert len(generated_reports) == 1
    report_data, report_path = generated_reports[0]
    assert report_data == post_scan
    assert report_path.name == "Example_App_phoenix_Report.pdf"
    assert report_path.read_bytes() == b"%PDF-fake"
