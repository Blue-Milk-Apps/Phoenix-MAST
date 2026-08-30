"""End-to-end Flutter workflow coverage with external scanners mocked."""

from __future__ import annotations

import json
from pathlib import Path

from application import mobile_analysis_workflow_service as workflow
from domain.models import ScanConfig, ScanResult, ScanType


class _ArtifactScanner:
    name = "Flutter fixture scanners"

    def __init__(self, results: list[ScanResult]) -> None:
        self._results = results

    @property
    def scan_type(self) -> ScanType:
        return self._results[0].scan_type

    def is_available(self) -> bool:
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        return self._results


def test_flutter_workflow_persists_post_scan_output_and_requests_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project_path = tmp_path / "example_app"
    project_path.mkdir()
    output_path = tmp_path / "results"
    config = ScanConfig(
        project_path=project_path,
        output_path=output_path,
        mode="source",
        scan_label="Flutter source",
        platform="ANY",
        stack="FLUTTER",
    )
    scanner_results = [
        ScanResult(
            scanner_name="Flutter Source Metadata Scanner",
            scan_type=ScanType.FLUTTER_SOURCE_METADATA,
            raw_output=json.dumps(
                {
                    "extraction": {"status": "complete", "warnings": []},
                    "identity": {"package_name": "example_app", "version_name": "1.0.0"},
                    "sdk": {"dart_constraint": ">=3.3.0", "flutter_constraint": ">=3.22.0"},
                    "platforms": {
                        "android": False,
                        "ios": False,
                        "web": True,
                        "linux": False,
                        "macos": False,
                        "windows": False,
                    },
                    "android": {"available": False, "metadata": None},
                    "ios": {"available": False, "metadata": None},
                    "dependencies": {
                        "direct": [{"name": "http", "constraint": "^1.2.0", "source": "hosted"}],
                        "development": [],
                        "resolved": [],
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
            raw_output=json.dumps({"artifacts": [{"name": "http", "version": "1.2.0"}]}),
            relative_target_path="sbom.json",
        ),
    ]
    opengrep_result = ScanResult(
        scanner_name="Flutter Scoped OpenGrep Scanner",
        scan_type=ScanType.OPENGREP_SOURCE,
        raw_output=json.dumps(
            {
                "results": [
                    {
                        "check_id": "flutter.source.sql-injection",
                        "phoenix_scope": "flutter",
                        "path": str(project_path / "lib" / "database.dart"),
                        "start": {"line": 12},
                    }
                ],
                "scan_metadata": {
                    "scopes": {
                        "flutter": {
                            "status": "success",
                            "configured_rule_ids": ["flutter.source.sql-injection"],
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

    post_scan_path = output_path / workflow.MobileAnalysisWorkflowService.POST_SCAN_OUTPUT_FILE_NAME
    post_scan = json.loads(post_scan_path.read_text(encoding="utf-8"))
    assert post_scan["meta"]["platform"] == "Flutter"
    assert post_scan["meta"]["target_type"] == "SOURCE"
    assert post_scan["dependency_inventory"]["declared"][0]["name"] == "http"
    assert post_scan["code_evidence"]["contains_potential_sql_injection"] == {
        "present": True,
        "evidence": "lib/database.dart:12",
        "details": ["lib/database.dart:12"],
    }
    assert len(generated_reports) == 1
    report_data, report_path = generated_reports[0]
    assert report_data == post_scan
    assert report_path.name == "example_app_phoenix_Report.pdf"
    assert report_path.read_bytes() == b"%PDF-fake"
