import json
import plistlib
from pathlib import Path

from adapters.output.phoenix_report.builders.react_native import ReactNativeReportDataBuilder
from adapters.output.phoenix_report.pdf_report import PdfReportGenerator
from adapters.post_scan.react_native import ReactNativeScanDetailExtractor
from adapters.scanners.react_native.react_native_source_metadata_scanner import (
    ReactNativeSourceMetadataScanner,
)
from application.mobile_analysis_workflow_service import MobileAnalysisWorkflowService
from application.report_generation_service import ReportGenerationService
from domain.models import ScanConfig
from domain.post_scan.rule_assessment import rule_assessments
from tests.rule_fixtures import assessment_payload, rule, scoped_payload


def test_react_native_extractor_builds_mobile_only_report_and_pdf(tmp_path):
    payload = scoped_payload(
        react_native=assessment_payload(
            rule("customer.transport"),
            rule("customer.bridge", finding_type="review"),
            category="networking",
            results=[{"check_id": "customer.transport"}, {"check_id": "customer.bridge"}],
        )
    )
    sections = ReactNativeScanDetailExtractor().extract_sections({"opengrep": payload})
    assert not any(key.endswith("_evidence") for key in sections)
    sections["rule_assessments"] = rule_assessments(payload)
    sections["target_information"] = {
        "target_kind": "react_native_source",
        "platform": "react_native",
        "target_type": "source",
        "stack": "react_native",
    }
    report = ReportGenerationService([ReactNativeReportDataBuilder()]).build_report_data(sections)
    assert [s.name for s in report.vulnerability_sections] == ["Networking"]
    assert len(report.vulnerability_sections[0].checks) == 2
    assert report.findings_severity.high == 1
    pdf = PdfReportGenerator().generate(report, tmp_path / "react-native-report.pdf")
    assert pdf.is_file() and pdf.stat().st_size > 0


def test_react_native_extractor_keeps_inventory_without_python_vulnerability_inference(tmp_path):
    sections = ReactNativeScanDetailExtractor().extract_sections(
        {
            "source_metadata": {"android": {"available": True, "metadata": {"application": {"debuggable": True}}}},
            "gitleaks_outputs": {
                "gitleaks_report.json": [{"RuleID": "example.secret", "File": "config.ts", "Description": "API key"}]
            },
            "syft_outputs": {"sbom.json": {"artifacts": [{"name": "nanopb", "version": "1.0.0"}]}},
        }
    )
    assert not any(key.endswith("_evidence") for key in sections)
    assert "manual_review" not in sections
    assert sections["application"]["debuggable"] is True
    assert sections["hardcoded_values"]["secrets"]
    assert sections["dependency_inventory"]["sbom_packages"][0]["name"] == "nanopb"


def test_react_native_metadata_does_not_classify_entitlement_risk(tmp_path: Path) -> None:
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

    assert "security_risk_keys" not in entitlement_metadata


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


def test_removed_inventory_findings_do_not_create_endpoint_sections() -> None:
    sections = ReactNativeScanDetailExtractor().extract_sections(
        {
            "opengrep": {
                "results": [
                    {
                        "check_id": "react-native.inventory.url-literal",
                        "phoenix_scope": "react_native",
                        "extra": {"lines": 'fetch("https://api.example.test")'},
                    }
                ]
            },
        }
    )
    assert "endpoints" not in sections
    assert "hardcoded_values" not in sections


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
