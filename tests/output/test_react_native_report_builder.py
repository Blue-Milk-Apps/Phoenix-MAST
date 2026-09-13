import pytest

from adapters.output.phoenix_report.builders.react_native import ReactNativeReportDataBuilder
from domain.report import ReportMetadata, ReportPlatform, ReportStack, ReportTarget, ReportTargetKind, ReportTargetType


def _metadata(kind: ReportTargetKind = ReportTargetKind.REACT_NATIVE_SOURCE) -> ReportMetadata:
    return ReportMetadata(
        target=ReportTarget(kind, ReportPlatform.REACT_NATIVE, ReportTargetType.SOURCE, ReportStack.REACT_NATIVE)
    )


def test_maps_react_native_details_and_inventories() -> None:
    report = ReactNativeReportDataBuilder().build(
        {
            "source_metadata": {
                "identity": {"package_name": "com.example.app", "version": "2.0"},
                "runtime": {"react_native_constraint": "0.81.0", "expo_constraint": "~54.0"},
                "platforms": {"android": True, "ios": False},
                "dependencies": {"declared": [{"name": "react", "constraint": "^19"}]},
            },
            "functionality": {"Camera": {"present": True}},
            "permissions": [{"name": "camera", "status": "requested"}],
            "hardcoded_values": {"emails": ["security@example.test"]},
            "endpoints": [{"endpoint": "https://api.example.test"}],
            "code_evidence": {"unsafe": {"present": True, "severity": "high", "evidence": "src/App.tsx:4"}},
        },
        _metadata(),
    )
    details = report.platform_details
    assert details.package_name == "com.example.app"
    assert details.runtime.react_native_constraint == "0.81.0"
    assert details.platforms.android_detected is True
    assert details.dependencies[0].name == "react"
    assert details.functionality[0].name == "Camera"
    assert details.permissions[0].permission == "camera"
    assert details.hardcoded_values.emails == ("security@example.test",)
    assert details.endpoints[0].endpoint == "https://api.example.test"
    assert report.findings_severity.high == 1


def test_empty_react_native_data_has_four_empty_sections() -> None:
    report = ReactNativeReportDataBuilder().build({}, _metadata())
    assert len(report.vulnerability_sections) == 4
    assert all(not section.checks for section in report.vulnerability_sections)


def test_rejects_incompatible_target_kind() -> None:
    with pytest.raises(ValueError, match="react_native_source"):
        ReactNativeReportDataBuilder().build({}, _metadata(ReportTargetKind.FLUTTER_SOURCE))
