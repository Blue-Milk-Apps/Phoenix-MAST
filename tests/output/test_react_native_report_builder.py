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
            "code_evidence": {"uses_dynamic_code_execution": {"present": True, "evidence": "src/App.tsx:4"}},
            "data_storage_evidence": {"deprecated_keychain_attributes": {"present": True}},
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
    keychain = next(
        check
        for section in report.vulnerability_sections
        if section.name == "Data Storage"
        for check in section.checks
        if check.name == "Application Utilizes Deprecated Keychain Attributes"
    )
    assert keychain.severity.value == "medium"


def test_uses_native_platform_labels_for_platform_backed_items() -> None:
    report = ReactNativeReportDataBuilder().build(
        {
            "functionality": {
                "Camera": {"present": True},
                "Navigation": {"present": True},
            },
            "functionality_platform_assessments": {
                "Camera": {
                    "react_native": {"status": "present", "explanation": "JS camera module detected."},
                    "android": {"status": "present", "explanation": "Android camera permission declared."},
                    "ios": {"status": "not_evaluated", "explanation": "iOS evidence unavailable."},
                },
                "Navigation": {
                    "react_native": {"status": "present", "explanation": "React Navigation dependency declared."},
                },
            },
            "platform_inventory": {
                "runtime": {
                    "security_check_platform_assessments": {
                        "uses_dynamic_code_execution": {
                            "react_native": {"status": "present", "explanation": "JS eval detected."},
                            "android": {"status": "not_present", "explanation": "No Android hit."},
                        },
                        "uses_sha1_hashing_algorithm": {
                            "react_native": {"status": "present", "explanation": "JS SHA1 detected."},
                            "android": {"status": "present", "explanation": "Android SHA1 detected."},
                        },
                    }
                }
            },
        },
        _metadata(),
    )

    details = report.platform_details
    camera = next(item for item in details.functionality if item.name == "Camera")
    assert {item.platform.value for item in camera.platform_assessments} == {"android", "ios"}
    navigation = next(item for item in details.functionality if item.name == "Navigation")
    assert [item.platform.value for item in navigation.platform_assessments] == ["react_native"]

    checks = {item.name: item for section in report.vulnerability_sections for item in section.checks}
    assert [item.platform.value for item in checks["Uses Dynamic Code Execution"].platform_assessments] == [
        "react_native"
    ]
    assert [item.platform.value for item in checks["Uses SHA1 Hashing Algorithm"].platform_assessments] == ["android"]


def test_empty_react_native_data_has_four_empty_sections() -> None:
    report = ReactNativeReportDataBuilder().build({}, _metadata())
    assert len(report.vulnerability_sections) == 4
    assert [len(section.checks) for section in report.vulnerability_sections] == [26, 28, 23, 1]


def test_rejects_incompatible_target_kind() -> None:
    with pytest.raises(ValueError, match="react_native_source"):
        ReactNativeReportDataBuilder().build({}, _metadata(ReportTargetKind.FLUTTER_SOURCE))
