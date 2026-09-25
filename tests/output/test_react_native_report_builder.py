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
            "app_info": {"package_name": "com.example.app", "version_name": "2.0"},
            "platform_inventory": {
                "runtime": {"react_native_constraint": "0.81.0", "expo_constraint": "~54.0"},
                "android": {"detected": True},
                "ios": {"detected": False},
            },
            "dependency_inventory": {"declared": [{"name": "react", "constraint": "^19"}]},
            "functionality": {"Camera": {"present": True}},
            "permissions": [
                {"name": "camera", "status": "requested", "info": "Runtime request", "usage_description": "Take photos"}
            ],
            "hardcoded_values": {"emails": ["security@example.test"]},
            "endpoints": [{"endpoint": "https://api.example.test", "tags": "HTTP API"}],
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
    assert details.permissions[0].info == "Runtime request"
    assert details.permissions[0].usage_description == "Take photos"
    assert details.hardcoded_values.emails == ("security@example.test",)
    assert details.endpoints[0].endpoint == "https://api.example.test"
    assert details.endpoints[0].tags == "HTTP API"
    assert report.findings_severity.high == 0
    assert report.vulnerability_sections == ()


def test_preserves_actual_platform_labels_for_functionality() -> None:
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
    assert {item.platform.value for item in camera.platform_assessments} == {"react_native", "android", "ios"}
    navigation = next(item for item in details.functionality if item.name == "Navigation")
    assert [item.platform.value for item in navigation.platform_assessments] == ["react_native"]

    assert report.vulnerability_sections == ()


def test_empty_react_native_data_has_no_invented_checks() -> None:
    report = ReactNativeReportDataBuilder().build({}, _metadata())
    assert report.vulnerability_sections == ()
    assert report.risk_summary == ()


def test_rejects_incompatible_target_kind() -> None:
    with pytest.raises(ValueError, match="react_native_source"):
        ReactNativeReportDataBuilder().build({}, _metadata(ReportTargetKind.FLUTTER_SOURCE))
