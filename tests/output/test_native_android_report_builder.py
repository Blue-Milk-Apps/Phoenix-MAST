from adapters.output.phoenix_report.builders.android import NativeAndroidReportDataBuilder
from adapters.output.phoenix_report.pdf_report.android import map_native_android_details
from domain.report import ReportMetadata, ReportPlatform, ReportStack, ReportTarget, ReportTargetKind, ReportTargetType


def _metadata() -> ReportMetadata:
    return ReportMetadata(
        ReportTarget(
            ReportTargetKind.NATIVE_ANDROID_SOURCE,
            ReportPlatform.ANDROID,
            ReportTargetType.SOURCE,
            ReportStack.NATIVE_ANDROID,
        )
    )


def test_maps_native_android_details_and_pdf_shape() -> None:
    report = NativeAndroidReportDataBuilder().build(
        {
            "app_info": {"package_name": "com.example", "version_name": "1.0", "target_sdk": "35", "min_sdk": "24"},
            "functionality": {"Camera": {"present": True}},
            "permissions": [{"name": "camera", "status": "requested"}],
            "hardcoded_values": {"emails": ["security@example.test"]},
            "endpoints": [{"endpoint": "https://api.example.test"}],
        },
        _metadata(),
    )
    details = report.platform_details
    assert details.package_name == "com.example"
    assert details.target_sdk == "35"
    assert details.functionality[0].name == "Camera"
    assert details.permissions[0].permission == "camera"
    assert details.hardcoded_values.emails == ("security@example.test",)
    assert map_native_android_details(details)["native_android_details"]["min_sdk"] == "24"
