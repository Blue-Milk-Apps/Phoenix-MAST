from adapters.output.phoenix_report.builders.android import NativeAndroidReportDataBuilder
from application.report_generation_service import ReportGenerationService
from domain.report import ReportTargetKind


def test_native_android_target_information_resolves_native_builder() -> None:
    report = ReportGenerationService([NativeAndroidReportDataBuilder()]).build_report_data(
        {
            "target_information": {
                "target_kind": "native_android_source",
                "platform": "android",
                "target_type": "source",
                "stack": "native_android",
            },
            "app_info": {"package_name": "com.example", "version_name": "1.0"},
        }
    )
    assert report.metadata.target.target_kind == ReportTargetKind.NATIVE_ANDROID_SOURCE
    assert report.platform_details.package_name == "com.example"
