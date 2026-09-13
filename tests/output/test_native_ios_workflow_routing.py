from adapters.output.phoenix_report.builders.ios import NativeIOSReportDataBuilder
from adapters.output.phoenix_report.pdf_report.ios import map_native_ios_details
from application.report_generation_service import ReportGenerationService
from domain.report import ReportTargetKind


def test_native_ios_target_information_resolves_native_builder() -> None:
    report = ReportGenerationService([NativeIOSReportDataBuilder()]).build_report_data(
        {
            "target_information": {
                "target_kind": "native_ios_source",
                "platform": "ios",
                "target_type": "source",
                "stack": "native_ios",
            },
            "app_info": {"bundle_identifier": "com.example.ios", "version_name": "1.0"},
            "url_schemes": [{"url_name": "example"}],
        }
    )
    assert report.metadata.target.target_kind == ReportTargetKind.NATIVE_IOS_SOURCE
    assert report.platform_details.bundle_identifier == "com.example.ios"
    assert map_native_ios_details(report.platform_details)["native_ios_details"]["url_schemes"] == ["example"]
