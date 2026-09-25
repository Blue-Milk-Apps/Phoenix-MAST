from adapters.output.phoenix_report.builders.android import NativeAndroidReportDataBuilder
from adapters.output.phoenix_report.pdf_report import PdfReportGenerator
from adapters.output.phoenix_report.pdf_report.presentation import PdfPresentation
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
            "deep_links": {
                "deep_links": [
                    {"component": "com.example.MainActivity", "scheme": "dontdothis"},
                    {"component": "com.example.MainActivity", "scheme": "dontdothis"},
                    {"component": "com.example.MainActivity", "scheme": "https"},
                    {"component": "com.example.MainActivity", "scheme": ""},
                ]
            },
        }
    )
    assert report.metadata.target.target_kind == ReportTargetKind.NATIVE_ANDROID_SOURCE
    assert report.platform_details.package_name == "com.example"
    assert PdfReportGenerator._merged_presentation_data(report)["url_schemes"] == [
        {"url_name": "com.example.MainActivity", "schemes": ("dontdothis",)}
    ]
    assert PdfPresentation.for_target_kind(report.metadata.target.target_kind).show_url_schemes
