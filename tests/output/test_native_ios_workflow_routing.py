from adapters.output.phoenix_report.builders.ios import NativeIOSReportDataBuilder
from adapters.output.phoenix_report.pdf_report import PdfReportGenerator
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
            "app_info": {"bundle_identifier": "com.example.ios", "version_name": "1.0", "icon_path": "app.png"},
            "url_schemes": [{"url_name": "Example App", "schemes": ["dontdothis", "example"]}],
        }
    )
    assert report.metadata.target.target_kind == ReportTargetKind.NATIVE_IOS_SOURCE
    assert report.platform_details.bundle_identifier == "com.example.ios"
    assert PdfReportGenerator._presentation_data(report)["app_info"]["icon_path"] == "app.png"
    expected = [{"url_name": "Example App", "schemes": ("dontdothis", "example")}]
    assert map_native_ios_details(report.platform_details)["url_schemes"] == expected
    assert PdfReportGenerator._merged_presentation_data(report)["url_schemes"] == expected


def test_native_ios_maps_expanded_inventories() -> None:
    report = ReportGenerationService([NativeIOSReportDataBuilder()]).build_report_data(
        {
            "target_information": {
                "target_kind": "native_ios_source",
                "platform": "ios",
                "target_type": "source",
                "stack": "native_ios",
            },
            "app_info": {"bundle_identifier": "com.example.ios", "version_name": "1.0", "minimum_os": "16.0"},
            "functionality": {"Camera": {"present": True, "explanation": "Detected"}},
            "permissions": [{"permission": "camera", "status": "requested"}],
            "hardcoded_values": {"emails": ["security@example.test"]},
            "endpoints": [{"endpoint": "https://api.example.test"}],
            "third_party_sdks": {"analytics": {"Firebase": True}},
        }
    )
    details = report.platform_details
    assert details.minimum_os == "16.0"
    assert details.functionality[0].name == "Camera"
    assert details.permissions[0].permission == "camera"
    assert details.hardcoded_values.emails == ("security@example.test",)
    assert details.endpoints[0].endpoint == "https://api.example.test"
    assert details.third_party_sdks == ("analytics",)
