from adapters.output.phoenix_report.pdf_report.flutter import map_flutter_details
from domain.report import FlutterDependencyDetails, FlutterReportDetails


def test_maps_flutter_details_for_pdf() -> None:
    mapped = map_flutter_details(
        FlutterReportDetails(
            package_name="com.example.app",
            version_name="1.2.3",
            dart_constraint=">=3.3.0",
            flutter_constraint=">=3.22.0",
            supported_platforms=("android", "ios"),
            dependencies=(FlutterDependencyDetails("http"), FlutterDependencyDetails("path")),
        )
    )
    assert mapped["flutter_details"] == {
        "dart_constraint": ">=3.3.0",
        "flutter_constraint": ">=3.22.0",
        "supported_platforms": ["android", "ios"],
        "dependencies": [
            {"name": "http", "version": "", "constraint": "", "source": "", "group": ""},
            {"name": "path", "version": "", "constraint": "", "source": "", "group": ""},
        ],
    }
