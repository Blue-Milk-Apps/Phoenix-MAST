from adapters.output.phoenix_report.pdf_report.flutter import map_flutter_details
from domain.report import (
    EndpointDetails,
    FlutterDependencyDetails,
    FlutterReportDetails,
    FunctionalityDetails,
    HardcodedSecretDetails,
    HardcodedUrlDetails,
    HardcodedValuesDetails,
    PermissionDetails,
)


def test_maps_flutter_details_for_pdf() -> None:
    mapped = map_flutter_details(
        FlutterReportDetails(
            package_name="com.example.app",
            version_name="1.2.3",
            dart_constraint=">=3.3.0",
            flutter_constraint=">=3.22.0",
            supported_platforms=("android", "ios"),
            dependencies=(FlutterDependencyDetails("http"), FlutterDependencyDetails("path")),
            functionality=(FunctionalityDetails("Camera", True, "Detected"),),
            permissions=(PermissionDetails("camera", "requested"),),
            hardcoded_values=HardcodedValuesDetails(
                urls=(HardcodedUrlDetails("https://example.test", "US"),),
                emails=("security@example.test",),
                secrets=(HardcodedSecretDetails("secret-value"),),
            ),
            endpoints=(EndpointDetails("https://api.example.test", country="US"),),
        )
    )
    assert mapped["functionality"]["Camera"]["present"] is True
    assert mapped["permissions"][0]["permission"] == "camera"
    assert mapped["hardcoded_values"]["secrets"][0]["value"] == "secret-value"
    assert mapped["endpoints"][0]["endpoint"] == "https://api.example.test"
    assert mapped["flutter_details"] == {
        "dart_constraint": ">=3.3.0",
        "flutter_constraint": ">=3.22.0",
        "supported_platforms": ["android", "ios"],
        "dependencies": [
            {"name": "http", "version": "", "constraint": "", "source": "", "group": ""},
            {"name": "path", "version": "", "constraint": "", "source": "", "group": ""},
        ],
    }
