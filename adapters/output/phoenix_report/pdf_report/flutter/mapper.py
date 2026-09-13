"""Map typed Flutter report details to the PDF template shape."""

from domain.report import FlutterReportDetails


def map_flutter_details(details: FlutterReportDetails) -> dict[str, object]:
    return {
        "flutter_details": {
            "dart_constraint": details.dart_constraint,
            "flutter_constraint": details.flutter_constraint,
            "supported_platforms": list(details.supported_platforms),
            "dependencies": list(details.dependencies),
        },
    }
