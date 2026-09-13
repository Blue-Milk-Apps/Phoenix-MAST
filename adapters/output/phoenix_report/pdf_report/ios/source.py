from domain.report.models import NativeIOSReportDetails


def map_native_ios_details(details: NativeIOSReportDetails) -> dict[str, object]:
    return {
        "native_ios_details": {
            "bundle_identifier": details.bundle_identifier,
            "version_name": details.version_name,
            "minimum_os": details.minimum_os,
            "url_schemes": list(details.url_schemes),
        }
    }
