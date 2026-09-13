"""Map native Android source details to the PDF template shape."""

from domain.report.models import NativeAndroidReportDetails


def map_native_android_details(details: NativeAndroidReportDetails) -> dict[str, object]:
    return {
        "native_android_details": {
            "package_name": details.package_name,
            "version_name": details.version_name,
            "target_sdk": details.target_sdk,
            "min_sdk": details.min_sdk,
        }
    }
