from domain.report import ReactNativeReportDetails


def map_react_native_details(details: ReactNativeReportDetails) -> dict[str, object]:
    return {
        "react_native_details": {
            "package_name": details.package_name,
            "version_name": details.version_name,
            "react_native_constraint": details.runtime.react_native_constraint,
            "expo_constraint": details.runtime.expo_constraint,
            "android_detected": details.platforms.android_detected,
            "ios_detected": details.platforms.ios_detected,
        }
    }
