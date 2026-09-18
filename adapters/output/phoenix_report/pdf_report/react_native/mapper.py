from adapters.output.phoenix_report.pdf_report.common import map_functionality
from domain.report import ReactNativeReportDetails


def map_react_native_details(details: ReactNativeReportDetails) -> dict[str, object]:
    return {
        "functionality": map_functionality(details.functionality),
        "permissions": [
            {
                "permission": item.permission,
                "status": item.status,
                "info": item.info,
                "usage_description": item.usage_description,
                "general_description": item.general_description,
            }
            for item in details.permissions
        ],
        "hardcoded_values": {
            "urls": [{"url": item.url, "country": item.country} for item in details.hardcoded_values.urls],
            "emails": list(details.hardcoded_values.emails),
            "secrets": [{"value": item.value} for item in details.hardcoded_values.secrets],
        },
        "endpoints": [
            {
                "endpoint": item.endpoint,
                "tags": item.tags,
                "ip_address": item.ip_address,
                "country": item.country,
            }
            for item in details.endpoints
        ],
        "react_native_details": {
            "package_name": details.package_name,
            "version_name": details.version_name,
            "react_native_constraint": details.runtime.react_native_constraint,
            "expo_constraint": details.runtime.expo_constraint,
            "android_detected": details.platforms.android_detected,
            "ios_detected": details.platforms.ios_detected,
        },
    }
