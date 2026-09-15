"""Map native Android source details to the PDF template shape."""

from dataclasses import asdict

from adapters.output.phoenix_report.pdf_report.common import map_functionality
from domain.report.models import NativeAndroidReportDetails


def map_native_android_details(details: NativeAndroidReportDetails) -> dict[str, object]:
    return {
        "application": asdict(details.application),
        "app_components": asdict(details.app_components),
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
        "native_android_details": {
            "package_name": details.package_name,
            "version_name": details.version_name,
            "target_sdk": details.target_sdk,
            "min_sdk": details.min_sdk,
        },
    }
