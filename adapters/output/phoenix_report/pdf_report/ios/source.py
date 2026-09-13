from domain.report.models import NativeIOSReportDetails


def map_native_ios_details(details: NativeIOSReportDetails) -> dict[str, object]:
    return {
        "functionality": {
            item.name: {"present": item.present, "explanation": item.explanation} for item in details.functionality
        },
        "permissions": [{"permission": item.permission, "status": item.status} for item in details.permissions],
        "hardcoded_values": {
            "urls": [{"url": item.url, "country": item.country} for item in details.hardcoded_values.urls],
            "emails": list(details.hardcoded_values.emails),
            "secrets": [{"value": item.value} for item in details.hardcoded_values.secrets],
        },
        "endpoints": [
            {"endpoint": item.endpoint, "tags": item.tags, "ip_address": item.ip_address, "country": item.country}
            for item in details.endpoints
        ],
        "native_ios_details": {
            "bundle_identifier": details.bundle_identifier,
            "version_name": details.version_name,
            "minimum_os": details.minimum_os,
            "url_schemes": list(details.url_schemes),
            "third_party_sdks": list(details.third_party_sdks),
        },
    }
