from adapters.output.phoenix_report.pdf_report.common import map_functionality
from domain.report.models import NativeIOSReportDetails


def map_native_ios_details(details: NativeIOSReportDetails) -> dict[str, object]:
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
            {"endpoint": item.endpoint, "tags": item.tags, "ip_address": item.ip_address, "country": item.country}
            for item in details.endpoints
        ],
        "native_ios_details": {
            "bundle_identifier": details.bundle_identifier,
            "version_name": details.version_name,
            "minimum_os": details.minimum_os,
            "url_schemes": list(details.url_schemes),
            "third_party_sdks": list(details.third_party_sdks),
            "manual_review_available": details.manual_review_available,
            "manual_review_status": details.manual_review_status,
            "manual_review_findings": [
                {
                    "rule_id": finding.rule_id,
                    "scope": finding.scope,
                    "severity": finding.severity,
                    "location": finding.location,
                    "reason": finding.reason,
                    "message": finding.message,
                }
                for finding in details.manual_review_findings
            ],
        },
    }
