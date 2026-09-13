"""Map typed Flutter report details to the PDF template shape."""

from domain.report import FlutterReportDetails


def map_flutter_details(details: FlutterReportDetails) -> dict[str, object]:
    return {
        "functionality": {
            item.name: {"present": item.present, "explanation": item.explanation} for item in details.functionality
        },
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
        "flutter_details": {
            "dart_constraint": details.dart_constraint,
            "flutter_constraint": details.flutter_constraint,
            "supported_platforms": list(details.supported_platforms),
            "dependencies": [
                {
                    "name": dependency.name,
                    "version": dependency.version,
                    "constraint": dependency.constraint,
                    "source": dependency.source,
                    "group": dependency.group,
                }
                for dependency in details.dependencies
            ],
        },
    }
