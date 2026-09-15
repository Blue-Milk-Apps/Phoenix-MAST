"""Map typed Flutter report details to the PDF template shape."""

from domain.report import FlutterReportDetails


def map_flutter_details(details: FlutterReportDetails) -> dict[str, object]:
    presentation = details.presentation
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
        "flutter_presentation": {
            "extraction_status": presentation.extraction_status,
            "dart_sdk_constraint": presentation.dart_sdk_constraint,
            "flutter_sdk_constraint": presentation.flutter_sdk_constraint,
            "android_application_id": presentation.android_application_id,
            "ios_bundle_identifier": presentation.ios_bundle_identifier,
            "description": presentation.description,
            "homepage": presentation.homepage,
            "repository": presentation.repository,
            "warnings": list(presentation.warnings),
            "platforms": [
                {
                    "name": platform.name,
                    "detected": platform.detected,
                    "metadata_status": platform.metadata_status,
                    "identifier": platform.identifier,
                    "version": platform.version,
                    "requirements": platform.requirements,
                }
                for platform in presentation.platforms
            ],
            "dependencies": {
                "metadata_status": presentation.dependencies.metadata_status,
                "sbom_status": presentation.dependencies.sbom_status,
                "declared": [
                    {
                        "name": dependency.name,
                        "constraint": dependency.constraint,
                        "scope": dependency.scope,
                        "source": dependency.source,
                    }
                    for dependency in presentation.dependencies.declared
                ],
                "resolved": [
                    {
                        "name": dependency.name,
                        "version": dependency.version,
                        "dependency_kind": dependency.dependency_kind,
                        "source": dependency.source,
                    }
                    for dependency in presentation.dependencies.resolved
                ],
                "sbom_packages": [
                    {
                        "name": package.name,
                        "version": package.version,
                        "output_path": package.output_path,
                    }
                    for package in presentation.dependencies.sbom_packages
                ],
            },
            "deep_links_assessed": presentation.deep_links_assessed,
            "deep_links": [
                {"uri": link.uri, "component": link.component, "mime_type": link.mime_type}
                for link in presentation.deep_links
            ],
            "url_schemes_assessed": presentation.url_schemes_assessed,
            "url_schemes": [
                {"url_name": scheme.url_name, "schemes": list(scheme.schemes)} for scheme in presentation.url_schemes
            ],
            "queried_url_schemes": list(presentation.queried_url_schemes),
            "manual_review_available": presentation.manual_review_available,
            "manual_review_status": presentation.manual_review_status,
            "manual_review_findings": [
                {
                    "rule_id": finding.rule_id,
                    "scope": finding.scope,
                    "severity": finding.severity,
                    "location": finding.location,
                    "reason": finding.reason,
                    "message": finding.message,
                }
                for finding in presentation.manual_review_findings
            ],
        },
    }
