"""Build standard report data from Flutter source post-scan output."""

from typing import Any, Mapping

from adapters.output.phoenix_report.builders.source import SourceReportDataBuilder
from domain.report import (
    CheckResult,
    CheckSeverity,
    EndpointDetails,
    FindingSeverity,
    FlutterDeclaredDependency,
    FlutterDeepLink,
    FlutterDependencyDetails,
    FlutterDependencyPresentation,
    FlutterManualReviewFinding,
    FlutterPlatformPresentation,
    FlutterPresentationDetails,
    FlutterReportDetails,
    FlutterResolvedDependency,
    FlutterSbomPackage,
    FlutterUrlScheme,
    FunctionalityDetails,
    HardcodedSecretDetails,
    HardcodedUrlDetails,
    HardcodedValuesDetails,
    PermissionDetails,
    ReportTargetKind,
    RiskLevel,
    SecurityCheck,
    VulnerabilitySection,
)


class FlutterReportDataBuilder(SourceReportDataBuilder):
    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.FLUTTER_SOURCE

    def _build_details(self, post_scan_data: Mapping[str, Any]) -> FlutterReportDetails:
        return self._details(post_scan_data)

    @classmethod
    def _section(cls, name: str, key: str, data: Mapping[str, Any]) -> VulnerabilitySection:
        evidence = data.get(key) if isinstance(data.get(key), Mapping) else {}
        checks = tuple(
            cls._check(str(check_name), value) for check_name, value in evidence.items() if isinstance(value, Mapping)
        )
        return VulnerabilitySection(name=name, findings_text="", checks=checks)

    @staticmethod
    def _check(name: str, value: Mapping[str, Any]) -> SecurityCheck:
        present = value.get("present")
        result = (
            CheckResult.PRESENT
            if present is True
            else CheckResult.NOT_PRESENT
            if present is False
            else CheckResult.NOT_EVALUATED
        )
        severity = str(value.get("severity", "info")).lower()
        check_severity = next((item for item in CheckSeverity if item.value == severity), CheckSeverity.INFO)
        return SecurityCheck(
            name=name,
            severity=check_severity,
            result=result,
            explanation=str(value.get("explanation") or ""),
            evidence=str(value.get("evidence") or ""),
            compliance=str(value.get("compliance") or ""),
            remediation_link=str(value.get("remediation_link") or ""),
        )

    @staticmethod
    def _risk(section: VulnerabilitySection) -> RiskLevel:
        severities = [c.severity for c in section.checks if c.result == CheckResult.PRESENT]
        return (
            RiskLevel.HIGH
            if any(s in (CheckSeverity.CRITICAL, CheckSeverity.HIGH) for s in severities)
            else RiskLevel.MEDIUM
            if CheckSeverity.MEDIUM in severities
            else RiskLevel.LOW
            if severities
            else RiskLevel.NOT_EVALUATED
        )

    @staticmethod
    def _severity(sections: tuple[VulnerabilitySection, ...]) -> FindingSeverity:
        counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info", "secure")}
        for section in sections:
            for check in section.checks:
                if check.result == CheckResult.PRESENT:
                    counts[check.severity.value] += 1
        return FindingSeverity(**counts)

    @staticmethod
    def _details(data: Mapping[str, Any]) -> FlutterReportDetails:
        identity = data.get("identity") if isinstance(data.get("identity"), Mapping) else {}
        sdk = data.get("sdk") if isinstance(data.get("sdk"), Mapping) else {}
        platforms = data.get("platforms") if isinstance(data.get("platforms"), Mapping) else {}
        dependencies = data.get("dependency_inventory") if isinstance(data.get("dependency_inventory"), Mapping) else {}
        dependency_items = tuple(
            FlutterDependencyDetails(
                name=str(item.get("name") or ""),
                version=str(item.get("version") or ""),
                constraint=str(item.get("constraint") or ""),
                source=str(item.get("source") or ""),
                group=group,
            )
            for group in ("declared", "development", "resolved")
            for item in dependencies.get(group, ())
            if isinstance(item, Mapping) and item.get("name")
        )
        return FlutterReportDetails(
            package_name=str(identity.get("package_name") or ""),
            version_name=str(identity.get("version_name") or ""),
            dart_constraint=str(sdk.get("dart_constraint") or ""),
            flutter_constraint=str(sdk.get("flutter_constraint") or ""),
            supported_platforms=tuple(str(name) for name, enabled in platforms.items() if enabled is True),
            dependencies=dependency_items,
            functionality=tuple(
                FunctionalityDetails(str(name), value.get("present"), str(value.get("explanation") or ""))
                for name, value in FlutterReportDataBuilder._mapping(data, "functionality").items()
                if isinstance(value, Mapping)
            ),
            permissions=tuple(
                PermissionDetails(
                    permission=str(item.get("permission") or item.get("name") or ""),
                    status=str(item.get("status") or ""),
                    info=str(item.get("info") or ""),
                    usage_description=str(item.get("usage_description") or ""),
                    general_description=str(item.get("general_description") or ""),
                )
                for item in data.get("permissions", ())
                if isinstance(item, Mapping)
            ),
            hardcoded_values=FlutterReportDataBuilder._hardcoded_values(data),
            endpoints=tuple(
                EndpointDetails(
                    endpoint=str(item.get("endpoint") or ""),
                    tags=str(item.get("tags") or ""),
                    ip_address=str(item.get("ip_address") or ""),
                    country=str(item.get("country") or ""),
                )
                for item in data.get("endpoints", ())
                if isinstance(item, Mapping)
            ),
            presentation=FlutterReportDataBuilder._presentation(data),
        )

    @classmethod
    def _presentation(cls, data: Mapping[str, Any]) -> FlutterPresentationDetails:
        app_info = cls._mapping(data, "app_info")
        inventory = cls._mapping(data, "platform_inventory")
        sdk = cls._mapping(inventory, "sdk")
        android = cls._mapping(inventory, "android")
        ios = cls._mapping(inventory, "ios")
        warnings = tuple(cls._strings(inventory.get("warnings")))
        metadata_assessed = inventory.get("source_metadata_assessed") is True

        return FlutterPresentationDetails(
            extraction_status=(
                "Partial" if metadata_assessed and warnings else "Complete" if metadata_assessed else "Not Assessed"
            ),
            dart_sdk_constraint=cls._text(sdk, "dart_constraint") or cls._text(app_info, "dart_sdk_constraint"),
            flutter_sdk_constraint=cls._text(sdk, "flutter_constraint")
            or cls._text(app_info, "flutter_sdk_constraint"),
            android_application_id=cls._text(android, "package_name") or cls._text(app_info, "android_application_id"),
            ios_bundle_identifier=cls._text(ios, "bundle_identifier") or cls._text(app_info, "ios_bundle_identifier"),
            description=cls._text(app_info, "description"),
            homepage=cls._text(app_info, "homepage"),
            repository=cls._text(app_info, "repository"),
            warnings=warnings,
            platforms=cls._platforms(inventory, android, ios),
            dependencies=cls._dependency_presentation(data),
            deep_links_assessed=cls._deep_links_assessed(data),
            deep_links=cls._deep_links(data),
            url_schemes_assessed=ios.get("metadata_assessed") is True,
            url_schemes=cls._url_schemes(data),
            queried_url_schemes=tuple(cls._strings(data.get("queried_url_schemes"))),
            manual_review_available=isinstance(data.get("manual_review"), Mapping),
            manual_review_status=cls._manual_review_status(data),
            manual_review_findings=cls._manual_review_findings(data),
        )

    @classmethod
    def _platforms(
        cls,
        inventory: Mapping[str, Any],
        android: Mapping[str, Any],
        ios: Mapping[str, Any],
    ) -> tuple[FlutterPlatformPresentation, ...]:
        android_requirements = cls._join_requirements(
            ("Min SDK", android.get("min_sdk")),
            ("Target SDK", android.get("target_sdk")),
            ("Compile SDK", android.get("compile_sdk")),
        )
        return (
            FlutterPlatformPresentation(
                name="Android",
                detected=android.get("detected") is True,
                metadata_status=cls._metadata_status(android),
                identifier=cls._text(android, "package_name"),
                version=cls._text(android, "version_name"),
                requirements=android_requirements,
            ),
            FlutterPlatformPresentation(
                name="iOS",
                detected=ios.get("detected") is True,
                metadata_status=cls._metadata_status(ios),
                identifier=cls._text(ios, "bundle_identifier"),
                version=cls._text(ios, "version_name"),
                requirements=cls._join_requirements(("Minimum iOS", ios.get("minimum_os"))),
            ),
            *(
                FlutterPlatformPresentation(
                    name=name,
                    detected=inventory.get(key) is True,
                    metadata_status="Not Applicable",
                )
                for name, key in (
                    ("Web", "web_detected"),
                    ("Linux", "linux_detected"),
                    ("macOS", "macos_detected"),
                    ("Windows", "windows_detected"),
                )
            ),
        )

    @staticmethod
    def _metadata_status(platform: Mapping[str, Any]) -> str:
        if platform.get("metadata_assessed") is True:
            return "Assessed"
        return "Not Assessed" if platform.get("detected") is True else "Not Applicable"

    @classmethod
    def _dependency_presentation(cls, data: Mapping[str, Any]) -> FlutterDependencyPresentation:
        inventory = cls._mapping(data, "dependency_inventory")
        declared = tuple(
            FlutterDeclaredDependency(
                name=cls._text(item, "name"),
                constraint=cls._text(item, "constraint"),
                scope=cls._text(item, "scope") or group,
                source=cls._text(item, "source"),
            )
            for group in ("direct", "declared", "development")
            for item in cls._mapping_list(inventory.get(group))
            if cls._text(item, "name")
        )
        resolved = tuple(
            FlutterResolvedDependency(
                name=cls._text(item, "name"),
                version=cls._text(item, "version"),
                dependency_kind=cls._text(item, "dependency_kind"),
                source=cls._text(item, "source"),
            )
            for item in cls._mapping_list(inventory.get("resolved"))
            if cls._text(item, "name")
        )
        sbom_packages = tuple(
            FlutterSbomPackage(
                name=cls._text(item, "name"),
                version=cls._text(item, "version"),
                output_path=cls._text(item, "output_path"),
            )
            for item in cls._mapping_list(inventory.get("sbom_packages"))
            if cls._text(item, "name")
        )
        return FlutterDependencyPresentation(
            metadata_status="Assessed" if inventory.get("metadata_assessed") is True else "Not Assessed",
            sbom_status="Assessed" if inventory.get("sbom_assessed") is True else "Not Assessed",
            declared=declared,
            resolved=resolved,
            sbom_packages=sbom_packages,
        )

    @classmethod
    def _deep_links(cls, data: Mapping[str, Any]) -> tuple[FlutterDeepLink, ...]:
        container = cls._mapping(data, "deep_links")
        return tuple(cls._deep_link(item) for item in cls._mapping_list(container.get("deep_links")))

    @classmethod
    def _deep_link(cls, item: Mapping[str, Any]) -> FlutterDeepLink:
        scheme = cls._text(item, "scheme")
        host = cls._text(item, "host")
        port = cls._text(item, "port")
        path = cls._text(item, "path") or cls._text(item, "path_prefix") or cls._text(item, "path_pattern")
        authority = f"{host}:{port}" if host and port else host
        if scheme and authority:
            uri = f"{scheme}://{authority}{path}"
        elif scheme:
            uri = f"{scheme}:{path}"
        else:
            uri = f"{authority}{path}"
        return FlutterDeepLink(uri, cls._text(item, "component"), cls._text(item, "mime_type"))

    @classmethod
    def _url_schemes(cls, data: Mapping[str, Any]) -> tuple[FlutterUrlScheme, ...]:
        return tuple(
            FlutterUrlScheme(cls._text(item, "url_name"), tuple(cls._strings(item.get("schemes"))))
            for item in cls._mapping_list(data.get("url_schemes"))
        )

    @classmethod
    def _manual_review_status(cls, data: Mapping[str, Any]) -> str:
        review = cls._mapping(data, "manual_review")
        if not review:
            return "Not Assessed"
        if review.get("fully_assessed") is True:
            return "Fully Assessed"
        if review.get("assessed") is True:
            return "Partially Assessed"
        return "Not Assessed"

    @classmethod
    def _manual_review_findings(cls, data: Mapping[str, Any]) -> tuple[FlutterManualReviewFinding, ...]:
        return tuple(
            FlutterManualReviewFinding(
                rule_id=cls._text(item, "rule_id"),
                scope=cls._text(item, "scope"),
                severity=cls._text(item, "severity"),
                location=cls._text(item, "location"),
                reason=cls._text(item, "reason"),
                message=cls._text(item, "message"),
            )
            for item in cls._mapping_list(cls._mapping(data, "manual_review").get("findings"))
        )

    @classmethod
    def _deep_links_assessed(cls, data: Mapping[str, Any]) -> bool:
        return isinstance(cls._mapping(data, "deep_links").get("deep_links"), list)

    @staticmethod
    def _join_requirements(*items: tuple[str, Any]) -> str:
        return ", ".join(f"{label}: {value}" for label, value in items if str(value or "").strip())

    @staticmethod
    def _text(data: Mapping[str, Any], key: str) -> str:
        return str(data.get(key) or "").strip()

    @staticmethod
    def _strings(value: Any) -> list[str]:
        if not isinstance(value, (list, tuple)):
            return []
        return list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))

    @staticmethod
    def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
        if not isinstance(value, (list, tuple)):
            return []
        return [item for item in value if isinstance(item, Mapping)]

    @staticmethod
    def _hardcoded_values(data: Mapping[str, Any]) -> HardcodedValuesDetails:
        values = data.get("hardcoded_values") if isinstance(data.get("hardcoded_values"), Mapping) else {}
        return HardcodedValuesDetails(
            urls=tuple(
                HardcodedUrlDetails(str(item.get("url") or ""), str(item.get("country") or ""))
                for item in values.get("urls", ())
                if isinstance(item, Mapping)
            ),
            emails=tuple(str(item) for item in values.get("emails", ()) if str(item).strip()),
            secrets=tuple(
                HardcodedSecretDetails(str(item.get("value") or item))
                for item in values.get("secrets", ())
                if str(item).strip()
            ),
        )

    @staticmethod
    def _mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
        value = data.get(key)
        return value if isinstance(value, Mapping) else {}
