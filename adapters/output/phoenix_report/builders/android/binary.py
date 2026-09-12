"""Build standard report data from Android binary post-scan output."""

from __future__ import annotations

from typing import Any, Mapping

from adapters.output.phoenix_report.builders.android.binary_check_catalog import (
    EVIDENCE_KEY_BY_CHECK,
    SECTION_CHECKS,
    AndroidBinaryCheckDefinition,
)
from domain.report import (
    AndroidApplicationDetails,
    AndroidBinaryReportDetails,
    AppComponentSummary,
    AppDetails,
    CertificateDetails,
    CheckResult,
    CheckSeverity,
    EndpointDetails,
    FileDetails,
    FindingSeverity,
    FunctionalityDetails,
    HardcodedSecretDetails,
    HardcodedUrlDetails,
    HardcodedValuesDetails,
    OverallEvaluation,
    PermissionDetails,
    ReportData,
    ReportMetadata,
    ReportTargetKind,
    RiskLevel,
    RiskSummary,
    SecurityCheck,
    SignatureVersions,
    VulnerabilitySection,
)
from ports.report_data_builder_port import ReportDataBuilderPort


class AndroidBinaryReportDataBuilder(ReportDataBuilderPort):
    """Translate Android binary post-scan output into standard report data."""

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.ANDROID_BINARY

    def build(
        self,
        post_scan_data: Mapping[str, Any],
        metadata: ReportMetadata,
    ) -> ReportData:
        """Build all report sections and Android-specific report details."""

        if metadata.target.target_kind != self.target_kind:
            raise ValueError(
                "Android binary report builder requires "
                f"target_kind={self.target_kind.value}, "
                f"got {metadata.target.target_kind.value}"
            )

        sections = tuple(
            self._section(name, evidence_key, checks, post_scan_data)
            for name, _area, evidence_key, checks in SECTION_CHECKS
        )
        findings_severity = self._findings_severity(sections)

        return ReportData(
            metadata=metadata,
            vulnerability_sections=sections,
            overall_evaluation=self._overall_evaluation(sections),
            risk_summary=tuple(
                RiskSummary(area=evaluation.area, risk_level=evaluation.risk_level)
                for evaluation in self._overall_evaluation(sections)
            ),
            findings_severity=findings_severity,
            platform_details=AndroidBinaryReportDetails(
                certificate=self._certificate_details(post_scan_data),
                file_info=self._file_details(post_scan_data),
                app_info=self._app_details(post_scan_data),
                application=self._application_details(post_scan_data),
                app_components=self._component_summary(post_scan_data),
                functionality=self._functionality_details(post_scan_data),
                permissions=self._permission_details(post_scan_data),
                hardcoded_values=self._hardcoded_values_details(post_scan_data),
                endpoints=self._endpoint_details(post_scan_data),
            ),
        )

    def _section(
        self,
        section_name: str,
        evidence_key: str,
        definitions: tuple[AndroidBinaryCheckDefinition, ...],
        post_scan_data: Mapping[str, Any],
    ) -> VulnerabilitySection:
        evidence = self._mapping(post_scan_data, evidence_key)
        checks = tuple(self._check(definition, evidence, post_scan_data) for definition in definitions)
        return VulnerabilitySection(
            name=section_name,
            findings_text="",
            checks=checks,
        )

    @classmethod
    def _check(
        cls,
        definition: AndroidBinaryCheckDefinition,
        section_evidence: Mapping[str, Any],
        post_scan_data: Mapping[str, Any],
    ) -> SecurityCheck:
        entry = section_evidence.get(EVIDENCE_KEY_BY_CHECK[cls._normalized(definition.name)])
        entry = entry if isinstance(entry, Mapping) else {}
        present = cls._optional_bool(entry.get("present"))
        evidence = cls._text(entry, "evidence")
        if present is None:
            present, evidence = cls._derived_result(definition.name, post_scan_data, evidence)
        result = cls._check_result(present)
        return SecurityCheck(
            name=definition.name,
            severity=definition.severity,
            result=result,
            explanation=cls._explanation(definition.name, result),
            evidence=evidence,
            compliance=cls._text(entry, "compliance"),
            remediation_link=cls._text(entry, "remediation_link"),
        )

    @classmethod
    def _derived_result(
        cls,
        check_name: str,
        data: Mapping[str, Any],
        evidence: str,
    ) -> tuple[bool | None, str]:
        component_key = {
            "Activities Accessible to Other Apps": "exported_activities",
            "Receivers Accessible to Other Apps": "exported_receivers",
            "Services Accessible to Other Apps": "exported_services",
        }.get(check_name)
        if component_key:
            components = cls._mapping(data, "app_components")
            if component_key in components:
                count = cls._integer(components[component_key])
                return count > 0, f"{component_key}={count}"
        if check_name == "App is Debuggable":
            return cls._derived_boolean(data, "debuggable", evidence)
        if check_name == "Allows Cleartext Traffic for All Domains":
            return cls._derived_boolean(data, "uses_cleartext_traffic", evidence)
        return None, evidence

    @classmethod
    def _derived_boolean(
        cls,
        data: Mapping[str, Any],
        key: str,
        evidence: str,
    ) -> tuple[bool | None, str]:
        for section_name in ("application", "app_info", "manifest"):
            section = cls._mapping(data, section_name)
            if key in section:
                value = cls._optional_bool(section.get(key))
                if value is not None:
                    return value, evidence or f"{key}={str(value).lower()}"
        return None, evidence

    @staticmethod
    def _check_result(value: bool | None) -> CheckResult:
        if value is True:
            return CheckResult.PRESENT
        if value is False:
            return CheckResult.NOT_PRESENT
        return CheckResult.NOT_EVALUATED

    @staticmethod
    def _explanation(check_name: str, result: CheckResult) -> str:
        if result == CheckResult.NOT_EVALUATED:
            return f"{check_name} was not evaluated because the required scan evidence is unavailable."
        if result == CheckResult.PRESENT:
            return f"Evidence indicates that {check_name.lower()}."
        return f"No evidence indicates that {check_name.lower()}."

    @staticmethod
    def _overall_evaluation(
        sections: tuple[VulnerabilitySection, ...],
    ) -> tuple[OverallEvaluation, ...]:
        area_by_section = {name: area for name, area, _evidence_key, _checks in SECTION_CHECKS}
        return tuple(
            OverallEvaluation(
                area=area_by_section[section.name],
                risk_level=AndroidBinaryReportDataBuilder._risk_level(section),
                findings=tuple(
                    check.name
                    for check in section.checks
                    if check.result == CheckResult.PRESENT
                    and check.severity not in {CheckSeverity.INFO, CheckSeverity.SECURE}
                )
                or ("No findings identified in this scan",),
            )
            for section in sections
        )

    @staticmethod
    def _risk_level(section: VulnerabilitySection) -> RiskLevel:
        severities = {check.severity for check in section.checks if check.result == CheckResult.PRESENT}
        if CheckSeverity.CRITICAL in severities or CheckSeverity.HIGH in severities:
            return RiskLevel.HIGH
        if CheckSeverity.MEDIUM in severities:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _findings_severity(
        sections: tuple[VulnerabilitySection, ...],
    ) -> FindingSeverity:
        counts = {severity: 0 for severity in CheckSeverity}
        for section in sections:
            for check in section.checks:
                if check.result == CheckResult.PRESENT:
                    counts[check.severity] += 1
        return FindingSeverity(
            critical=counts[CheckSeverity.CRITICAL],
            high=counts[CheckSeverity.HIGH],
            medium=counts[CheckSeverity.MEDIUM],
            low=counts[CheckSeverity.LOW],
            info=counts[CheckSeverity.INFO],
            secure=counts[CheckSeverity.SECURE],
        )

    @staticmethod
    def _mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
        value = data.get(key)
        return value if isinstance(value, Mapping) else {}

    @staticmethod
    def _normalized(value: str) -> str:
        return " ".join(value.lower().split())

    @staticmethod
    def _mappings(value: Any) -> tuple[Mapping[str, Any], ...]:
        if not isinstance(value, list):
            return ()
        return tuple(item for item in value if isinstance(item, Mapping))

    @classmethod
    def _certificate_details(cls, data: Mapping[str, Any]) -> CertificateDetails:
        certificate = cls._mapping(data, "certificate")
        versions = cls._mapping(certificate, "signature_versions")
        return CertificateDetails(
            owner_name=cls._text(certificate, "owner_name"),
            organization=cls._text(certificate, "organization"),
            organizational_unit=cls._text(certificate, "organizational_unit"),
            location=cls._text(certificate, "location"),
            validity=cls._text(certificate, "validity"),
            issuer=cls._text(certificate, "issuer"),
            serial_number=cls._text(certificate, "serial_number"),
            signature_versions=SignatureVersions(
                v1=cls._bool(versions.get("v1")),
                v2=cls._bool(versions.get("v2")),
                v3=cls._bool(versions.get("v3")),
                v4=cls._bool(versions.get("v4")),
            ),
            hash_algorithms=cls._text(certificate, "hash_algorithms"),
            fingerprint=cls._text(certificate, "fingerprint"),
            unique_certs=cls._text(certificate, "unique_certs"),
        )

    @classmethod
    def _file_details(cls, data: Mapping[str, Any]) -> FileDetails:
        file_info = cls._mapping(data, "file_info")
        return FileDetails(
            filename=cls._text(file_info, "filename"),
            size=cls._text(file_info, "size"),
            md5=cls._text(file_info, "md5"),
            sha1=cls._text(file_info, "sha1"),
            sha256=cls._text(file_info, "sha256"),
        )

    @classmethod
    def _app_details(cls, data: Mapping[str, Any]) -> AppDetails:
        app_info = cls._mapping(data, "app_info")
        return AppDetails(
            icon_path=cls._text(app_info, "icon_path"),
            name=cls._text(app_info, "name"),
            package_name=cls._text(app_info, "package_name"),
            main_activity=cls._text(app_info, "main_activity"),
            target_sdk=cls._text(app_info, "target_sdk"),
            min_sdk=cls._text(app_info, "min_sdk"),
            max_sdk=cls._text(app_info, "max_sdk"),
            version_name=cls._text(app_info, "version_name"),
            app_store_id=cls._text(app_info, "app_store_id"),
            developer=cls._text(app_info, "developer"),
            categories=cls._text(app_info, "categories"),
            trackers_detected=cls._text(app_info, "trackers_detected"),
        )

    @classmethod
    def _application_details(cls, data: Mapping[str, Any]) -> AndroidApplicationDetails:
        application = cls._mapping(data, "application")
        return AndroidApplicationDetails(
            debuggable=cls._optional_bool(application.get("debuggable")),
            allow_backup=cls._optional_bool(application.get("allow_backup")),
            uses_cleartext_traffic=cls._optional_bool(application.get("uses_cleartext_traffic")),
        )

    @classmethod
    def _component_summary(cls, data: Mapping[str, Any]) -> AppComponentSummary:
        components = cls._mapping(data, "app_components")
        return AppComponentSummary(
            activities=cls._integer(components.get("activities")),
            services=cls._integer(components.get("services")),
            receivers=cls._integer(components.get("receivers")),
            providers=cls._integer(components.get("providers")),
            exported_activities=cls._integer(components.get("exported_activities")),
            exported_services=cls._integer(components.get("exported_services")),
            exported_receivers=cls._integer(components.get("exported_receivers")),
            exported_providers=cls._integer(components.get("exported_providers")),
        )

    @classmethod
    def _functionality_details(cls, data: Mapping[str, Any]) -> tuple[FunctionalityDetails, ...]:
        functionality = cls._mapping(data, "functionality")
        return tuple(
            FunctionalityDetails(
                name=name,
                present=cls._optional_bool(value.get("present")) if isinstance(value, Mapping) else None,
                explanation=cls._text(value, "explanation") if isinstance(value, Mapping) else "",
            )
            for name, value in sorted(functionality.items())
        )

    @classmethod
    def _permission_details(cls, data: Mapping[str, Any]) -> tuple[PermissionDetails, ...]:
        return tuple(
            PermissionDetails(
                permission=cls._text(item, "permission"),
                status=cls._text(item, "status"),
                info=cls._text(item, "info"),
                usage_description=cls._text(item, "usage_description"),
                general_description=cls._text(item, "general_description"),
            )
            for item in cls._mappings(data.get("permissions"))
            if cls._text(item, "permission")
        )

    @classmethod
    def _hardcoded_values_details(cls, data: Mapping[str, Any]) -> HardcodedValuesDetails:
        values = cls._mapping(data, "hardcoded_values")
        urls = tuple(
            HardcodedUrlDetails(url=cls._text(item, "url"), country=cls._text(item, "country"))
            for item in cls._mappings(values.get("urls"))
            if cls._text(item, "url")
        )
        emails = tuple(str(value).strip() for value in values.get("emails", []) if str(value).strip())
        secrets = tuple(
            HardcodedSecretDetails(value=cls._text(item, "value") or str(item).strip())
            for item in values.get("secrets", [])
            if cls._text(item, "value") or str(item).strip()
        )
        return HardcodedValuesDetails(urls=urls, emails=emails, secrets=secrets)

    @classmethod
    def _endpoint_details(cls, data: Mapping[str, Any]) -> tuple[EndpointDetails, ...]:
        return tuple(
            EndpointDetails(
                endpoint=cls._text(item, "endpoint"),
                tags=cls._text(item, "tags"),
                ip_address=cls._text(item, "ip_address"),
                country=cls._text(item, "country"),
            )
            for item in cls._mappings(data.get("endpoints"))
            if cls._text(item, "endpoint")
        )

    @staticmethod
    def _text(data: Mapping[str, Any], key: str) -> str:
        return str(data.get(key) or "").strip()

    @staticmethod
    def _integer(value: Any) -> int:
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _bool(value: Any) -> bool:
        return value is True or str(value).strip().lower() == "true"

    @staticmethod
    def _optional_bool(value: Any) -> bool | None:
        if value is True or str(value).strip().lower() == "true":
            return True
        if value is False or str(value).strip().lower() == "false":
            return False
        return None
