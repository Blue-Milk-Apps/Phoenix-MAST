"""Build standard report data from iOS binary post-scan output."""

from __future__ import annotations

from typing import Any, Mapping

from adapters.output.phoenix_report.builders.binary import BinaryReportDataBuilder
from domain.report import (
    AppDetails,
    EndpointDetails,
    FileDetails,
    FindingSeverity,
    HardcodedSecretDetails,
    HardcodedUrlDetails,
    HardcodedValuesDetails,
    IOSBinaryEvidenceDetails,
    IOSBinaryReportDetails,
    IOSSDKCategoryDetails,
    PermissionDetails,
    ReportData,
    ReportMetadata,
    ReportPlatform,
    ReportTargetKind,
    UrlSchemeDetails,
)


class IOSBinaryReportDataBuilder(BinaryReportDataBuilder):
    """Build standard report data for iOS binary assessments."""

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.IOS_BINARY

    def build(self, post_scan_data: Mapping[str, Any], metadata: ReportMetadata) -> ReportData:
        """Validate the target until all iOS report sections are implemented."""

        if metadata.target.target_kind != self.target_kind:
            raise ValueError(
                "iOS binary report builder requires "
                f"target_kind={self.target_kind.value}, got {metadata.target.target_kind.value}"
            )
        return ReportData(
            metadata=metadata,
            vulnerability_sections=(),
            overall_evaluation=(),
            risk_summary=(),
            findings_severity=FindingSeverity(),
            platform_details=self._details(post_scan_data),
        )

    @classmethod
    def _details(cls, data: Mapping[str, Any]) -> IOSBinaryReportDetails:
        manual_review_findings = ()
        return IOSBinaryReportDetails(
            file_info=FileDetails(
                **{
                    k: cls._text(cls._mapping(data, "file_info"), k)
                    for k in ("filename", "size", "md5", "sha1", "sha256")
                }
            ),
            app_info=AppDetails(
                icon_path=cls._text(cls._mapping(data, "app_info"), "icon_path"),
                name=cls._text(cls._mapping(data, "app_info"), "name"),
                package_name=cls._text(cls._mapping(data, "app_info"), "package_name"),
                main_activity=cls._text(cls._mapping(data, "app_info"), "main_activity"),
                version_name=cls._text(cls._mapping(data, "app_info"), "version_name"),
                app_store_id=cls._text(cls._mapping(data, "app_info"), "app_store_id"),
                developer=cls._text(cls._mapping(data, "app_info"), "developer"),
                categories=cls._text(cls._mapping(data, "app_info"), "categories"),
                trackers_detected=cls._text(cls._mapping(data, "app_info"), "trackers_detected"),
            ),
            binary_evidence=IOSBinaryEvidenceDetails(
                **{
                    k.replace(" ", "_"): cls._optional_bool(v)
                    for k, v in cls._mapping(data, "ipa_binary_evidence").items()
                }
            ),
            url_schemes=tuple(
                UrlSchemeDetails(cls._text(x, "url_name"), tuple(x.get("schemes", ())))
                for x in data.get("url_schemes", ())
                if isinstance(x, Mapping)
            ),
            functionality=tuple(
                cls._single_platform_functionality(
                    name=k,
                    value=cls._optional_bool(v.get("present")) if isinstance(v, Mapping) else None,
                    platform=ReportPlatform.IOS,
                    explanation=cls._text(v, "explanation") if isinstance(v, Mapping) else "",
                )
                for k, v in cls._mapping(data, "functionality").items()
            ),
            third_party_sdks=tuple(
                IOSSDKCategoryDetails(k, tuple(n for n, present in v.items() if present))
                for k, v in cls._mapping(data, "third_party_sdks").items()
                if isinstance(v, Mapping)
            ),
            permissions=tuple(
                PermissionDetails(
                    permission=cls._text(x, "permission"),
                    status=cls._text(x, "status"),
                    info=cls._text(x, "info"),
                    usage_description=cls._text(x, "usage_description"),
                    general_description=cls._text(x, "general_description"),
                )
                for x in data.get("permissions", ())
                if isinstance(x, Mapping)
            ),
            hardcoded_values=cls._hardcoded_values(data),
            endpoints=tuple(
                EndpointDetails(
                    endpoint=cls._text(x, "endpoint"),
                    tags=cls._text(x, "tags"),
                    ip_address=cls._text(x, "ip_address"),
                    country=cls._text(x, "country"),
                )
                for x in data.get("endpoints", ())
                if isinstance(x, Mapping)
            ),
            manual_review_available=bool(manual_review_findings),
            manual_review_status="Not Assessed",
            manual_review_findings=manual_review_findings,
        )

    @classmethod
    def _hardcoded_values(cls, data: Mapping[str, Any]) -> HardcodedValuesDetails:
        values = cls._mapping(data, "hardcoded_values")
        urls = tuple(
            HardcodedUrlDetails(cls._text(item, "url"), cls._text(item, "country"))
            for item in values.get("urls", ())
            if isinstance(item, Mapping)
        )
        secrets = tuple(
            HardcodedSecretDetails(cls._text(item, "value") or str(item).strip())
            for item in values.get("secrets", ())
            if isinstance(item, Mapping) or str(item).strip()
        )
        emails = tuple(str(value).strip() for value in values.get("emails", ()) if str(value).strip())
        return HardcodedValuesDetails(urls=urls, emails=emails, secrets=secrets)

    @staticmethod
    def _mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
        value = data.get(key)
        return value if isinstance(value, Mapping) else {}

    @staticmethod
    def _optional_bool(value: Any) -> bool | None:
        if value is True or str(value).strip().lower() == "true":
            return True
        if value is False or str(value).strip().lower() == "false":
            return False
        return None

    @staticmethod
    def _text(data: Mapping[str, Any], key: str) -> str:
        return str(data.get(key) or "").strip()
