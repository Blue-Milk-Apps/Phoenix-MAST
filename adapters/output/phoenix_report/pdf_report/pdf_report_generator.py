"""PDF output adapter for standard Phoenix report data."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from adapters.output.phoenix_report.generate_report import generate_report
from domain.report import AndroidBinaryReportDetails, ReportData, ReportPlatform
from ports.report_generator_port import ReportGeneratorPort


class PdfReportGenerator(ReportGeneratorPort):
    """Render standard report data with the Phoenix PDF presentation."""

    def generate(
        self,
        input_data: ReportData,
        output_path: Path | str,
        *,
        show_confidence_caveats: bool = False,
    ) -> Path:
        """Render a PDF from format-independent report data."""

        return generate_report(
            self._presentation_data(input_data),
            output_path,
            show_confidence_caveats=show_confidence_caveats,
        )

    @staticmethod
    def _presentation_data(report_data: ReportData) -> dict[str, object]:
        details = report_data.platform_details
        if not isinstance(details, AndroidBinaryReportDetails):
            raise ValueError(
                "PdfReportGenerator does not yet support "
                f"{report_data.metadata.target.target_kind.value} report details"
            )

        metadata = report_data.metadata
        return {
            "meta": {
                "app_display_name": metadata.app_display_name,
                "file_name": metadata.file_name,
                "package_name": metadata.package_name,
                "scan_date": metadata.scan_date,
                "platform": PdfReportGenerator._platform_label(metadata.target.platform),
                "target_type": metadata.target.target_type.value.upper(),
                "version_name": metadata.version_name,
                "version_code": metadata.version_code,
                "reviewer_org": metadata.reviewer_org,
            },
            "certificate": asdict(details.certificate),
            "file_info": asdict(details.file_info),
            "app_info": asdict(details.app_info),
            "application": asdict(details.application),
            "app_components": asdict(details.app_components),
            "functionality": {
                item.name: {
                    "present": item.present,
                    "explanation": item.explanation,
                }
                for item in details.functionality
            },
            "permissions": [asdict(item) for item in details.permissions],
            "hardcoded_values": asdict(details.hardcoded_values),
            "endpoints": [asdict(item) for item in details.endpoints],
            "vulnerability_sections": [
                {
                    "section_name": section.name,
                    "findings_text": section.findings_text,
                    "checks": [
                        {
                            "check": check.name,
                            "result": check.result.value.replace("_", " ").title(),
                            "severity": check.severity.value.title(),
                            "explanation": check.explanation,
                            "evidence": check.evidence,
                            "compliance": check.compliance,
                            "remediation_link": check.remediation_link,
                        }
                        for check in section.checks
                    ],
                }
                for section in report_data.vulnerability_sections
            ],
            "overall_evaluation": [
                {
                    "area_of_concern": evaluation.area,
                    "risk_rating": evaluation.risk_level.value.title(),
                    "summary_findings": list(evaluation.findings),
                }
                for evaluation in report_data.overall_evaluation
            ],
            "findings_severity": asdict(report_data.findings_severity),
        }

    @staticmethod
    def _platform_label(platform: ReportPlatform) -> str:
        return {
            ReportPlatform.ANDROID: "Android",
            ReportPlatform.IOS: "iOS",
            ReportPlatform.FLUTTER: "Flutter",
            ReportPlatform.REACT_NATIVE: "React Native",
        }[platform]
