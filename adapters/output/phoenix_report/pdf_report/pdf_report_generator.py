"""PDF output adapter for standard Phoenix report data."""

from __future__ import annotations

import copy
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from adapters.output.phoenix_report.generate_report import (
    build_charts,
    get_app_icon_data_uri,
    get_report_brand_icon_data_uri,
    result_badge,
    risk_badge,
)
from adapters.output.phoenix_report.pdf_report.presentation import PdfPresentation
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

        self._configure_weasyprint_library_path()
        from jinja2 import Environment, FileSystemLoader
        from weasyprint import HTML

        presentation = PdfPresentation.for_target_kind(input_data.metadata.target.target_kind)
        data = self._merged_presentation_data(input_data)
        base_dir = Path(__file__).parent.parent
        environment = Environment(loader=FileSystemLoader(str(base_dir / "templates")))
        environment.globals["risk_badge"] = risk_badge
        environment.globals["result_badge"] = result_badge
        html = environment.get_template("report.html.jinja").render(
            data=data,
            presentation=asdict(presentation),
            css=(base_dir / "templates" / "style.css").read_text(encoding="utf-8"),
            charts=build_charts(data),
            app_icon_uri=get_app_icon_data_uri(data),
            phoenix_brand_icon_uri=get_report_brand_icon_data_uri(),
            show_confidence_caveats=show_confidence_caveats,
        )
        resolved_output_path = Path(output_path)
        resolved_output_path.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=html, base_url=str(base_dir)).write_pdf(str(resolved_output_path))
        print(f"Wrote {resolved_output_path}")
        return resolved_output_path

    @classmethod
    def _merged_presentation_data(cls, report_data: ReportData) -> dict[str, object]:
        base_dir = Path(__file__).parent.parent
        base_template = json.loads((base_dir / "data" / "blank_template.json").read_text(encoding="utf-8"))
        return cls._merge(base_template, cls._presentation_data(report_data))

    @staticmethod
    def _merge(base: object, override: object) -> object:
        if isinstance(base, dict) and isinstance(override, dict):
            result = copy.deepcopy(base)
            for key, value in override.items():
                result[key] = PdfReportGenerator._merge(result[key], value) if key in result else copy.deepcopy(value)
            return result
        return copy.deepcopy(override)

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
            "risk_summary": {
                PdfReportGenerator._risk_summary_key(summary.area): summary.risk_level.value
                for summary in report_data.risk_summary
            },
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

    @staticmethod
    def _risk_summary_key(area: str) -> str:
        return {
            "Code Vulnerability": "code_vulnerability",
            "Networking": "networking",
            "Data Storage": "data_storage",
            "Resilience": "resilience",
        }[area]

    @staticmethod
    def _configure_weasyprint_library_path() -> None:
        if sys.platform != "darwin":
            return

        library_dirs = [Path("/opt/homebrew/lib"), Path("/usr/local/lib")]
        existing_dirs = [str(path) for path in library_dirs if path.is_dir()]
        if not existing_dirs:
            return

        current_dirs = [part for part in os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", "").split(":") if part]
        os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = ":".join(dict.fromkeys([*existing_dirs, *current_dirs]))
