"""Shared presentation helpers for Phoenix PDF reports."""

from collections.abc import Iterable

from adapters.output.phoenix_report.pdf_report.common.charts import build_charts, make_overall_risk_polar_chart
from adapters.output.phoenix_report.pdf_report.common.images import (
    get_app_icon_data_uri,
    get_report_brand_icon_data_uri,
)
from domain.report import FunctionalityDetails


def map_functionality(items: Iterable[FunctionalityDetails]) -> dict[str, dict[str, object]]:
    """Map typed functionality details to the shared PDF template shape."""

    return {
        item.name: {
            "present": item.present,
            "status": item.status.value if item.status else "",
            "explanation": item.explanation,
            "platform_assessments": [
                {
                    "platform": assessment.platform.value,
                    "status": assessment.status.value,
                    "explanation": assessment.explanation,
                    "evidence": list(assessment.evidence),
                }
                for assessment in item.platform_assessments
            ],
        }
        for item in items
    }


__all__ = [
    "build_charts",
    "map_functionality",
    "get_app_icon_data_uri",
    "get_report_brand_icon_data_uri",
    "make_overall_risk_polar_chart",
]
