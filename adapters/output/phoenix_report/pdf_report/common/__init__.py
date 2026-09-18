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

    mapped: dict[str, dict[str, object]] = {}
    for item in items:
        status = item.status.value if item.status else _status_from_presence(item.present)
        explanation = item.explanation.strip() or _functionality_explanation(item.name, status)
        mapped[item.name] = {
            "present": item.present,
            "status": status,
            "explanation": explanation,
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
    return mapped


def _status_from_presence(present: bool | None) -> str:
    if present is True:
        return "present"
    if present is False:
        return "not_present"
    return "not_evaluated"


def _functionality_explanation(name: str, status: str) -> str:
    if status == "present":
        return f"Evidence indicates that {name.lower()} functionality is present."
    if status == "not_present":
        return f"No evidence indicates that {name.lower()} functionality is present."
    if status == "not_applicable":
        return f"{name} functionality is not applicable to this target."
    return f"{name} functionality was not evaluated because scan evidence is unavailable."


__all__ = [
    "build_charts",
    "map_functionality",
    "get_app_icon_data_uri",
    "get_report_brand_icon_data_uri",
    "make_overall_risk_polar_chart",
]
