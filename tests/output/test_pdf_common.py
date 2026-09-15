from pathlib import Path

from adapters.output.phoenix_report.pdf_report.common import (
    build_charts,
    get_app_icon_data_uri,
    get_report_brand_icon_data_uri,
)


def test_build_charts_handles_empty_risk_summary() -> None:
    assert build_charts({"risk_summary": {}})["overall_risk_polar"]


def test_app_icon_uses_fallback_for_missing_path() -> None:
    uri = get_app_icon_data_uri({"app_info": {"icon_path": str(Path("missing.png"))}})
    assert uri.startswith("data:image/")


def test_brand_icon_returns_data_uri() -> None:
    assert get_report_brand_icon_data_uri().startswith("data:image/")
