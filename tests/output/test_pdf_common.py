from pathlib import Path

import pytest

from adapters.output.phoenix_report.common import assessment_badge, result_badge, risk_badge
from adapters.output.phoenix_report.pdf_report.common import (
    build_charts,
    get_app_icon_data_uri,
    get_report_brand_icon_data_uri,
)


def test_build_charts_handles_empty_risk_summary() -> None:
    assert build_charts({"risk_summary": {}})["overall_risk_polar"]


@pytest.mark.parametrize("categories", [2, 12])
def test_risk_chart_uses_four_rings_with_critical_at_the_edge(monkeypatch, categories) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    monkeypatch.setattr(plt, "close", lambda *args: None)
    levels = {"Code": "critical", "iOS / Crypto": "low"}
    levels.update({"networking" if index == 0 else f"Category {index}": "high" for index in range(categories - 2)})
    build_charts({"risk_summary": levels})
    axis = plt.gcf().axes[0]
    assert axis.get_ylim() == (0, 4)
    assert list(axis.get_yticks()) == [1, 2, 3, 4]
    assert axis.patches[0].get_height() == axis.get_ylim()[1]
    assert len(axis.patches) == categories
    assert axis.get_xlim() == (0, 2 * np.pi)
    assert [label.get_text() for label in axis.get_xticklabels()] == [
        key.title() if key.islower() else key for key in levels
    ]
    assert not axis.spines["polar"].get_visible()
    monkeypatch.undo()
    plt.close("all")


@pytest.mark.parametrize("embedded", ["", "data:image/png;base64,broken", "data:image/png;base64,bm90IGEgcG5n"])
def test_app_icon_uses_fallback_for_missing_path(embedded: str) -> None:
    uri = get_app_icon_data_uri({"app_info": {"icon_path": str(Path("missing.png")), "icon_data_uri": embedded}})
    assert uri == get_app_icon_data_uri({})


def test_brand_icon_returns_data_uri() -> None:
    assert get_report_brand_icon_data_uri().startswith("data:image/")


def test_result_badges_distinguish_not_evaluated_from_not_present() -> None:
    not_evaluated = str(result_badge("not_evaluated"))
    not_present = str(result_badge("not_present"))

    assert "badge-not-evaluated" in not_evaluated
    assert "Not Evaluated" in not_evaluated
    assert "badge-not-present" in not_present
    assert "Not Present" in not_present
    assert "badge-not-evaluated" not in not_present


def test_risk_badge_uses_not_evaluated_status_color() -> None:
    assert "badge-not-evaluated" in str(risk_badge("not_evaluated"))


def test_functionality_present_badge_remains_informational() -> None:
    badge = str(assessment_badge("present"))

    assert "badge-info" in badge
    assert "Present" in badge
