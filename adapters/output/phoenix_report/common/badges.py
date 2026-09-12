"""Template badge rendering shared by report output adapters."""

from markupsafe import Markup


def risk_badge(rating: str, label: str | None = None) -> Markup:
    """Render a risk or severity badge."""

    key = (rating or "").strip().lower()
    css_class = {
        "critical": "badge-critical",
        "high": "badge-high",
        "medium": "badge-medium",
        "low": "badge-low",
        "info": "badge-info",
        "secure hotspot": "badge-secure",
        "secure": "badge-secure",
        "hotspot": "badge-hotspot",
        "variable": "badge-variable",
        "n/a": "badge-na",
        "dangerous": "badge-high",
        "normal": "badge-info",
    }.get(key, "badge-info")
    return Markup(f'<span class="badge {css_class}">{label or rating}</span>')


def result_badge(result: str) -> Markup:
    """Render an assessment-result badge."""

    css_class = {"present": "badge-present", "not present": "badge-notpresent"}.get(
        (result or "").strip().lower(), "badge-na"
    )
    return Markup(f'<span class="badge {css_class}">{result}</span>')
