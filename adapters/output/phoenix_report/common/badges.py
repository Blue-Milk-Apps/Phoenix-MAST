"""Template badge rendering shared by report output adapters."""

from markupsafe import Markup


def risk_badge(rating: str, label: str | None = None) -> Markup:
    """Render a risk or severity badge."""

    key = (rating or "").strip().lower().replace("_", " ")
    css_class = {
        "critical": "badge-critical",
        "high": "badge-high",
        "medium": "badge-medium",
        "low": "badge-low",
        "info": "badge-info",
        "partial": "badge-partial",
        "secure hotspot": "badge-secure",
        "secure": "badge-secure",
        "hotspot": "badge-hotspot",
        "variable": "badge-variable",
        "n/a": "badge-na",
        "not evaluated": "badge-not-evaluated",
        "not applicable": "badge-not-applicable",
        "dangerous": "badge-high",
        "normal": "badge-info",
    }.get(key, "badge-info")
    return Markup(f'<span class="badge {css_class}">{label or rating}</span>')


def result_badge(result: str) -> Markup:
    """Render an assessment-result badge."""

    key = (result or "").strip().lower().replace("_", " ")
    css_class = {
        "present": "badge-present",
        "not present": "badge-not-present",
        "not found": "badge-not-present",
        "partial": "badge-partial",
        "not evaluated": "badge-not-evaluated",
        "not applicable": "badge-not-applicable",
    }.get(key, "badge-na")
    labels = {
        "present": "Present",
        "not present": "Not Present",
        "not found": "Not Found",
        "partial": "Partial",
        "not evaluated": "Not Evaluated",
        "not applicable": "Not Applicable",
    }
    return Markup(f'<span class="badge {css_class}">{labels.get(key, result)}</span>')


def assessment_badge(status: str) -> Markup:
    """Render a functionality assessment status."""

    key = (status or "").strip().lower().replace("_", " ")
    if key == "present":
        return risk_badge("info", label="Present")
    return result_badge(status)
