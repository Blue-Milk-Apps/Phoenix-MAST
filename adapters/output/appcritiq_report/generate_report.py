#!/usr/bin/env python3
"""
AppCritique Security Report generator.

Usage:
    python3 generate_report.py <data.json> <output.pdf>

Feed it a JSON file matching the schema in data/blank_template.json (a filled
example is at data/sample_insecurebankv2.json) and it renders a PDF report in
the AppCritique / mobile-app-pentest style: cover page, risk donuts, overall
evaluation table, certificate/file/app info, functionality & SDK inventory,
permissions, one section per vulnerability category with a findings narrative
and a checks-conducted table, hardcoded values, and endpoint connections.
"""
import base64
import copy
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
BLANK_TEMPLATE_PATH = BASE_DIR / "data" / "blank_template.json"

RISK_LEVEL_ORDER = {"low": 1, "medium": 2, "high": 3}
RISK_LEVEL_COLOR = {"low": "#2980b9", "medium": "#e08e0b", "high": "#c0392b"}
FINDINGS_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info", "secure")
SECTION_TO_AREA = {
    "code": ("Code Vulnerability", "code_vulnerability"),
    "storage": ("Data Storage", "data_storage"),
    "network": ("Networking", "networking"),
    "resilience": ("Resilience", "resilience"),
}
SECTION_SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "secure": 0,
}

DERIVED_CHECK_ALIAS_TO_COMPONENT_KEY = {
    "unprotected exported activity": "exported_activities",
    "activities accessible to other apps": "exported_activities",
    "unprotected exported service": "exported_services",
    "services accessible to other apps": "exported_services",
    "unprotected exported receiver": "exported_receivers",
    "receivers accessible to other apps": "exported_receivers",
    "unprotected exported provider": "exported_providers",
    "providers accessible to other apps": "exported_providers",
}
SHARED_PREFS_HINTS = ("shared_prefs/", "/shared_prefs/", "shared_prefs\\")
CACHE_HINTS = ("cache/", "/cache/", "cache\\", "webviewcache", "httpcache")

# Vulnerability categories excluded from the report entirely (per request:
# Authentication, Cryptography, and Platform are dropped from the output
# regardless of what's present in the source data file).
EXCLUDED_VULN_SECTIONS = {"authentication", "cryptography", "platform"}

# Path to the generic placeholder app-icon image used on the cover page
# when app_info.icon_path isn't provided.
PLACEHOLDER_ICON_PATH = BASE_DIR / "assets" / "placeholder_icon.png"


def risk_badge(rating, label=None):
    from markupsafe import Markup

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
    text = label if label else rating
    return Markup(f'<span class="badge {css_class}">{text}</span>')


def result_badge(result):
    from markupsafe import Markup

    key = (result or "").strip().lower()
    css_class = "badge-present" if key == "present" else "badge-notpresent"
    return Markup(f'<span class="badge {css_class}">{result}</span>')


def make_overall_risk_polar_chart(risk_summary):
    """Single polar-area (Nightingale rose) chart with one wedge per area of
    concern in risk_summary (e.g. Code Vulnerability, Data Storage,
    Networking, Resilience); wedge radius encodes Low/Medium/High and color
    matches the severity. Scales automatically to however many categories
    are present in risk_summary, so a 3-category and a 4-category report
    both render correctly with the same code."""
    import matplotlib
    import numpy as np
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Preferred display order; any keys not listed here are appended in
    # whatever order they appear in the data.
    preferred_order = ["code_vulnerability", "data_storage", "networking", "resilience"]
    keys = [k for k in preferred_order if k in risk_summary]
    keys += [k for k in risk_summary if k not in keys]

    def pretty_label(key):
        words = key.replace("_", " ").split()
        # Two-word labels wrap onto two lines to match the original layout;
        # longer/shorter labels are left on one line.
        if len(words) == 2:
            return "\n".join(w.capitalize() for w in words)
        return " ".join(w.capitalize() for w in words)

    categories = [(pretty_label(k), risk_summary.get(k, "Low")) for k in keys]

    n = len(categories)
    theta = np.linspace(0.0, 2 * np.pi, n, endpoint=False) + (np.pi / 2)
    width = (2 * np.pi / n) * 0.92

    radii = []
    colors = []
    labels = []
    for label, level in categories:
        key = (level or "low").strip().lower()
        radii.append(RISK_LEVEL_ORDER.get(key, 1))
        colors.append(RISK_LEVEL_COLOR.get(key, "#2980b9"))
        labels.append(label)

    fig = plt.figure(figsize=(5.6, 4.8))
    ax = fig.add_subplot(111, projection="polar")
    ax.set_theta_zero_location("N")

    bars = ax.bar(theta, radii, width=width, color=colors, alpha=0.85,
                   edgecolor="white", linewidth=2, bottom=0)

    ax.set_ylim(0, 4.3)
    ax.set_yticks([1, 2, 3])
    ax.set_yticklabels(["Low", "Medium", "High"], fontsize=7.5, color="#888")
    for t in ax.get_yticklabels():
        t.set_bbox(dict(facecolor="white", edgecolor="none", pad=1, alpha=0.85))
    ax.set_rlabel_position(200)
    ax.set_xticks(theta)
    ax.set_xticklabels(labels, fontsize=10, fontweight="bold", color="#16233c")
    ax.tick_params(axis="x", pad=14)
    ax.spines["polar"].set_color("#dddddd")
    ax.grid(color="#dddddd", linewidth=0.7)
    ax.set_facecolor("none")
    fig.patch.set_alpha(0)

    for angle, radius, level in zip(theta, radii, [c[1] for c in categories]):
        label_r = max(radius - 0.55, 0.6)
        ax.text(angle, label_r, level.title(), ha="center", va="center",
                 fontsize=9, fontweight="bold", color="white")

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=200, bbox_inches="tight", transparent=True)
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("ascii")


def build_charts(data):
    rs = data.get("risk_summary", {})
    return {"overall_risk_polar": make_overall_risk_polar_chart(rs)}


def get_app_icon_data_uri(data):
    """Return a data: URI for the app icon — the provided icon_path if set
    and readable, otherwise the generic placeholder icon."""
    icon_path = (data.get("app_info", {}) or {}).get("icon_path") or ""
    path = Path(icon_path) if icon_path else None
    if path and path.is_file():
        target = path
    else:
        target = PLACEHOLDER_ICON_PATH
    ext = target.suffix.lstrip(".").lower() or "png"
    mime = "jpeg" if ext in ("jpg", "jpeg") else ext
    encoded = base64.b64encode(target.read_bytes()).decode("ascii")
    return f"data:image/{mime};base64,{encoded}"


def load_report_data(input_data: dict[str, Any] | Path | str) -> dict[str, Any]:
    if isinstance(input_data, dict):
        data = copy.deepcopy(input_data)
    else:
        data = json.loads(Path(input_data).read_text(encoding="utf-8"))

    return _normalize_report_data(data)


def generate_report(input_data: dict[str, Any] | Path | str, output_path: Path | str) -> Path:
    _configure_weasyprint_library_path()
    from jinja2 import Environment, FileSystemLoader
    from weasyprint import HTML

    data = load_report_data(input_data)
    resolved_output_path = Path(output_path)

    css_text = (TEMPLATES_DIR / "style.css").read_text(encoding="utf-8")
    charts = build_charts(data)
    app_icon_uri = get_app_icon_data_uri(data)

    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    env.globals["risk_badge"] = risk_badge
    env.globals["result_badge"] = result_badge

    template = env.get_template("report.html.jinja")
    html_out = template.render(data=data, css=css_text, charts=charts, app_icon_uri=app_icon_uri)

    resolved_output_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html_out, base_url=str(BASE_DIR)).write_pdf(str(resolved_output_path))
    print(f"Wrote {resolved_output_path}")
    return resolved_output_path


def _configure_weasyprint_library_path() -> None:
    if sys.platform != "darwin":
        return

    known_library_dirs = [Path("/opt/homebrew/lib"), Path("/usr/local/lib")]
    existing_dirs = [str(path) for path in known_library_dirs if path.is_dir()]
    if not existing_dirs:
        return

    current = os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", "")
    current_parts = [part for part in current.split(":") if part]
    merged_parts: list[str] = []
    for part in [*existing_dirs, *current_parts]:
        if part not in merged_parts:
            merged_parts.append(part)
    os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = ":".join(merged_parts)


def _normalize_report_data(data: dict[str, Any]) -> dict[str, Any]:
    report_data = _merge_nested(_blank_template(), data)

    _apply_derived_vulnerability_checks(report_data)
    report_data["vulnerability_sections"] = [
        s for s in report_data.get("vulnerability_sections", [])
        if (s.get("section_name") or "").strip().lower() not in EXCLUDED_VULN_SECTIONS
    ]
    report_data["overall_evaluation"] = _build_overall_evaluation(report_data)
    report_data["risk_summary"] = _build_risk_summary(report_data)
    report_data["findings_severity"] = _build_findings_severity(report_data)

    return _prune_placeholder_rows(report_data)


def _apply_derived_vulnerability_checks(report_data: dict[str, Any]) -> None:
    for section in report_data.get("vulnerability_sections") or []:
        for check in section.get("checks") or []:
            _apply_derived_check(report_data, section, check)


def _apply_derived_check(
    report_data: dict[str, Any],
    section: dict[str, Any],
    check: dict[str, Any],
) -> None:
    section_name = str(section.get("section_name", "")).strip().lower()
    if section_name == "code":
        _apply_derived_code_check(report_data, check)
    elif section_name == "network":
        _apply_derived_network_check(report_data, check)
    elif section_name == "storage":
        _apply_derived_storage_check(report_data, check)


def _apply_derived_code_check(report_data: dict[str, Any], check: dict[str, Any]) -> None:
    check_name = _normalized_check_name(check.get("check"))

    component_key = DERIVED_CHECK_ALIAS_TO_COMPONENT_KEY.get(check_name)
    if component_key is not None:
        _apply_exported_component_check(report_data, check, component_key)
        return

    if check_name == "application data can be backed up":
        _apply_boolean_check(
            report_data,
            check,
            paths=[
                ("application", "allow_backup"),
                ("app_info", "allow_backup"),
                ("manifest", "allow_backup"),
            ],
            present_explanation=(
                "The manifest allows application data backup, which can expose "
                "app data through device backup mechanisms."
            ),
            not_present_explanation=(
                "Application data backup is not enabled based on the available "
                "report data."
            ),
            evidence_label="allow_backup",
        )
        return

    if check_name == "app is debuggable":
        _apply_boolean_check(
            report_data,
            check,
            paths=[
                ("application", "debuggable"),
                ("app_info", "debuggable"),
                ("manifest", "debuggable"),
            ],
            present_explanation=(
                "The app is marked as debuggable, which can expose runtime "
                "state and make reverse engineering easier."
            ),
            not_present_explanation=(
                "The app is not marked as debuggable based on the available "
                "report data."
            ),
            evidence_label="debuggable",
        )
        return

    if check_name == "application uses custom url schemes / deep links":
        _apply_deep_link_check(report_data, check)


def _apply_derived_network_check(report_data: dict[str, Any], check: dict[str, Any]) -> None:
    check_name = _normalized_check_name(check.get("check"))
    if check_name != "api authentication weakness (weak token handling / api key used as authentication)":
        return

    secrets = _secret_entries(report_data)
    if not secrets:
        return

    count = len(secrets)
    check["result"] = "Present"
    noun = "value" if count == 1 else "values"
    check["explanation"] = (
        f"{count} hardcoded secret-like {noun} detected in the application package. "
        "These may represent static API keys, tokens, or authentication material "
        "that weakens API authentication controls."
    )
    check["evidence"] = f"hardcoded_secrets={count}"


def _apply_derived_storage_check(report_data: dict[str, Any], check: dict[str, Any]) -> None:
    check_name = _normalized_check_name(check.get("check"))
    if check_name == "sensitive values stored insecurely in sharedpreferences":
        _apply_location_based_secret_check(
            report_data,
            check,
            hints=SHARED_PREFS_HINTS,
            present_explanation=(
                "Secret-like values were found in SharedPreferences-related paths, "
                "indicating sensitive data may be stored insecurely in local preferences."
            ),
            not_present_explanation=(
                "No secret-like values were found in SharedPreferences-related paths."
            ),
            evidence_label="shared_prefs_secret_hits",
        )
        return

    if check_name == "sensitive data in http cache databases":
        _apply_location_based_secret_check(
            report_data,
            check,
            hints=CACHE_HINTS,
            present_explanation=(
                "Secret-like values were found in cache-related paths, indicating "
                "sensitive data may be present in application cache storage."
            ),
            not_present_explanation=(
                "No secret-like values were found in cache-related paths."
            ),
            evidence_label="cache_secret_hits",
        )


def _apply_exported_component_check(
    report_data: dict[str, Any],
    check: dict[str, Any],
    component_key: str,
) -> None:
    app_components = report_data.get("app_components") or {}
    if component_key not in app_components:
        return

    exported_count = _coerce_int(app_components.get(component_key))
    if exported_count is None:
        return

    component_label = component_key.removeprefix("exported_").replace("_", " ")
    singular = component_label[:-1] if component_label.endswith("s") else component_label
    plural = component_label if component_label.endswith("s") else f"{component_label}s"

    if exported_count > 0:
        check["result"] = "Present"
        noun = singular if exported_count == 1 else plural
        check["explanation"] = (
            f"{exported_count} exported {noun} detected in the manifest."
        )
        check["evidence"] = f"{component_key}={exported_count}"
        return

    check["result"] = "Not Present"
    check["explanation"] = f"No exported {plural} were detected in the manifest."
    check["evidence"] = f"{component_key}=0"


def _apply_boolean_check(
    report_data: dict[str, Any],
    check: dict[str, Any],
    *,
    paths: list[tuple[str, str]],
    present_explanation: str,
    not_present_explanation: str,
    evidence_label: str,
) -> None:
    for section_key, field_key in paths:
        section = report_data.get(section_key)
        if not isinstance(section, dict) or field_key not in section:
            continue
        flag = _coerce_bool(section.get(field_key))
        if flag is None:
            continue
        check["result"] = "Present" if flag else "Not Present"
        check["explanation"] = present_explanation if flag else not_present_explanation
        check["evidence"] = f"{evidence_label}={str(flag).lower()}"
        return


def _apply_deep_link_check(report_data: dict[str, Any], check: dict[str, Any]) -> None:
    deep_links = report_data.get("deep_links")
    if not isinstance(deep_links, dict):
        return

    entries = deep_links.get("deep_links")
    if not isinstance(entries, list):
        return

    count = len(entries)
    if count > 0:
        check["result"] = "Present"
        noun = "handler" if count == 1 else "handlers"
        check["explanation"] = (
            f"{count} custom URL scheme or deep link {noun} detected in the app."
        )
        check["evidence"] = f"deep_links={count}"
        return

    check["result"] = "Not Present"
    check["explanation"] = "No custom URL schemes or deep links were detected."
    check["evidence"] = "deep_links=0"


def _apply_location_based_secret_check(
    report_data: dict[str, Any],
    check: dict[str, Any],
    *,
    hints: tuple[str, ...],
    present_explanation: str,
    not_present_explanation: str,
    evidence_label: str,
) -> None:
    secrets = _secret_entries(report_data)
    matched = [
        secret for secret in secrets
        if any(hint in str(secret.get("location", "")).lower() for hint in hints)
    ]
    if matched:
        check["result"] = "Present"
        check["explanation"] = present_explanation
        check["evidence"] = f"{evidence_label}={len(matched)}"
        return

    if secrets:
        check["result"] = "Not Present"
        check["explanation"] = not_present_explanation
        check["evidence"] = f"{evidence_label}=0"


def _secret_entries(report_data: dict[str, Any]) -> list[dict[str, Any]]:
    hardcoded_values = report_data.get("hardcoded_values")
    if not isinstance(hardcoded_values, dict):
        return []
    secrets = hardcoded_values.get("secrets")
    if not isinstance(secrets, list):
        return []
    return [secret for secret in secrets if isinstance(secret, dict)]


def _blank_template() -> dict[str, Any]:
    return json.loads(BLANK_TEMPLATE_PATH.read_text(encoding="utf-8"))


def _merge_nested(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        merged = {key: copy.deepcopy(value) for key, value in base.items()}
        for key, value in override.items():
            if key in merged:
                merged[key] = _merge_nested(merged[key], value)
            else:
                merged[key] = copy.deepcopy(value)
        return merged

    if isinstance(base, list) and isinstance(override, list):
        if override:
            return copy.deepcopy(override)
        return copy.deepcopy(base)

    return copy.deepcopy(override)


def _build_findings_severity(report_data: dict[str, Any]) -> dict[str, int]:
    counts = {key: 0 for key in FINDINGS_SEVERITY_KEYS}

    for section in report_data.get("vulnerability_sections") or []:
        for check in section.get("checks") or []:
            severity = str(check.get("severity", "")).strip().lower()
            if severity in counts:
                counts[severity] += 1

    return counts


def _build_overall_evaluation(report_data: dict[str, Any]) -> list[dict[str, Any]]:
    rows_by_area: dict[str, dict[str, Any]] = {}

    for section in report_data.get("vulnerability_sections") or []:
        section_name = str(section.get("section_name", "")).strip().lower()
        area_details = SECTION_TO_AREA.get(section_name)
        if area_details is None:
            continue

        area_label, _risk_key = area_details
        present_checks = [
            check for check in (section.get("checks") or [])
            if str(check.get("result", "")).strip().lower() == "present"
        ]
        summary_findings = [str(check.get("check", "")).strip() for check in present_checks if str(check.get("check", "")).strip()]
        risk_rating = _highest_present_severity(present_checks)

        rows_by_area[area_label] = {
            "area_of_concern": area_label,
            "risk_rating": risk_rating,
            "summary_findings": summary_findings or ["No present findings identified in this scan"],
        }

    ordered_rows: list[dict[str, Any]] = []
    for area_label, _risk_key in SECTION_TO_AREA.values():
        row = rows_by_area.get(area_label)
        if row is not None:
            ordered_rows.append(row)

    return ordered_rows


def _build_risk_summary(report_data: dict[str, Any]) -> dict[str, str]:
    summary = {risk_key: "Low" for _area_label, risk_key in SECTION_TO_AREA.values()}

    for row in report_data.get("overall_evaluation") or []:
        area_name = str(row.get("area_of_concern", "")).strip().lower()
        for section_name, (area_label, risk_key) in SECTION_TO_AREA.items():
            if area_label.lower() == area_name:
                summary[risk_key] = _normalize_risk_level(row.get("risk_rating"))
                break

    return summary


def _highest_present_severity(present_checks: list[dict[str, Any]]) -> str:
    highest = "info"
    highest_rank = SECTION_SEVERITY_ORDER[highest]

    for check in present_checks:
        severity = str(check.get("severity", "")).strip().lower()
        if severity not in SECTION_SEVERITY_ORDER:
            continue
        rank = SECTION_SEVERITY_ORDER[severity]
        if rank > highest_rank:
            highest = severity
            highest_rank = rank

    return highest.title()


def _normalize_risk_level(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in {"critical", "high"}:
        return "High"
    if text == "medium":
        return "Medium"
    return "Low"


def _normalized_check_name(value: object) -> str:
    return str(value or "").strip().lower()


def _coerce_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def _prune_placeholder_rows(data: dict[str, Any]) -> dict[str, Any]:
    if not any(data.get("permissions") or []):
        data["permissions"] = []
    elif len(data["permissions"]) == 1 and not any(str(value).strip() for value in data["permissions"][0].values()):
        data["permissions"] = []

    hardcoded_values = data.get("hardcoded_values") or {}
    urls = hardcoded_values.get("urls") or []
    if len(urls) == 1 and not any(str(value).strip() for value in urls[0].values()):
        hardcoded_values["urls"] = []

    endpoints = data.get("endpoints") or []
    if len(endpoints) == 1 and not any(str(value).strip() for value in endpoints[0].values()):
        data["endpoints"] = []

    return data


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 generate_report.py <data.json> <output.pdf>")
        sys.exit(1)

    data_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    generate_report(data_path, output_path)


if __name__ == "__main__":
    main()
