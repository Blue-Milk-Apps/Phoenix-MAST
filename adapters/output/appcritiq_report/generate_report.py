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

    report_data["vulnerability_sections"] = [
        s for s in report_data.get("vulnerability_sections", [])
        if (s.get("section_name") or "").strip().lower() not in EXCLUDED_VULN_SECTIONS
    ]

    return _prune_placeholder_rows(report_data)


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
