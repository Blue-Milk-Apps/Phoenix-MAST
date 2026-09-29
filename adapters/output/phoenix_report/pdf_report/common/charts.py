"""Chart rendering shared by PDF report adapters."""

import base64
import io
import textwrap

SEVERITY_ORDER = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
SEVERITY_COLOR = {
    "info": "#2980b9",
    "low": "#5499c7",
    "medium": "#e08e0b",
    "high": "#c0392b",
    "critical": "#8e1b1b",
}


def make_finding_severity_polar_chart(severities: dict[str, str]) -> str:
    import matplotlib
    import numpy as np

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    categories = [(key.replace("_", " ").title() if key.islower() else key, value) for key, value in severities.items()]
    if not categories:
        fig, ax = plt.subplots(figsize=(5.6, 4.8))
        ax.axis("off")
        ax.text(0.5, 0.5, "No matched security findings", ha="center", va="center", fontsize=12, color="#667085")
    else:
        theta = np.linspace(0.0, 2 * np.pi, len(categories), endpoint=False)
        radii = [SEVERITY_ORDER.get(level.strip().lower(), 0) for _, level in categories]
        colors = [SEVERITY_COLOR.get(level.strip().lower(), "#98a2b3") for _, level in categories]
        fig = plt.figure(figsize=(5.6, 4.8))
        ax = fig.add_subplot(111, projection="polar")
        ax.set_theta_zero_location("N")
        ax.bar(
            theta,
            radii,
            width=(2 * np.pi / len(categories)) * 0.92,
            color=colors,
            alpha=0.85,
            edgecolor="white",
            linewidth=2,
        )
        ax.set_ylim(0, 5)
        ax.set_yticks([1, 2, 3, 4, 5])
        ax.set_yticklabels(["Info", "Low", "Medium", "High", "Critical"], fontsize=7.5, color="#888")
        ax.set_rlabel_position(15)
        ax.spines["polar"].set_visible(False)
        ax.set_xticks(theta)
        ax.set_xticklabels(
            [textwrap.fill(label, width=18, break_long_words=False) for label, _ in categories],
            fontsize=10,
            fontweight="bold",
            color="#16233c",
        )
        ax.tick_params(axis="x", pad=18)
        ax.set_facecolor("none")
        fig.patch.set_alpha(0)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=200, bbox_inches="tight", transparent=True)
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def build_charts(data: dict[str, object]) -> dict[str, str]:
    severities = {row["area"]: row["severity"] for row in data["finding_summary"]}
    return {"finding_severity_polar": make_finding_severity_polar_chart(severities)}
