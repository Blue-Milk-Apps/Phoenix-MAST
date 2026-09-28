"""Chart rendering shared by PDF report adapters."""

import base64
import io

RISK_LEVEL_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4, "not_evaluated": 0}
RISK_LEVEL_COLOR = {
    "low": "#2980b9",
    "medium": "#e08e0b",
    "high": "#c0392b",
    "critical": "#8e1b1b",
    "not_evaluated": "#98a2b3",
}


def make_overall_risk_polar_chart(risk_summary: dict[str, str]) -> str:
    import matplotlib
    import numpy as np

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    keys = list(risk_summary)
    categories = [(key.replace("_", " ").title() if key.islower() else key, risk_summary[key]) for key in keys]
    if not categories:
        fig, ax = plt.subplots(figsize=(5.6, 4.8))
        ax.axis("off")
        ax.text(0.5, 0.5, "No security sections were evaluated", ha="center", va="center", fontsize=12, color="#667085")
    else:
        theta = np.linspace(0.0, 2 * np.pi, len(categories), endpoint=False)
        radii = [RISK_LEVEL_ORDER.get(level.strip().lower(), 0) for _, level in categories]
        colors = [RISK_LEVEL_COLOR.get(level.strip().lower(), "#98a2b3") for _, level in categories]
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
        ax.set_ylim(0, 4)
        ax.set_yticks([1, 2, 3, 4])
        ax.set_yticklabels(["Low", "Medium", "High", "Critical"], fontsize=7.5, color="#888")
        ax.set_rlabel_position(15)
        ax.spines["polar"].set_visible(False)
        ax.set_xticks(theta)
        ax.set_xticklabels([label for label, _ in categories], fontsize=10, fontweight="bold", color="#16233c")
        ax.tick_params(axis="x", pad=18)
        ax.set_facecolor("none")
        fig.patch.set_alpha(0)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=200, bbox_inches="tight", transparent=True)
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("ascii")


def build_charts(data: dict[str, object]) -> dict[str, str]:
    return {"overall_risk_polar": make_overall_risk_polar_chart(data["risk_summary"])}
