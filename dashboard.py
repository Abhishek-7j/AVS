import matplotlib.pyplot as plt

from plugins import Finding


def show_dashboard(findings: list[Finding], score: int) -> None:
    severity_count: dict[str, int] = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0,
    }

    for f in findings:
        if f.severity in severity_count:
            severity_count[f.severity] += 1

    labels = [k for k, v in severity_count.items() if v > 0]
    values = [severity_count[k] for k in labels]

    if not values:
        labels = ["No findings"]
        values = [1]

    colors_map = {
        "Critical": "#c62828",
        "High": "#ef6c00",
        "Medium": "#f9a825",
        "Low": "#2e7d32",
        "Info": "#1565c0",
        "No findings": "#90a4ae",
    }
    pie_colors = [colors_map.get(l, "#546e7a") for l in labels]

    fig, axes = plt.subplots(1, 2, figsize=(10, 5))
    fig.patch.set_facecolor("#eceff1")
    fig.suptitle("AutoVuln Scanner — Assessment overview", fontsize=14, fontweight="bold")

    axes[0].pie(
        values,
        labels=labels,
        autopct="%1.0f%%" if sum(values) else None,
        startangle=40,
        colors=pie_colors,
        textprops={"fontsize": 9},
    )
    axes[0].set_title("Findings by severity")

    bar_labels = ["Score"]
    axes[1].barh(bar_labels, [score], color="#3949ab", height=0.35)
    axes[1].set_xlim(0, 100)
    axes[1].set_xlabel("Security score (higher is better)")
    axes[1].set_title("Overall security score")
    for spine in ("top", "right"):
        axes[1].spines[spine].set_visible(False)

    plt.tight_layout()
    plt.show()
