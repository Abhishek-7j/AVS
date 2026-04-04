"""
Spectral Surface Map — polar view of open ports weighted by finding severity.
Distinct from typical bar/pie dashboards: one glance at “where risk lives” on the port axis.
"""
from __future__ import annotations

import math

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

from intel_fusion import TargetIntel
from plugins import Finding

SEV_COLOR = {
    "Critical": "#d32f2f",
    "High": "#f57c00",
    "Medium": "#fbc02d",
    "Low": "#388e3c",
    "Info": "#1976d2",
}


def _severity_rank(sev: str) -> float:
    return {"Critical": 4.0, "High": 3.0, "Medium": 2.0, "Low": 1.0, "Info": 0.5}.get(sev, 1.0)


def show_spectral_surface(
    scan_rows: list[tuple],
    findings: list[Finding],
    intel: TargetIntel | None = None,
) -> None:
    port_to_max: dict[int, float] = {}
    for p, _, _ in scan_rows:
        port_to_max[int(p)] = 0.0
    for f in findings:
        if f.port is None:
            continue
        p = int(f.port)
        r = _severity_rank(f.severity)
        port_to_max[p] = max(port_to_max.get(p, 0.0), r)

    if not port_to_max:
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.text(0.5, 0.5, "Run a scan to render the Spectral Surface map.", ha="center", va="center")
        ax.axis("off")
        plt.show()
        return

    ports = sorted(port_to_max.keys())
    theta = [2 * math.pi * (p / 65535.0) for p in ports]
    radii = [0.25 + 0.75 * min(1.0, port_to_max.get(p, 0.25) / 4.0) for p in ports]
    colors = []
    for p in ports:
        rank = port_to_max.get(p, 0.25)
        if rank >= 3.5:
            colors.append(SEV_COLOR["Critical"])
        elif rank >= 2.5:
            colors.append(SEV_COLOR["High"])
        elif rank >= 1.5:
            colors.append(SEV_COLOR["Medium"])
        elif rank >= 0.9:
            colors.append(SEV_COLOR["Low"])
        else:
            colors.append("#5c6bc0")

    fig = plt.figure(figsize=(9, 5.2))
    fig.patch.set_facecolor("#0d1117")
    axp = fig.add_subplot(121, projection="polar", facecolor="#0d1117")
    axp.set_theta_zero_location("N")
    axp.set_theta_direction(-1)
    axp.set_ylim(0, 1.15)
    axp.set_yticklabels([])
    axp.grid(True, color="#30363d", alpha=0.6)
    axp.scatter(theta, radii, c=colors, s=[42 + 80 * r for r in radii], alpha=0.92, edgecolors="#e3eafc", linewidths=0.35)
    axp.set_title("Spectral Surface — port angle · radius = risk heat", color="#e6edf3", pad=14, fontsize=11)

    axb = fig.add_subplot(122, facecolor="#0d1117")
    axb.set_facecolor("#0d1117")
    labels = ["Critical", "High", "Medium", "Low", "Info"]
    handles = [mpatches.Patch(color=SEV_COLOR[k], label=k) for k in labels]
    axb.legend(handles=handles, loc="upper left", frameon=False, labelcolor="#e6edf3")
    axb.tick_params(colors="#e6edf3")
    for spine in axb.spines.values():
        spine.set_color("#30363d")

    lines = ["Intel snapshot", "—" * 28]
    if intel:
        lines.append(f"Query: {intel.query}")
        lines.append(f"IPv4: {intel.resolved_ipv4}")
        if intel.reverse_ptr:
            lines.append(f"PTR: {', '.join(intel.reverse_ptr[:3])}")
        if intel.dns_aliases:
            lines.append(f"Aliases: {', '.join(intel.dns_aliases[:4])}")
        lines.append(f"HTTP layers: {len(intel.http_layers)} · TLS records: {len(intel.tls_layers)}")
    else:
        lines.append("No intel fusion data (run full pipeline).")

    lines.append("")
    lines.append("Open services")
    lines.append("—" * 28)
    for port, svc, ver in scan_rows[:14]:
        v = (ver or "")[:28]
        lines.append(f"{port:>5}  {svc}  {v}")
    if len(scan_rows) > 14:
        lines.append(f"… +{len(scan_rows) - 14} more")

    axb.text(0.02, 0.98, "\n".join(lines), transform=axb.transAxes, va="top", ha="left", fontsize=9, color="#c9d1d9", family="monospace")
    axb.axis("off")

    plt.tight_layout()
    plt.show()
