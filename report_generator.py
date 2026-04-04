from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from xml.sax.saxutils import escape

from plugins import Finding


def generate_report(
    target: str,
    results: list[tuple],
    findings: list[Finding],
    score: int,
    risk_level: str,
    profile: str = "",
    intel: dict | None = None,
) -> str:
    safe_target = "".join(c if c.isalnum() or c in "-._" else "_" for c in target)[:80]
    filename = f"scan_report_{safe_target}.pdf"

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=20,
        spaceAfter=14,
        textColor=colors.HexColor("#1a237e"),
    )
    elements: list = []

    elements.append(Paragraph("AutoVuln Scanner — Security Assessment", title_style))
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(Paragraph(f"<b>Target:</b> {target}", styles["Normal"]))
    if profile:
        elements.append(Paragraph(f"<b>Scan profile:</b> {profile}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Security score:</b> {score}/100", styles["Normal"]))
    elements.append(Paragraph(f"<b>Risk level:</b> {risk_level}", styles["Normal"]))
    elements.append(Spacer(1, 0.2 * inch))

    elements.append(Paragraph("Executive summary", styles["Heading2"]))
    summary = (
        "This report summarizes exposed services and configuration weaknesses observed from the network. "
        "No scanner can enumerate every vulnerability without authenticated, in-depth testing. "
        "Remediate Critical and High items first, then validate with a rescan."
    )
    elements.append(Paragraph(summary, styles["Normal"]))
    elements.append(Spacer(1, 0.15 * inch))

    if intel:
        elements.append(Paragraph("Surface intel fusion", styles["Heading2"]))
        ip = escape(str(intel.get("resolved_ipv4", "")))
        ptr = ", ".join(intel.get("reverse_ptr") or [])[:500]
        aliases = ", ".join(intel.get("dns_aliases") or [])[:500]
        elements.append(Paragraph(f"<b>IPv4:</b> {ip}", styles["Normal"]))
        if ptr:
            elements.append(Paragraph(f"<b>PTR:</b> {escape(ptr)}", styles["Normal"]))
        if aliases:
            elements.append(Paragraph(f"<b>DNS aliases:</b> {escape(aliases)}", styles["Normal"]))
        elements.append(
            Paragraph(
                f"<b>HTTP layers:</b> {len(intel.get('http_layers') or [])} · "
                f"<b>TLS records:</b> {len(intel.get('tls_layers') or [])}",
                styles["Normal"],
            )
        )
        for h in (intel.get("http_layers") or [])[:6]:
            title = escape(str(h.get("title", ""))[:120])
            st = escape(str(h.get("status_line", ""))[:120])
            elements.append(
                Paragraph(
                    f"— {h.get('scheme')}:{h.get('port')} {st} <i>{title}</i>",
                    styles["Normal"],
                )
            )
        elements.append(Spacer(1, 0.15 * inch))

    elements.append(Paragraph("Open ports and services", styles["Heading2"]))
    table_data = [["Port", "Service", "Version"]]
    for port, service, version in results:
        table_data.append([str(port), str(service), str(version) or "—"])

    t = Table(table_data, colWidths=[0.7 * inch, 1.4 * inch, 3.5 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3949ab")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
            ]
        )
    )
    elements.append(t)
    elements.append(Spacer(1, 0.2 * inch))

    elements.append(Paragraph("Findings (plugin-style)", styles["Heading2"]))
    if findings:
        for f in findings:
            line = (
                f"<b>[{escape(f.plugin_id)}] {escape(f.name)}</b> — Severity: {escape(f.severity)} "
                f"(CVSS {f.cvss})<br/>"
                f"{escape(f.description)}<br/><i>Remediation:</i> {escape(f.solution)}"
            )
            elements.append(Paragraph(line, styles["Normal"]))
            elements.append(Spacer(1, 0.08 * inch))
    else:
        elements.append(Paragraph("No plugin findings for this target.", styles["Normal"]))

    elements.append(Spacer(1, 0.15 * inch))
    elements.append(Paragraph("Recommendations", styles["Heading2"]))
    for i, text in enumerate(
        [
            "Patch or upgrade services with disclosed versions; subscribe to vendor advisories.",
            "Close or firewall ports that do not require broad network exposure.",
            "Replace legacy protocols (Telnet, FTP cleartext) with SSH, SFTP, or FTPS.",
            "Enforce TLS 1.2+ and disable weak ciphers; test with SSL Labs or testssl.sh.",
            "Re-run scans after changes to verify risk reduction.",
        ],
        start=1,
    ):
        elements.append(Paragraph(f"{i}. {text}", styles["Normal"]))

    pdf = SimpleDocTemplate(filename, pagesize=letter, topMargin=0.75 * inch, bottomMargin=0.65 * inch)
    pdf.build(elements)

    return filename
