import threading

import customtkinter as ctk

from config import skip_login
from cve_lookup import search_cve
from dashboard import show_dashboard
from database import get_scan_history, init_db, save_scan
from exporter import export_full_report
from intel_fusion import TargetIntel, gather_intel
from login import show_login
from plugins import Finding
from report_generator import generate_report
from scanner import PROFILES, scan_target
from spectral_surface import show_spectral_surface
from target_dossier import build_target_dossier
from vuln_checker import calculate_risk_score, check_vulnerabilities

results: list[tuple] = []
findings: list[Finding] = []
score = 0
risk_level = ""
last_profile = "standard"
last_resolved_host = ""
last_intel: TargetIntel | None = None

target_entry = None
results_box = None
progress_bar = None
status_label = None
history_box = None
profile_var = None
fusion_var = None
root = None


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.withdraw()

init_db()


def ui_log(msg: str) -> None:
    def _append() -> None:
        if results_box:
            results_box.insert("end", msg)
            results_box.see("end")

    if root:
        root.after(0, _append)


def view_history() -> None:
    if not history_box:
        return
    rows = get_scan_history()
    history_box.delete("1.0", "end")
    history_box.insert("end", "Scan history (latest first)\n")
    history_box.insert("end", "—" * 52 + "\n")
    for row in rows:
        sid, target, date, sc, risk, prof = (
            (row + (None,) * 6)[:6]
        )
        p = prof or "—"
        history_box.insert(
            "end",
            f"#{sid}  {target}  |  {date}  |  score {sc}  |  {risk}  |  {p}\n",
        )


def generate_pdf() -> None:
    global results, findings, score, risk_level, last_profile
    if not target_entry:
        return
    target = target_entry.get().strip().split()[0] if target_entry.get().strip() else "target"
    intel_d = last_intel.as_dict() if last_intel else None
    filename = generate_report(
        target,
        results,
        findings,
        score,
        risk_level,
        profile=last_profile,
        intel=intel_d,
    )
    ui_log(f"\n📄 Report generated: {filename}\n")


def export_report() -> None:
    global results, findings, score, risk_level, last_profile
    if not target_entry:
        return
    target = target_entry.get().strip().split()[0] if target_entry.get().strip() else "target"
    intel_d = last_intel.as_dict() if last_intel else None
    folder = export_full_report(
        target,
        results,
        findings,
        score,
        risk_level,
        profile=last_profile,
        intel=intel_d,
    )
    ui_log(f"\n📁 Full export folder: {folder}\n")


def start_scan() -> None:
    global results, findings, score, risk_level, last_profile, last_resolved_host, last_intel

    if not target_entry or not progress_bar or not status_label:
        return

    targets = [t for t in target_entry.get().split() if t.strip()]
    if not targets:
        ui_log("Enter at least one target (hostname or IP).\n")
        return

    profile = (profile_var.get() if profile_var else "standard") or "standard"
    last_profile = profile
    do_fusion = bool(fusion_var.get()) if fusion_var else True

    def set_status(text: str) -> None:
        root.after(0, lambda: status_label.configure(text=text))

    def set_progress(v: float) -> None:
        root.after(0, lambda: progress_bar.set(v))

    set_status("Status: Starting scan…")
    set_progress(0)
    root.after(0, lambda: results_box.delete("1.0", "end") if results_box else None)
    ui_log("Surface DNA pipeline — pulse → fingerprint → intel fusion → plugins → CVE\n")
    ui_log('(No tool can guarantee "all" vulnerabilities; fusion maximizes observable signal.)\n\n')
    ui_log(f"Profile: {profile} — {PROFILES.get(profile, PROFILES['standard'])}\n")
    ui_log(f"Intel fusion: {'ON' if do_fusion else 'OFF'}\n\n")

    def run_scan() -> None:
        global results, findings, score, risk_level, last_resolved_host, last_intel

        total_targets = len(targets)
        step = 1.0 / total_targets if total_targets else 1.0
        current = 0.0

        for target in targets:
            ui_log(f"\n{'═' * 50}\n🎯 Target: {target}\n{'═' * 50}\n")

            set_status(f"Scanning ports ({profile})…")
            set_progress(current + step * 0.12)

            scan_results, resolved, meta = scan_target(target, profile=profile)
            last_resolved_host = resolved
            results = scan_results

            ui_log(f"Resolved host: {resolved}\n")
            if meta.get("pulse_open_ports") is not None:
                ui_log(
                    f"⚡ Pulse sweep: {len(meta['pulse_open_ports'])} open TCP ports in signal set\n"
                )
            if meta.get("hyper_note"):
                ui_log(f"   {meta['hyper_note']}\n")
            ui_log("\nPort\tService\tVersion\n")
            ui_log("—" * 40 + "\n")
            if not scan_results:
                ui_log("(no open ports reported — check Nmap install / target reachability)\n")
            for port, service, version in scan_results:
                ui_log(f"{port}\t{service}\t{version}\n")

            intel = None
            if do_fusion:
                set_status("Intel fusion (HTTP/TLS/DNS)…")
                set_progress(current + step * 0.28)
                intel = gather_intel(target, resolved, scan_results)
                last_intel = intel
                ui_log("\n🧬 Intel fusion\n")
                ui_log("—" * 40 + "\n")
                ui_log(f"PTR: {', '.join(intel.reverse_ptr) or '—'}\n")
                ui_log(f"Aliases: {', '.join(intel.dns_aliases) or '—'}\n")
                for layer in intel.http_layers:
                    ui_log(
                        f"  {layer.get('scheme')}:{layer.get('port')} {layer.get('path', '/')} "
                        f"{layer.get('status_line', '')[:72]}\n"
                    )
                    if layer.get("path", "/") == "/" and layer.get("title"):
                        ui_log(f"      title: {layer.get('title', '')[:100]}\n")
                    if layer.get("path") == "/robots.txt" and layer.get("body_preview"):
                        ui_log(f"      robots preview: {layer.get('body_preview', '')[:80]}…\n")
                for t in intel.tls_layers:
                    ui_log(
                        f"  TLS:{t.get('port')} {t.get('negotiated', '')} "
                        f"cipher={t.get('cipher', [])[:2]} exp={t.get('not_after', '')}\n"
                    )
                ui_log("\n📡 Deep DNS (host + apex)\n")
                ui_log("—" * 40 + "\n")
                dd = intel.dns_deep
                rp = dd.get("reachability_probe") or {}
                ui_log(f"TCP quick check: 80={rp.get('tcp_80')}  443={rp.get('tcp_443')}\n")
                ui_log(f"Apex domain: {dd.get('apex_name') or '—'}\n")
                hr = dd.get("host") or {}
                for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
                    v = hr.get(rtype)
                    if isinstance(v, list) and v:
                        tail = ", ".join(v[:5])
                        extra = f" (+{len(v) - 5} more)" if len(v) > 5 else ""
                        ui_log(f"  {rtype}: {tail}{extra}\n")
            else:
                last_intel = None

            set_status("Running vulnerability plugins…")
            set_progress(current + step * 0.42)

            findings = check_vulnerabilities(resolved, scan_results, intel=intel)

            set_status("Querying NVD for related CVEs…")
            set_progress(current + step * 0.58)

            ui_log("\n🔎 CVE keyword lookup (NVD API)\n")
            ui_log("—" * 40 + "\n")
            for port, service, version in scan_results:
                cves = search_cve(service, version)
                if cves:
                    ui_log(f"\n{service} {version} (port {port})\n")
                    for cve_id, desc in cves:
                        ui_log(f"  • {cve_id}: {desc}…\n")

            if findings:
                ui_log("\n⚠ Plugin findings\n")
                ui_log("—" * 40 + "\n")
                for f in findings:
                    ui_log(
                        f"[{f.severity}] {f.plugin_id} — {f.name}\n"
                        f"    CVSS {f.cvss}  port {f.port}  ({f.service})\n"
                        f"    {f.description[:220]}{'…' if len(f.description) > 220 else ''}\n"
                        f"    → {f.solution[:180]}{'…' if len(f.solution) > 180 else ''}\n\n"
                    )
            else:
                ui_log("\n✓ No plugin findings for exposed services (still verify manually).\n")

            set_status("Calculating risk…")
            set_progress(current + step * 0.82)

            score, risk_level = calculate_risk_score(findings)

            findings_payload = [f.as_dict() for f in findings]
            ports_payload = [
                {"port": p, "service": s, "version": v} for p, s, v in scan_results
            ]
            save_scan(
                target,
                score,
                risk_level,
                findings=findings_payload,
                ports=ports_payload,
                profile=profile,
                intel=intel.as_dict() if intel else None,
            )

            ui_log("\n🔐 Security assessment\n")
            ui_log("—" * 40 + "\n")
            ui_log(f"Security score: {score}/100\n")
            ui_log(f"Risk level: {risk_level}\n")

            dossier_bundle = {
                "target": target,
                "resolved": resolved,
                "intel_fusion": intel.as_dict() if intel else {},
                "open_ports": ports_payload,
                "findings": findings_payload,
                "score": score,
                "risk_level": risk_level,
                "cve_hints": {},
            }
            dossier = build_target_dossier(dossier_bundle)
            ui_log("\n📋 Target dossier (summary)\n")
            ui_log("—" * 40 + "\n")
            ui_log(f"{dossier.get('scope_note', '')}\n")
            ui_log(
                f"Open ports: {dossier['surface']['open_port_count']} · "
                f"HTTP probes: {dossier['application_intel']['http_probes']} · "
                f"TLS records: {dossier['application_intel']['tls_inspections']} · "
                f"Findings: {dossier['assessment']['finding_count']}\n"
            )

            current += step
            set_progress(min(1.0, current))

        set_status("Scan completed")
        set_progress(1.0)
        if risk_level == "Critical":
            set_status("⚠ Critical risk — review findings immediately")
        elif risk_level == "High":
            set_status("⚠ High risk — prioritize remediation")

    threading.Thread(target=run_scan, daemon=True).start()


def open_dashboard() -> None:
    show_dashboard(findings, score)


def open_spectral() -> None:
    show_spectral_surface(results, findings, intel=last_intel)


def start_scanner() -> None:
    global target_entry, results_box, progress_bar, status_label, history_box, profile_var, fusion_var

    root.deiconify()
    root.title("AutoVuln Scanner — Surface DNA")
    root.geometry("980x740")
    root.minsize(860, 620)

    header = ctk.CTkFrame(root, fg_color="transparent")
    header.pack(fill="x", padx=24, pady=(20, 8))

    title = ctk.CTkLabel(
        header,
        text="AutoVuln Scanner",
        font=ctk.CTkFont(size=26, weight="bold"),
    )
    title.pack(anchor="w")
    subtitle = ctk.CTkLabel(
        header,
        text="Hyper pulse sweep · Targeted fingerprint · Intel fusion · Spectral surface map",
        font=ctk.CTkFont(size=13),
        text_color=("gray30", "gray70"),
    )
    subtitle.pack(anchor="w", pady=(4, 0))

    tabview = ctk.CTkTabview(root, width=900, height=540)
    tabview.pack(fill="both", expand=True, padx=20, pady=10)

    tabview.add("Scanner")
    tabview.add("Reports")
    tabview.add("Dashboard")
    tabview.add("History")

    scanner_tab = tabview.tab("Scanner")
    reports_tab = tabview.tab("Reports")
    dashboard_tab = tabview.tab("Dashboard")
    history_tab = tabview.tab("History")

    profile_var = ctk.StringVar(value="hyper")
    fusion_var = ctk.BooleanVar(value=True)

    row = ctk.CTkFrame(scanner_tab, fg_color="transparent")
    row.pack(fill="x", pady=(8, 4))

    ctk.CTkLabel(row, text="Scan profile").pack(side="left", padx=(0, 8))
    profile_menu = ctk.CTkOptionMenu(
        row,
        values=list(PROFILES.keys()),
        variable=profile_var,
        width=130,
    )
    profile_menu.pack(side="left", padx=(0, 16))

    ctk.CTkCheckBox(row, text="Intel fusion (HTTP/TLS/DNS)", variable=fusion_var).pack(side="left")

    hint = ctk.CTkLabel(
        scanner_tab,
        text="hyper: parallel pulse + Nmap only on hits (fast) · deep: NSE scripts + strong fingerprint",
        font=ctk.CTkFont(size=11),
        text_color=("gray40", "gray65"),
    )
    hint.pack(anchor="w", padx=4, pady=(0, 6))

    target_entry = ctk.CTkEntry(
        scanner_tab,
        width=520,
        placeholder_text="Targets: hostname or IP (space-separated for multiple)",
    )
    target_entry.pack(pady=8, fill="x", padx=4)
    target_entry.bind("<Return>", lambda _e: start_scan())

    scan_button = ctk.CTkButton(
        scanner_tab,
        text="Start assessment",
        command=start_scan,
        width=180,
        height=36,
        font=ctk.CTkFont(size=14, weight="bold"),
    )
    scan_button.pack(pady=6)

    status_label = ctk.CTkLabel(scanner_tab, text="Status: Idle")
    status_label.pack(pady=4)

    progress_bar = ctk.CTkProgressBar(scanner_tab, width=520)
    progress_bar.pack(pady=4, fill="x", padx=4)
    progress_bar.set(0)

    results_box = ctk.CTkTextbox(scanner_tab, width=880, height=360, font=ctk.CTkFont(family="Consolas", size=12))
    results_box.pack(fill="both", expand=True, pady=12, padx=4)

    ctk.CTkButton(
        reports_tab,
        text="Generate PDF report",
        command=generate_pdf,
        width=220,
    ).pack(pady=16)
    ctk.CTkButton(
        reports_tab,
        text="Export JSON + text bundle",
        command=export_report,
        width=220,
    ).pack(pady=8)
    ctk.CTkLabel(
        reports_tab,
        text="Exports include open ports, plugin metadata, CVSS, and remediation text.",
        wraplength=400,
        justify="left",
        text_color=("gray40", "gray65"),
    ).pack(pady=20)

    ctk.CTkButton(
        dashboard_tab,
        text="Classic dashboard (pie + score)",
        command=open_dashboard,
        width=260,
    ).pack(pady=14)
    ctk.CTkButton(
        dashboard_tab,
        text="Spectral Surface map (polar port/risk view)",
        command=open_spectral,
        width=260,
        fg_color=("#6a1b9a", "#7b1fa2"),
        hover_color=("#4a148c", "#6a1b9a"),
    ).pack(pady=10)
    ctk.CTkLabel(
        dashboard_tab,
        text="Run a scan first. Spectral map needs open ports / findings for contrast.",
        text_color=("gray40", "gray65"),
        wraplength=420,
        justify="left",
    ).pack(pady=12)

    history_box = ctk.CTkTextbox(history_tab, width=840, height=400, font=ctk.CTkFont(family="Consolas", size=12))
    history_box.pack(fill="both", expand=True, pady=12, padx=8)
    ctk.CTkButton(history_tab, text="Refresh history", command=view_history, width=160).pack(pady=8)


if skip_login():
    start_scanner()
else:
    show_login(root, start_scanner)

root.mainloop()
