"""
Secure Web Report Server & Interactive Assessment Console for AVS (HTTPS).
Generates self-signed SSL certificates automatically, handles web-based scans,
streams log outputs in real-time, and serves a dedicated interactive details page (/report).
"""
from __future__ import annotations

import os
import ssl
import json
import http.server
import socketserver
import threading
import shutil
from datetime import datetime, timezone, timedelta
from urllib.parse import unquote, parse_qs

# Cryptography imports for self-signed SSL certificate generation
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cli import run_assessment
from exporter import export_full_report
from report_generator import generate_report
from plugins import Finding

import os
PORT = int(os.environ.get("PORT", 8080))
DISABLE_HTTPS = (
    os.environ.get("AVS_DISABLE_HTTPS", "false").lower() in ("1", "true", "yes")
    or os.path.exists("/.dockerenv")
    or "RENDER" in os.environ
    or "PORT" in os.environ
)

# Dicts to track active scans and console log streams
ACTIVE_SCANS: dict[str, str] = {}
ACTIVE_LOGS: dict[str, list[str]] = {}


def generate_self_signed_cert(cert_path="cert.pem", key_path="key.pem") -> None:
    """Generates a secure 2048-bit RSA self-signed TLS certificate dynamically in-memory."""
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return
        
    print("[*] Generating dynamic self-signed SSL certificate for HTTPS...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc) - timedelta(days=1)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("[*] Certificate and private key created successfully.")


def run_background_scan(target: str, profile: str, fusion: bool, cve: bool, ports_spec: str) -> None:
    def log(msg: str):
        time_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
        ACTIVE_LOGS[target].append(f"[{time_str}] {msg}")
        ACTIVE_SCANS[target] = msg

    try:
        ACTIVE_LOGS[target] = []
        log("Enqueuing scan parameters...")
        
        # 1. Port scan execution
        log(f"Starting port discovery sweep (Profile: {profile}, Custom Ports: {ports_spec or 'default'})...")
        bundle = run_assessment(target, profile, fusion, cve, ports_spec=ports_spec or None)
        
        # 2. Heuristics & CVE checks
        log("Evaluating passive vulnerability plugins & validating server headers...")
        findings_objs = []
        for f in bundle.get("findings", []):
            findings_objs.append(
                Finding(
                    plugin_id=f.get("plugin_id", ""),
                    name=f.get("name", ""),
                    severity=f.get("severity", "Info"),
                    cvss=f.get("cvss", 0.0),
                    port=f.get("port"),
                    service=f.get("service"),
                    description=f.get("description", ""),
                    solution=f.get("solution", ""),
                    refs=f.get("refs", [])
                )
            )
            
        results_tuples = [(p["port"], p["service"], p["version"]) for p in bundle.get("open_ports", [])]
        intel_d = bundle.get("intel_fusion")
        
        log(f"Discovered {len(results_tuples)} open port(s) and {len(findings_objs)} vulnerability finding(s).")
        
        # 3. PDF/Full Exports compilations
        log("Compiling security assessment PDF report...")
        pdf_file = generate_report(
            target,
            results_tuples,
            findings_objs,
            bundle["score"],
            bundle["risk_level"],
            profile=profile,
            intel=intel_d
        )
        
        log("Packaging JSON bundle and reports folder structure...")
        folder = export_full_report(
            target,
            results_tuples,
            findings_objs,
            bundle["score"],
            bundle["risk_level"],
            profile=profile,
            intel=intel_d
        )
        
        # Copy the PDF into the output directory for unified download access
        if os.path.exists(pdf_file):
            shutil.move(pdf_file, os.path.join(folder, pdf_file))
            
        log("Vulnerability Assessment completed successfully.")
        ACTIVE_SCANS[target] = "Completed"
    except Exception as e:
        log(f"Failed: {str(e)}")


class SecureReportServerHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path == "/scan":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = parse_qs(post_data)
            
            target = params.get('target', [''])[0].strip()
            profile = params.get('profile', ['standard'])[0]
            fusion = params.get('fusion', ['false'])[0] == 'true'
            cve = params.get('cve', ['false'])[0] == 'true'
            ports_spec = params.get('ports', [''])[0].strip()
            
            if not target:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Target hostname or IP is required.")
                return
            
            # Start background scanning thread
            ACTIVE_SCANS[target] = "Awaiting scanner thread execution..."
            ACTIVE_LOGS[target] = []
            threading.Thread(target=run_background_scan, args=(target, profile, fusion, cve, ports_spec), daemon=True).start()
            
            # Redirect to progress checking page
            self.send_response(303)
            self.send_header('Location', f'/scan-progress?target={target}')
            self.end_headers()
            return
            
        self.send_error(404, "Route Not Found")

    def do_GET(self) -> None:
        parsed_url = self.path.split("?")
        path = unquote(parsed_url[0]).strip("/")
        
        # 1. Main Dashboard Index
        if not path or path == "index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(self._generate_dashboard_html().encode("utf-8"))
            return
            
        # 2. Scanning Progress Page
        if path == "scan-progress":
            params = parse_qs(parsed_url[1]) if len(parsed_url) > 1 else {}
            target = params.get('target', [''])[0]
            
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(self._generate_progress_html(target).encode("utf-8"))
            return

        # 3. Interactive Report View
        if path == "report":
            params = parse_qs(parsed_url[1]) if len(parsed_url) > 1 else {}
            folder = params.get('folder', [''])[0].strip()
            
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(self._generate_report_detail_html(folder).encode("utf-8"))
            return

        # 4. Dynamic Static File Server (PDF, JSON, TXT)
        if os.path.exists(path) and os.path.isfile(path):
            super().do_GET()
            return

        self.send_error(404, "File Not Found")

    def _generate_progress_html(self, target: str) -> str:
        status = ACTIVE_SCANS.get(target, "Awaiting status...")
        logs = "\n".join(ACTIVE_LOGS.get(target, ["No logs initialized yet."]))
        
        redirect_meta = ""
        loader_class = "loader"
        error_msg = ""
        
        if status == "Completed":
            redirect_meta = '<meta http-equiv="refresh" content="0;url=/">'
        elif status.startswith("Failed"):
            loader_class = "loader-failed"
            error_msg = f"<div class='error-box'>{status}</div>"
        else:
            redirect_meta = '<meta http-equiv="refresh" content="2">'
            
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    {redirect_meta}
    <title>AVS — Scanning...</title>
    <style>
        body {{
            background-color: #0b0f19;
            color: #f3f4f6;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background-image: radial-gradient(circle at 50% 50%, rgba(139, 92, 246, 0.1) 0%, transparent 60%);
        }}
        .card {{
            background: rgba(17, 24, 39, 0.75);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            padding: 30px;
            border-radius: 16px;
            text-align: center;
            max-width: 650px;
            width: 90%;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
        }}
        h2 {{
            margin-top: 0;
            background: linear-gradient(135deg, #a78bfa 0%, #60a5fa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .status-text {{
            font-size: 16px;
            color: #9ca3af;
            margin: 10px 0;
        }}
        .loader {{
            width: 45px;
            height: 45px;
            border: 4px solid rgba(139, 92, 246, 0.2);
            border-top: 4px solid #8b5cf6;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }}
        .loader-failed {{
            width: 45px;
            height: 45px;
            border: 4px solid rgba(239, 68, 68, 0.2);
            border-top: 4px solid #ef4444;
            border-radius: 50%;
            margin: 20px auto;
            position: relative;
        }}
        .loader-failed::after {{
            content: "❌";
            font-size: 20px;
            position: absolute;
            top: 8px;
            left: 10px;
        }}
        .console-log {{
            background: #000;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 14px;
            font-family: "Consolas", monospace;
            font-size: 13px;
            color: #34d399;
            text-align: left;
            height: 180px;
            overflow-y: auto;
            white-space: pre-wrap;
            margin-top: 15px;
            box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.8);
        }}
        .error-box {{
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
            padding: 12px;
            border-radius: 8px;
            margin-top: 14px;
            font-size: 14px;
            text-align: left;
        }}
        .btn {{
            display: inline-block;
            background: rgba(255, 255, 255, 0.1);
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 14px;
            margin-top: 15px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }}
        .btn:hover {{
            background: rgba(255, 255, 255, 0.15);
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="card">
        <h2>AVS Assessment Engine</h2>
        <div class="status-text">Scanning Target: <strong style="color: #60a5fa;">{target}</strong></div>
        <div class="{loader_class}"></div>
        <div class="status-text" style="color: #fff; font-weight: 600;">{status}</div>
        <div class="console-log">{logs}</div>
        {error_msg}
        {f'<a class="btn" href="/">Return to Dashboard</a>' if "Failed" in status or "Completed" in status else ''}
    </div>
</body>
</html>
"""

    def _generate_report_detail_html(self, folder: str) -> str:
        """Generates the interactive Report details page showing CNAME takeovers, CORS issues, ports, and root causes."""
        bundle_file = os.path.join(folder, "scan_bundle.json")
        if not os.path.exists(bundle_file):
            return f"<h3>Scan report {folder} not found.</h3>"
            
        try:
            with open(bundle_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return f"<h3>Failed to read report file: {str(e)}</h3>"
            
        target = data.get("target", "unknown")
        resolved = data.get("resolved", "unknown")
        score = data.get("score", 0)
        risk = data.get("risk_level", "Info")
        findings = data.get("findings", [])
        ports = data.get("open_ports", [])
        scanned_at = data.get("scanned_at_utc", "")[:16].replace("T", " ")
        
        # Identity and DNS aliases
        intel = data.get("intel_fusion") or {}
        ptr = ", ".join(intel.get("reverse_ptr") or []) or "—"
        aliases = ", ".join(intel.get("dns_aliases") or []) or "—"
        
        # Build Open Ports Table Rows
        ports_rows = ""
        if not ports:
            ports_rows = "<tr><td colspan='3' style='text-align:center;'>No open ports identified.</td></tr>"
        else:
            for p in ports:
                ports_rows += f"""
                <tr>
                    <td><strong>{p.get('port')}</strong></td>
                    <td><span class="badge badge-ports">{p.get('service')}</span></td>
                    <td style="font-family: monospace;">{p.get('version') or '—'}</td>
                </tr>
                """
                
        # Build Vulnerability Findings List
        findings_html = ""
        if not findings:
            findings_html = "<div class='empty-card'>No vulnerability findings reported. Secure configuration confirmed!</div>"
        else:
            for i, f in enumerate(findings):
                sev_lower = f.get('severity', 'info').lower()
                cve_badge = f'<span class="cve-tag">{f.get("plugin_id")}</span>'
                findings_html += f"""
                <div class="vuln-card">
                    <div class="vuln-header" onclick="toggleAccordion('vuln-{i}')">
                        <div style="display:flex; align-items:center; gap:12px;">
                            <span class="badge risk-{sev_lower}">{f.get('severity')}</span>
                            <span class="vuln-title">{f.get('name')}</span>
                        </div>
                        <div style="display:flex; align-items:center; gap:8px;">
                            {cve_badge}
                            <span class="arrow-icon" id="arrow-vuln-{i}">▼</span>
                        </div>
                    </div>
                    <div class="vuln-content" id="vuln-{i}" style="display: none;">
                        <div style="margin-bottom:12px; font-size: 13px; color: var(--text-secondary);">
                            <strong>CVSS Score:</strong> {f.get('cvss')} | 
                            <strong>Target Interface:</strong> Port {f.get('port') or 'None'} ({f.get('service') or 'system'})
                        </div>
                        <p style="white-space: pre-line;">{f.get('description')}</p>
                        <div class="solution-box">
                            <strong>Remediation Strategy:</strong>
                            <p style="margin: 6px 0 0 0;">{f.get('solution')}</p>
                        </div>
                        {f'<div style="margin-top:12px; font-size:12px;"><strong>References:</strong> ' + ", ".join(f.get('refs', [])) + '</div>' if f.get('refs') else ''}
                    </div>
                </div>
                """
                
        risk_class = f"risk-{risk.lower()}"
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AVS Assessment — {target}</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --container-bg: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --risk-critical: #ef4444;
            --risk-high: #f97316;
            --risk-medium: #eab308;
            --risk-low: #10b981;
            --risk-info: #3b82f6;
        }}
        body {{
            background-color: var(--bg-color);
            background-image: radial-gradient(circle at 10% 20%, rgba(139, 92, 246, 0.1) 0%, transparent 45%);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            color: var(--text-primary);
            margin: 0;
            padding: 40px 20px;
        }}
        .report-header {{
            max-width: 1000px;
            margin: 0 auto 30px auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        h1 {{
            margin: 0;
            background: linear-gradient(135deg, #a78bfa 0%, #60a5fa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 26px;
        }}
        .btn-back {{
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid var(--border-color);
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 14px;
        }}
        .btn-back:hover {{
            background: rgba(255, 255, 255, 0.15);
        }}
        .grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 24px;
            max-width: 1000px;
            margin: 0 auto;
        }}
        @media(min-width: 900px) {{
            .grid {{
                grid-template-columns: 1fr 340px;
            }}
        }}
        .container {{
            background: var(--container-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);
        }}
        .sec-title {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 8px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: capitalize;
        }}
        .risk-critical {{
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}
        .risk-high {{
            background: rgba(249, 115, 22, 0.15);
            color: #fdba74;
            border: 1px solid rgba(249, 115, 22, 0.3);
        }}
        .risk-medium {{
            background: rgba(234, 179, 8, 0.15);
            color: #fde047;
            border: 1px solid rgba(234, 179, 8, 0.3);
        }}
        .risk-low {{
            background: rgba(16, 185, 129, 0.15);
            color: #6ee7b7;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        .risk-info {{
            background: rgba(59, 130, 246, 0.15);
            color: #93c5fd;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }}
        .vuln-card {{
            border: 1px solid rgba(255, 255, 255, 0.05);
            background: rgba(0, 0, 0, 0.2);
            border-radius: 8px;
            margin-bottom: 14px;
            overflow: hidden;
        }}
        .vuln-header {{
            padding: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            background: rgba(255, 255, 255, 0.01);
            user-select: none;
        }}
        .vuln-header:hover {{
            background: rgba(255, 255, 255, 0.04);
        }}
        .vuln-title {{
            font-weight: 600;
            font-size: 15px;
        }}
        .vuln-content {{
            padding: 16px;
            border-top: 1px solid rgba(255, 255, 255, 0.04);
            background: rgba(0, 0, 0, 0.3);
            font-size: 14px;
            line-height: 1.5;
        }}
        .cve-tag {{
            font-family: monospace;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
            color: #d1d5db;
        }}
        .solution-box {{
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.2);
            padding: 12px;
            border-radius: 8px;
            margin-top: 12px;
            color: #a7f3d0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            text-align: left;
            color: var(--text-secondary);
            font-size: 12px;
            text-transform: uppercase;
            padding: 8px 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }}
        td {{
            padding: 12px;
            font-size: 14px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
        }}
        .badge-ports {{
            background: rgba(59, 130, 246, 0.15);
            color: #93c5fd;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }}
        .score-circle {{
            width: 110px;
            height: 110px;
            border-radius: 50%;
            border: 6px solid #1f2937;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            margin: 15px auto;
            position: relative;
            background: radial-gradient(circle, rgba(17, 24, 39, 0.8) 0%, transparent 90%);
        }}
        .score-num {{
            font-size: 32px;
            font-weight: 800;
        }}
        .arrow-icon {{
            font-size: 11px;
            color: var(--text-secondary);
            transition: transform 0.2s;
        }}
        .meta-list {{
            list-style: none;
            padding: 0;
            margin: 0;
            font-size: 14px;
        }}
        .meta-list li {{
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
        }}
        .meta-list span {{
            color: var(--text-secondary);
        }}
    </style>
    <script>
        function toggleAccordion(id) {{
            var content = document.getElementById(id);
            var arrow = document.getElementById("arrow-" + id);
            if (content.style.display === "none") {{
                content.style.display = "block";
                arrow.style.transform = "rotate(180deg)";
            }} else {{
                content.style.display = "none";
                arrow.style.transform = "rotate(0deg)";
            }}
        }}
    </script>
</head>
<body>
    <div class="report-header">
        <div>
            <h1>Assessment Findings: {target}</h1>
            <div style="color: var(--text-secondary); font-size:14px; margin-top:4px;">Date: {scanned_at} (UTC)</div>
        </div>
        <a class="btn-back" href="/">← Console Dashboard</a>
    </div>
    <main class="grid">
        <!-- Findings list -->
        <div class="container">
            <div class="sec-title">Identified Vulnerabilities & Risks</div>
            {findings_html}
        </div>
        
        <!-- Sidebar Target properties -->
        <div style="display:flex; flex-direction:column; gap:24px;">
            <div class="container" style="text-align: center;">
                <div class="sec-title" style="text-align: left;">Assessed Risk Score</div>
                <div class="score-circle" style="border-color: var(--risk-{risk_class.split('-')[1]});">
                    <span class="score-num">{score}</span>
                    <span style="font-size:10px; text-transform:uppercase; color:var(--text-secondary);">Score</span>
                </div>
                <span class="badge {risk_class}" style="font-size: 14px; margin-top: 10px; padding: 6px 14px;">{risk} Risk</span>
            </div>
            
            <div class="container">
                <div class="sec-title">Target Dossier Info</div>
                <ul class="meta-list">
                    <li><span>IP Address:</span> <strong>{resolved}</strong></li>
                    <li><span>DNS PTR:</span> <strong>{ptr}</strong></li>
                    <li><span>Aliases:</span> <strong>{aliases}</strong></li>
                </ul>
            </div>
            
            <div class="container">
                <div class="sec-title">Service Mapping</div>
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Version</th>
                        </tr>
                    </thead>
                    <tbody>
                        {ports_rows}
                    </tbody>
                </table>
            </div>
        </div>
    </main>
</body>
</html>
"""

    def _generate_dashboard_html(self) -> str:
        export_folders = []
        for name in os.listdir("."):
            if os.path.isdir(name) and name.startswith("scan_export_"):
                bundle_file = os.path.join(name, "scan_bundle.json")
                if os.path.exists(bundle_file):
                    try:
                        with open(bundle_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            
                            pdf_name = ""
                            for subfile in os.listdir(name):
                                if subfile.endswith(".pdf"):
                                    pdf_name = subfile
                                    break
                                    
                            export_folders.append({
                                "folder": name,
                                "target": data.get("target", "unknown"),
                                "date": data.get("exported_at_utc", "unknown")[:16].replace("T", " "),
                                "score": data.get("score", 0),
                                "risk": data.get("risk_level", "Info"),
                                "findings": len(data.get("findings", [])),
                                "ports": len(data.get("open_ports", [])),
                                "pdf": pdf_name
                            })
                    except Exception:
                        pass

        export_folders.sort(key=lambda x: x["date"], reverse=True)

        rows_html = ""
        if not export_folders:
            rows_html = "<tr><td colspan='6' class='empty-row'>No scan reports found. Run a target scan below to initialize!</td></tr>"
        else:
            for item in export_folders:
                risk_class = f"risk-{item['risk'].lower()}"
                
                pdf_btn = ""
                if item["pdf"]:
                    pdf_btn = f'<a class="btn-action btn-pdf" href="/{item["folder"]}/{item["pdf"]}" target="_blank">PDF Report</a>'
                    
                rows_html += f"""
                <tr>
                    <td><strong>{item['target']}</strong></td>
                    <td>{item['date']}</td>
                    <td><span class="badge badge-ports">{item['ports']} Ports</span></td>
                    <td><span class="badge badge-findings">{item['findings']} Findings</span></td>
                    <td><span class="badge {risk_class}">{item['risk']} ({item['score']}/100)</span></td>
                    <td class="action-cell">
                        <a class="btn-action btn-report" href="/report?folder={item['folder']}">Interactive View</a>
                        {pdf_btn}
                        <a class="btn-action btn-json" href="/{item['folder']}/scan_bundle.json" target="_blank">JSON</a>
                    </td>
                </tr>
                """

        # Return a premium responsive glassmorphism dark-mode interface with Scan panels
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AVS Assessment Console (Secure)</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --container-bg: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-purple: #8b5cf6;
            --accent-blue: #3b82f6;
            --risk-critical: #ef4444;
            --risk-high: #f97316;
            --risk-medium: #eab308;
            --risk-low: #10b981;
            --risk-info: #3b82f6;
        }}
        body {{
            margin: 0;
            padding: 0;
            background-color: var(--bg-color);
            background-image: radial-gradient(circle at 10% 20%, rgba(139, 92, 246, 0.12) 0%, transparent 40%),
                              radial-gradient(circle at 90% 80%, rgba(59, 130, 246, 0.12) 0%, transparent 40%);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            color: var(--text-primary);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        header {{
            width: 100%;
            max-width: 1100px;
            margin-top: 40px;
            padding: 0 20px;
            box-sizing: border-box;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        h1 {{
            font-size: 28px;
            margin: 0;
            background: linear-gradient(135deg, #a78bfa 0%, #60a5fa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 800;
            letter-spacing: -0.5px;
        }}
        .subtitle {{
            color: var(--text-secondary);
            font-size: 14px;
            margin-top: 4px;
        }}
        main {{
            width: 100%;
            max-width: 1100px;
            margin-top: 24px;
            padding: 0 20px 60px 20px;
            box-sizing: border-box;
        }}
        .grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 24px;
        }}
        @media(min-width: 900px) {{
            .grid {{
                grid-template-columns: 340px 1fr;
            }}
        }}
        .container {{
            background: var(--container-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }}
        .form-title {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 18px;
            color: #f3f4f6;
        }}
        .form-group {{
            margin-bottom: 16px;
        }}
        label {{
            display: block;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 6px;
            letter-spacing: 0.5px;
        }}
        .input-text {{
            width: 100%;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 10px 12px;
            box-sizing: border-box;
            border-radius: 8px;
            color: white;
            font-size: 14px;
            transition: all 0.2s;
        }}
        .input-text:focus {{
            border-color: var(--accent-purple);
            outline: none;
            box-shadow: 0 0 8px rgba(139, 92, 246, 0.4);
        }}
        select.input-text {{
            cursor: pointer;
        }}
        .checkbox-group {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 12px;
            cursor: pointer;
        }}
        .checkbox-group input {{
            width: 16px;
            height: 16px;
            cursor: pointer;
        }}
        .btn-submit {{
            width: 100%;
            background: linear-gradient(135deg, #8b5cf6 0%, #3b82f6 100%);
            color: white;
            font-weight: 700;
            border: none;
            padding: 12px;
            border-radius: 8px;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.2s;
            box-shadow: 0 4px 12px rgba(139, 92, 246, 0.2);
        }}
        .btn-submit:hover {{
            box-shadow: 0 4px 20px rgba(139, 92, 246, 0.5);
            transform: translateY(-1px);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        th {{
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 13px;
            text-transform: uppercase;
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 18px 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            font-size: 14px;
            vertical-align: middle;
        }}
        tr:hover td {{
            background: rgba(255, 255, 255, 0.02);
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: capitalize;
        }}
        .badge-ports {{
            background: rgba(59, 130, 246, 0.15);
            color: #93c5fd;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }}
        .badge-findings {{
            background: rgba(139, 92, 246, 0.15);
            color: #c084fc;
            border: 1px solid rgba(139, 92, 246, 0.3);
        }}
        .risk-critical {{
            background: rgba(239, 68, 68, 0.15);
            color: #fca5a5;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}
        .risk-high {{
            background: rgba(249, 115, 22, 0.15);
            color: #fdba74;
            border: 1px solid rgba(249, 115, 22, 0.3);
        }}
        .risk-medium {{
            background: rgba(234, 179, 8, 0.15);
            color: #fde047;
            border: 1px solid rgba(234, 179, 8, 0.3);
        }}
        .risk-low {{
            background: rgba(16, 185, 129, 0.15);
            color: #6ee7b7;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        .risk-info {{
            background: rgba(59, 130, 246, 0.15);
            color: #93c5fd;
            border: 1px solid rgba(59, 130, 246, 0.3);
        }}
        .btn-action {{
            display: inline-block;
            text-decoration: none;
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 500;
            margin-left: 6px;
            transition: all 0.2s;
        }}
        .btn-report {{
            background: linear-gradient(135deg, #8b5cf6 0%, #3b82f6 100%);
            color: white;
        }}
        .btn-report:hover {{
            box-shadow: 0 0 10px rgba(139, 92, 246, 0.5);
        }}
        .btn-pdf {{
            background: var(--risk-low);
            color: white;
        }}
        .btn-pdf:hover {{
            background: #059669;
            box-shadow: 0 0 12px rgba(16, 185, 129, 0.4);
        }}
        .btn-json {{
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }}
        .btn-json:hover {{
            background: rgba(255, 255, 255, 0.15);
        }}
        .action-cell {{
            text-align: right;
            white-space: nowrap;
        }}
        .empty-row {{
            text-align: center;
            color: var(--text-secondary);
            padding: 40px 0;
            font-style: italic;
        }}
        .status-badge {{
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #34d399;
            padding: 6px 14px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .status-dot {{
            width: 8px;
            height: 8px;
            background: #10b981;
            border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 8px #10b981;
        }}
    </style>
</head>
<body>
    <header>
        <div>
            <h1>AVS Assessment Center</h1>
            <div class="subtitle">AutoVuln Scanner — Secure Console (HTTPS)</div>
        </div>
        <div class="status-badge">
            <span class="status-dot"></span> HTTPS Secure Active
        </div>
    </header>
    <main>
        <div class="grid">
            <!-- Left Column: Scan Trigger Form -->
            <div class="container">
                <div class="form-title">Trigger Vulnerability Scan</div>
                <form action="/scan" method="POST">
                    <div class="form-group">
                        <label for="target">Target IP / Hostname</label>
                        <input class="input-text" type="text" id="target" name="target" placeholder="e.g. scanme.nmap.org" required>
                    </div>
                    <div class="form-group">
                        <label for="ports">Custom Port Scope (Optional)</label>
                        <input class="input-text" type="text" id="ports" name="ports" placeholder="e.g. 22,80,443 or 1-1000">
                    </div>
                    <div class="form-group">
                        <label for="profile">Scan Policy Profile</label>
                        <select class="input-text" id="profile" name="profile">
                            <option value="quick">Quick TCP Discovery</option>
                            <option value="standard" selected>Standard Assessment</option>
                            <option value="deep">Deep Version & NSE Audit</option>
                            <option value="udp">UDP Service Sweep</option>
                            <option value="hyper">Hyper Composite Pipeline</option>
                        </select>
                    </div>
                    <div class="form-group" style="margin-top: 20px;">
                        <label class="checkbox-group">
                            <input type="checkbox" name="fusion" value="true" checked>
                            <span>Enable Intel Fusion (DNS/HTTP/TLS)</span>
                        </label>
                        <label class="checkbox-group">
                            <input type="checkbox" name="cve" value="true" checked>
                            <span>Enable NVD CVE Lookup</span>
                        </label>
                    </div>
                    <button type="submit" class="btn-submit">Start Assessment</button>
                </form>
            </div>
            
            <!-- Right Column: Scan History Grid -->
            <div class="container" style="overflow-x: auto;">
                <div class="form-title">Completed Assessments</div>
                <table>
                    <thead>
                        <tr>
                            <th>Target</th>
                            <th>Scan Date (UTC)</th>
                            <th>Ports</th>
                            <th>Findings</th>
                            <th>Risk Level</th>
                            <th style="text-align: right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
            </div>
        </div>
    </main>
</body>
</html>
"""


def run_server() -> None:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("0.0.0.0", PORT), SecureReportServerHandler) as httpd:
        if not DISABLE_HTTPS:
            # 1. Generate SSL Certificate and key if missing
            generate_self_signed_cert("cert.pem", "key.pem")
            # 2. Wrap the socket with TLS SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            proto = "HTTPS"
            url_scheme = "https"
        else:
            proto = "HTTP"
            url_scheme = "http"
            
        print("=" * 60)
        print(f" AVS Assessment Console {proto} Web Server Active!")
        print(f" Web Interface URL: {url_scheme}://localhost:{PORT}")
        print("=" * 60)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")


if __name__ == "__main__":
    run_server()
