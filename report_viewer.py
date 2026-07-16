"""
Lightweight Web Report Server & Interactive Assessment Console for AVS.
Allows initiating scans from the browser, tracks real-time progress,
and serves a polished dashboard to view PDF, JSON, and TXT results.
"""
from __future__ import annotations

import os
import json
import http.server
import socketserver
import threading
import shutil
from datetime import datetime, timezone
from urllib.parse import unquote, parse_qs

from cli import run_assessment
from exporter import export_full_report
from report_generator import generate_report
from plugins import Finding

PORT = 8080

# Dict to track background scan progress: { target: status_message }
ACTIVE_SCANS: dict[str, str] = {}


def run_background_scan(target: str, profile: str, fusion: bool, cve: bool) -> None:
    try:
        ACTIVE_SCANS[target] = "Initializing targets and sweeps..."
        
        # 1. Run the scanning engine
        ACTIVE_SCANS[target] = "Performing network port scan..."
        bundle = run_assessment(target, profile, fusion, cve)
        
        # 2. Correlate vulnerabilities
        ACTIVE_SCANS[target] = "Evaluating active plugins & correlating CVE hints..."
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
        
        # 3. Export PDF & full bundle
        ACTIVE_SCANS[target] = "Compiling PDF report and exporting folder..."
        pdf_file = generate_report(
            target,
            results_tuples,
            findings_objs,
            bundle["score"],
            bundle["risk_level"],
            profile=profile,
            intel=intel_d
        )
        
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
            
        ACTIVE_SCANS[target] = "Completed"
    except Exception as e:
        import traceback
        traceback.print_exc()
        ACTIVE_SCANS[target] = f"Failed: {str(e)}"


class ReportServerHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path == "/scan":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            params = parse_qs(post_data)
            
            target = params.get('target', [''])[0].strip()
            profile = params.get('profile', ['standard'])[0]
            fusion = params.get('fusion', ['false'])[0] == 'true'
            cve = params.get('cve', ['false'])[0] == 'true'
            
            if not target:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Target hostname or IP is required.")
                return
            
            # Start background scanning thread
            ACTIVE_SCANS[target] = "Enqueuing assessment..."
            threading.Thread(target=run_background_scan, args=(target, profile, fusion, cve), daemon=True).start()
            
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

        # 3. Dynamic Static File Server (PDF, JSON, TXT)
        # Allow reading files from inside subdirectories
        if os.path.exists(path) and os.path.isfile(path):
            super().do_GET()
            return

        self.send_error(404, "File Not Found")

    def _generate_progress_html(self, target: str) -> str:
        status = ACTIVE_SCANS.get(target, "Awaiting status...")
        
        # Redirect once completed
        redirect_meta = ""
        loader_class = "loader"
        error_msg = ""
        
        if status == "Completed":
            redirect_meta = '<meta http-equiv="refresh" content="0;url=/">'
        elif status.startswith("Failed"):
            loader_class = "loader-failed"
            error_msg = f"<div class='error-box'>{status}</div>"
        else:
            redirect_meta = '<meta http-equiv="refresh" content="3">'
            
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    {redirect_meta}
    <title>AVS — Scanning Target...</title>
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
            padding: 40px;
            border-radius: 16px;
            text-align: center;
            max-width: 500px;
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
            margin: 20px 0;
        }}
        .loader {{
            width: 50px;
            height: 50px;
            border: 4px solid rgba(139, 92, 246, 0.2);
            border-top: 4px solid #8b5cf6;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 24px auto;
        }}
        .loader-failed {{
            width: 50px;
            height: 50px;
            border: 4px solid rgba(239, 68, 68, 0.2);
            border-top: 4px solid #ef4444;
            border-radius: 50%;
            margin: 24px auto;
            position: relative;
        }}
        .loader-failed::after {{
            content: "❌";
            font-size: 24px;
            position: absolute;
            top: 6px;
            left: 10px;
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
            word-break: break-all;
        }}
        .btn {{
            display: inline-block;
            background: rgba(255, 255, 255, 0.1);
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 14px;
            margin-top: 20px;
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
        <h2>AVS Scan Pipeline</h2>
        <div class="status-text">Target: <strong>{target}</strong></div>
        <div class="{loader_class}"></div>
        <div class="status-text" style="color:#e6edf3;">{status}</div>
        {error_msg}
        {f'<a class="btn" href="/">Return to Dashboard</a>' if "Failed" in status or "Completed" in status else ''}
    </div>
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
                            
                            # Find if PDF is inside directory
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
                
                # Check if PDF action should be shown
                pdf_btn = ""
                if item["pdf"]:
                    pdf_btn = f'<a class="btn-action btn-pdf" href="/{item["folder"]}/{item["pdf"]}" target="_blank">View PDF</a>'
                    
                rows_html += f"""
                <tr>
                    <td><strong>{item['target']}</strong></td>
                    <td>{item['date']}</td>
                    <td><span class="badge badge-ports">{item['ports']} Ports</span></td>
                    <td><span class="badge badge-findings">{item['findings']} Findings</span></td>
                    <td><span class="badge {risk_class}">{item['risk']} ({item['score']}/100)</span></td>
                    <td class="action-cell">
                        {pdf_btn}
                        <a class="btn-action btn-json" href="/{item['folder']}/scan_bundle.json" target="_blank">JSON</a>
                        <a class="btn-action btn-txt" href="/{item['folder']}/scan_results.txt" target="_blank">Text</a>
                    </td>
                </tr>
                """

        # Return a premium responsive glassmorphism dark-mode interface with Scan panels
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AVS Assessment Center</title>
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
            background-image: radial-gradient(circle at 10% 20%, rgba(139, 92, 246, 0.15) 0%, transparent 40%),
                              radial-gradient(circle at 90% 80%, rgba(59, 130, 246, 0.15) 0%, transparent 40%);
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
                grid-template-columns: 320px 1fr;
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
        .btn-pdf {{
            background: var(--risk-low);
            color: white;
        }}
        .btn-pdf:hover {{
            background: #059669;
            box-shadow: 0 0 12px rgba(16, 185, 129, 0.4);
        }}
        .btn-json {{
            background: var(--accent-purple);
            color: white;
        }}
        .btn-json:hover {{
            background: #7c3aed;
            box-shadow: 0 0 12px rgba(139, 92, 246, 0.4);
        }}
        .btn-txt {{
            background: rgba(255, 255, 255, 0.08);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }}
        .btn-txt:hover {{
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
            <div class="subtitle">AutoVuln Scanner — Deployment Verification Console</div>
        </div>
        <div class="status-badge">
            <span class="status-dot"></span> Deployment Active
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
    
    with socketserver.TCPServer(("", PORT), ReportServerHandler) as httpd:
        print("=" * 60)
        print(f" AVS Assessment Console Web Server Active!")
        print(f" Web Interface URL: http://localhost:{PORT}")
        print("=" * 60)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")


if __name__ == "__main__":
    run_server()
