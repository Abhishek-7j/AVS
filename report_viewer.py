"""
Lightweight Web Report Server for AVS.
Scans the current workspace directory for generated scan bundle folders
and serves a polished dashboard listing all available reports.
"""
from __future__ import annotations

import os
import json
import http.server
import socketserver
from urllib.parse import unquote

PORT = 8080


class ReportServerHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
        path = unquote(self.path).strip("/")

        # Root route: serve the polished dashboard of reports
        if not path or path == "index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(self._generate_dashboard_html().encode("utf-8"))
            return

        # Serve static bundle files or PDFs directly from local directories
        if os.path.exists(path) and (path.endswith(".json") or path.endswith(".pdf") or path.endswith(".txt")):
            super().do_GET()
            return

        self.send_error(404, "File Not Found")

    def _generate_dashboard_html(self) -> str:
        # Find all scan_export_* folders in the directory
        export_folders = []
        for name in os.listdir("."):
            if os.path.isdir(name) and name.startswith("scan_export_"):
                bundle_file = os.path.join(name, "scan_bundle.json")
                if os.path.exists(bundle_file):
                    try:
                        with open(bundle_file, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            export_folders.append({
                                "folder": name,
                                "target": data.get("target", "unknown"),
                                "date": data.get("exported_at_utc", "unknown")[:16].replace("T", " "),
                                "score": data.get("score", 0),
                                "risk": data.get("risk_level", "Info"),
                                "findings": len(data.get("findings", [])),
                                "ports": len(data.get("open_ports", []))
                            })
                    except Exception:
                        pass

        # Sort exports by date descending
        export_folders.sort(key=lambda x: x["date"], reverse=True)

        rows_html = ""
        if not export_folders:
            rows_html = "<tr><td colspan='6' class='empty-row'>No scan reports found. Run a scan with cli.py or main.py first!</td></tr>"
        else:
            for item in export_folders:
                risk_class = f"risk-{item['risk'].lower()}"
                rows_html += f"""
                <tr>
                    <td><strong>{item['target']}</strong></td>
                    <td>{item['date']}</td>
                    <td><span class="badge badge-ports">{item['ports']} Ports</span></td>
                    <td><span class="badge badge-findings">{item['findings']} Findings</span></td>
                    <td><span class="badge {risk_class}">{item['risk']} ({item['score']}/100)</span></td>
                    <td class="action-cell">
                        <a class="btn-action btn-json" href="/{item['folder']}/scan_bundle.json" target="_blank">View JSON</a>
                        <a class="btn-action btn-txt" href="/{item['folder']}/scan_results.txt" target="_blank">View Text</a>
                    </td>
                </tr>
                """

        # Return a premium responsive glassmorphism dark-mode dashboard
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AVS — Deployment Report Center</title>
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
            margin-top: 30px;
            padding: 0 20px 60px 20px;
            box-sizing: border-box;
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
        <div class="container">
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
    </main>
</body>
</html>
"""


def run_server() -> None:
    # Set workspace root as the serving directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Allow address reuse to prevent TCP socket bind errors on quick restarts
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), ReportServerHandler) as httpd:
        print("=" * 60)
        print(f" AVS Web Deployment Active!")
        print(f" Report Dashboard URL: http://localhost:{PORT}")
        print("=" * 60)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")


if __name__ == "__main__":
    run_server()
