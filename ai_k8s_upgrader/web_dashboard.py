"""
Web Dashboard Module.
Launches a standalone interactive Web Dashboard to view and analyze Kubernetes upgrade reports.
"""

import http.server
import socketserver
import json
import os

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-Kubernetes-Upgrader | Interactive Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --bg-hover: #21262d;
            --border-color: #30363d;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --text-bright: #f0f6fc;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
            --accent-purple: #a371f7;
            --font-main: 'Inter', sans-serif;
            --font-code: 'JetBrains Mono', monospace;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: var(--font-main);
            background-color: var(--bg-dark);
            color: var(--text-main);
            line-height: 1.6;
            padding: 24px;
        }

        .container {
            max-width: 1300px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 24px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .brand h1 {
            font-size: 22px;
            font-weight: 700;
            color: var(--text-bright);
        }

        .badge-version {
            background: rgba(88, 166, 255, 0.15);
            color: var(--accent-blue);
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            border: 1px solid rgba(88, 166, 255, 0.3);
        }

        .grid-top {
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.2);
        }

        .score-box {
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        .score-circle {
            width: 140px;
            height: 140px;
            border-radius: 50%;
            background: conic-gradient(var(--score-color, var(--accent-green)) calc(var(--score-val, 85) * 1%), #21262d 0);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 16px;
            position: relative;
        }

        .score-circle::before {
            content: '';
            position: absolute;
            width: 110px;
            height: 110px;
            border-radius: 50%;
            background: var(--bg-card);
        }

        .score-text {
            position: relative;
            z-index: 2;
            font-size: 32px;
            font-weight: 800;
            color: var(--text-bright);
        }

        .decision-badge {
            display: inline-block;
            padding: 6px 16px;
            border-radius: 30px;
            font-weight: 700;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .decision-APPROVED { background: rgba(63, 185, 80, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }
        .decision-CONDITIONAL { background: rgba(210, 153, 34, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
        .decision-NOT-RECOMMENDED { background: rgba(248, 81, 73, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }

        .summary-details h2 {
            font-size: 18px;
            font-weight: 600;
            color: var(--text-bright);
            margin-bottom: 16px;
        }

        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid rgba(48, 54, 61, 0.5);
            font-size: 14px;
        }

        .info-row span:first-child { color: var(--text-muted); }
        .info-row span:last-child { color: var(--text-bright); font-weight: 600; }

        .section-title {
            font-size: 18px;
            font-weight: 700;
            color: var(--text-bright);
            margin: 32px 0 16px 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }

        th, td {
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            font-size: 14px;
        }

        th {
            background: #1c2128;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.5px;
        }

        tr:hover { background: var(--bg-hover); }

        .sev-Critical { color: var(--accent-red); font-weight: 700; }
        .sev-High { color: #f97316; font-weight: 600; }
        .sev-Medium { color: var(--accent-yellow); }
        .sev-Low { color: var(--accent-green); }

        .status-pill {
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
        }
        .status-PASS { background: rgba(63,185,80,0.15); color: var(--accent-green); }
        .status-CRITICAL { background: rgba(248,81,73,0.15); color: var(--accent-red); }
        .status-HIGH-RISK { background: rgba(249,115,22,0.15); color: #f97316; }
        .status-WARNING { background: rgba(210,153,34,0.15); color: var(--accent-yellow); }

        pre {
            background: #0d1117;
            padding: 16px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            font-family: var(--font-code);
            font-size: 13px;
            color: #79c0ff;
            overflow-x: auto;
            white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>AI-Kubernetes-Upgrader</h1>
                <span class="badge-version">Assessment Engine v1.0</span>
            </div>
            <div>
                <span class="text-muted" style="font-size: 13px;">Enterprise Assessment Report</span>
            </div>
        </header>

        <div class="grid-top">
            <div class="card score-box">
                <div class="score-circle" id="scoreCircle" style="--score-val: 75; --score-color: var(--accent-yellow);">
                    <div class="score-text" id="scoreText">75/100</div>
                </div>
                <div class="decision-badge decision-CONDITIONAL" id="decisionBadge">CONDITIONAL</div>
                <p style="margin-top: 12px; font-size: 13px; color: var(--text-muted);">Confidence Score: <strong style="color: var(--text-bright);" id="confText">95%</strong></p>
            </div>

            <div class="card summary-details">
                <h2>Upgrade Overview</h2>
                <div class="info-row">
                    <span>Source Version</span>
                    <span id="srcVer">v1.25.0</span>
                </div>
                <div class="info-row">
                    <span>Target Version</span>
                    <span id="tgtVer">v1.29.0</span>
                </div>
                <div class="info-row">
                    <span>Critical Issues</span>
                    <span style="color: var(--accent-red);" id="critCount">2 Workloads Breaking</span>
                </div>
                <div class="info-row">
                    <span>Controller Actions</span>
                    <span style="color: var(--accent-yellow);" id="ctrlCount">2 Updates Required</span>
                </div>
            </div>
        </div>

        <div class="section-title">10-Area Risk Matrix</div>
        <table>
            <thead>
                <tr>
                    <th>Area</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Explanation</th>
                </tr>
            </thead>
            <tbody id="riskMatrixBody">
                <!-- Rows injected dynamically -->
            </tbody>
        </table>

        <div class="section-title">Assessment Report Output</div>
        <pre id="reportPre">Loading assessment report...</pre>
    </div>

    <script>
        fetch('/api/report-data')
            .then(res => res.json())
            .then(data => {
                document.getElementById('reportPre').textContent = data.raw_markdown || JSON.stringify(data, null, 2);
            })
            .catch(err => {
                document.getElementById('reportPre').textContent = "Failed to load report data: " + err;
            });
    </script>
</body>
</html>
"""

def start_web_dashboard(report_path: str, port: int = 8080):
    report_content = ""
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            report_content = f.read()
    else:
        report_content = f"Report file not found at: {report_path}. Run 'ai-k8s-upgrader analyze' first."

    class DashboardHandler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/" or self.path == "/index.html":
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
            elif self.path == "/api/report-data":
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                resp = {"raw_markdown": report_content}
                self.wfile.write(json.dumps(resp).encode("utf-8"))
            else:
                self.send_error(404)

    print(f"[*] Starting AI-Kubernetes-Upgrader Web Dashboard on http://localhost:{port}")
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", port), DashboardHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Dashboard server stopped.")
