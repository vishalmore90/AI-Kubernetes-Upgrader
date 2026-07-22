"""
web_dashboard.py
================
Interactive Flask web dashboard for the Kubernetes Upgrade Assessor.

Features:
- Upload a cluster JSON snapshot or run live assessment
- Visual Risk Matrix with color-coded status indicators
- Readiness Score gauge
- Expandable sections for each assessment area
- Export report button
- Real-time assessment progress
"""

import json
import os
import tempfile
from datetime import datetime

from flask import Flask, render_template_string, request, jsonify, send_file, redirect, url_for

from ai_k8s_upgrader.assessment_engine import AssessmentEngine
from ai_k8s_upgrader.cluster_collector import collect_cluster_state
from ai_k8s_upgrader.scoring_matrix import ScoringEngine
from ai_k8s_upgrader.reporter import generate_markdown_report, generate_json_report
from ai_k8s_upgrader.sample_generator import generate_sample_cluster

app = Flask(__name__)

# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-Kubernetes-Upgrader | Upgrade Assessment Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0d14;
            --bg-secondary: #111827;
            --bg-card: #1a2235;
            --bg-card-hover: #1e2a3f;
            --accent-blue: #3b82f6;
            --accent-cyan: #06b6d4;
            --accent-purple: #8b5cf6;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-orange: #f97316;
            --accent-red: #ef4444;
            --accent-critical: #dc2626;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --text-muted: #475569;
            --border: #1e2d40;
            --border-bright: #2d4060;
            --gradient-1: linear-gradient(135deg, #1a2235 0%, #0f1929 100%);
            --shadow: 0 4px 24px rgba(0,0,0,0.4);
            --shadow-glow: 0 0 30px rgba(59,130,246,0.15);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }

        /* Header */
        .header {
            background: linear-gradient(90deg, #0a0d14 0%, #111827 50%, #0a0d14 100%);
            border-bottom: 1px solid var(--border-bright);
            padding: 0 2rem;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: var(--shadow);
        }

        .header-inner {
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            height: 64px;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .logo-icon {
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }

        .logo-text {
            font-size: 1.1rem;
            font-weight: 700;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .logo-subtitle {
            font-size: 0.75rem;
            color: var(--text-secondary);
        }

        .header-badge {
            background: rgba(59,130,246,0.1);
            border: 1px solid rgba(59,130,246,0.3);
            color: var(--accent-blue);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 500;
        }

        /* Main content */
        .main {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }

        /* Config Panel */
        .config-panel {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-glow);
            position: relative;
            overflow: hidden;
        }

        .config-panel::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-cyan), var(--accent-purple));
        }

        .config-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .config-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr auto;
            gap: 1rem;
            align-items: end;
        }

        .form-group label {
            display: block;
            font-size: 0.8rem;
            font-weight: 500;
            color: var(--text-secondary);
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .form-group input, .form-group select {
            width: 100%;
            background: var(--bg-secondary);
            border: 1px solid var(--border-bright);
            border-radius: 8px;
            padding: 10px 14px;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            transition: border-color 0.2s;
        }

        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px rgba(59,130,246,0.1);
        }

        .btn {
            padding: 10px 24px;
            border-radius: 8px;
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s;
            border: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-cyan));
            color: white;
        }

        .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 4px 20px rgba(59,130,246,0.4); }

        .btn-secondary {
            background: transparent;
            border: 1px solid var(--border-bright);
            color: var(--text-secondary);
        }

        .btn-secondary:hover { border-color: var(--accent-blue); color: var(--accent-blue); }

        .btn-success {
            background: linear-gradient(135deg, var(--accent-green), #059669);
            color: white;
        }

        /* Upload area */
        .upload-area {
            border: 2px dashed var(--border-bright);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            transition: all 0.2s;
            cursor: pointer;
            margin-top: 1rem;
        }

        .upload-area:hover, .upload-area.drag-over {
            border-color: var(--accent-blue);
            background: rgba(59,130,246,0.05);
        }

        .upload-area input[type=file] {
            display: none;
        }

        /* Loading spinner */
        .spinner {
            display: none;
            align-items: center;
            gap: 12px;
            color: var(--accent-cyan);
            font-size: 0.9rem;
        }

        .spinner.active { display: flex; }

        .spin {
            width: 20px;
            height: 20px;
            border: 2px solid rgba(6,182,212,0.2);
            border-top-color: var(--accent-cyan);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin { to { transform: rotate(360deg); } }

        /* Results grid */
        .results-grid {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 2rem;
            margin-top: 2rem;
        }

        /* Score panel */
        .score-panel {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .score-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
        }

        .score-number {
            font-size: 4rem;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            line-height: 1;
            margin: 0.5rem 0;
        }

        .score-label {
            font-size: 0.85rem;
            color: var(--text-secondary);
            font-weight: 500;
        }

        .score-bar-container {
            height: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            margin: 1rem 0;
            overflow: hidden;
        }

        .score-bar {
            height: 100%;
            border-radius: 4px;
            transition: width 1s ease;
        }

        .decision-badge {
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            margin: 0.5rem 0;
        }

        .decision-approved { background: rgba(16,185,129,0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3); }
        .decision-conditional { background: rgba(245,158,11,0.15); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); }
        .decision-not-recommended { background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }

        /* Risk Matrix */
        .matrix-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
        }

        .matrix-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
            font-size: 0.95rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .matrix-row {
            display: grid;
            grid-template-columns: 140px 130px 100px 1fr;
            align-items: center;
            padding: 0.75rem 1.5rem;
            border-bottom: 1px solid rgba(30,45,64,0.5);
            transition: background 0.15s;
        }

        .matrix-row:hover { background: rgba(30,42,62,0.6); }
        .matrix-row:last-child { border-bottom: none; }

        .area-name { font-weight: 600; font-size: 0.9rem; }

        .status-badge {
            padding: 3px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.05em;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }

        .status-pass { background: rgba(16,185,129,0.15); color: #10b981; }
        .status-good { background: rgba(16,185,129,0.1); color: #10b981; }
        .status-warning { background: rgba(245,158,11,0.15); color: #f59e0b; }
        .status-high { background: rgba(239,68,68,0.15); color: #ef4444; }
        .status-critical { background: rgba(220,38,38,0.2); color: #dc2626; border: 1px solid rgba(220,38,38,0.3); }

        .severity-badge {
            font-size: 0.7rem;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: 500;
        }

        .sev-critical { background: rgba(220,38,38,0.15); color: #dc2626; }
        .sev-high { background: rgba(239,68,68,0.15); color: #ef4444; }
        .sev-medium { background: rgba(245,158,11,0.15); color: #f59e0b; }
        .sev-low { background: rgba(16,185,129,0.1); color: #10b981; }

        .explanation { font-size: 0.8rem; color: var(--text-secondary); }

        /* Content panels */
        .content-area {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .panel {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }

        .panel-header {
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: background 0.15s;
        }

        .panel-header:hover { background: var(--bg-card-hover); }

        .panel-title {
            font-weight: 600;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .panel-body {
            padding: 1.5rem;
            display: none;
        }

        .panel-body.active { display: block; }

        .chevron { transition: transform 0.2s; }
        .panel-header.open .chevron { transform: rotate(180deg); }

        /* Issues list */
        .issue-item {
            padding: 0.75rem 1rem;
            border-radius: 8px;
            margin-bottom: 0.5rem;
            font-size: 0.85rem;
            display: flex;
            align-items: flex-start;
            gap: 8px;
        }

        .issue-critical { background: rgba(220,38,38,0.1); border-left: 3px solid #dc2626; }
        .issue-high { background: rgba(239,68,68,0.08); border-left: 3px solid #ef4444; }
        .issue-warning { background: rgba(245,158,11,0.08); border-left: 3px solid #f59e0b; }
        .issue-info { background: rgba(59,130,246,0.05); border-left: 3px solid #3b82f6; }

        /* Failure scenarios */
        .scenario-item {
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 0.5rem;
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--border);
        }

        .scenario-question {
            font-weight: 600;
            font-size: 0.9rem;
            margin-bottom: 0.5rem;
        }

        .scenario-answer-yes { color: #ef4444; }
        .scenario-answer-no { color: #10b981; }
        .scenario-answer-possible { color: #f59e0b; }

        /* Table */
        table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        th {
            text-align: left;
            padding: 8px 12px;
            background: rgba(255,255,255,0.03);
            color: var(--text-secondary);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border);
        }
        td { padding: 8px 12px; border-bottom: 1px solid rgba(30,45,64,0.5); }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255,255,255,0.02); }

        code {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(255,255,255,0.05);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.8em;
        }

        .tag {
            display: inline-flex;
            align-items: center;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 500;
        }

        /* Actions list */
        .action-item {
            padding: 0.75rem 1rem;
            background: rgba(59,130,246,0.05);
            border: 1px solid rgba(59,130,246,0.1);
            border-radius: 8px;
            margin-bottom: 0.5rem;
            font-size: 0.85rem;
            display: flex;
            gap: 10px;
        }

        .action-number {
            color: var(--accent-blue);
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            min-width: 24px;
        }

        .empty-state {
            text-align: center;
            color: var(--text-muted);
            padding: 2rem;
            font-size: 0.85rem;
        }

        /* Alerts */
        .alert {
            padding: 0.75rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            margin-bottom: 0.5rem;
        }

        .alert-error { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); color: #f87171; }
        .alert-success { background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.3); color: #34d399; }

        /* Tabs */
        .tabs { display: flex; gap: 4px; margin-bottom: 1rem; }

        .tab {
            padding: 6px 16px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 500;
            cursor: pointer;
            border: 1px solid var(--border);
            color: var(--text-secondary);
            transition: all 0.15s;
        }

        .tab.active {
            background: rgba(59,130,246,0.15);
            border-color: rgba(59,130,246,0.3);
            color: var(--accent-blue);
        }

        .export-bar {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem 1.5rem;
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            margin-top: 1rem;
        }

        .export-bar span { flex: 1; font-size: 0.85rem; color: var(--text-secondary); }

        @media (max-width: 900px) {
            .results-grid { grid-template-columns: 1fr; }
            .config-grid { grid-template-columns: 1fr 1fr; }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <div class="header-inner">
            <div class="logo">
                <div class="logo-icon">⚡</div>
                <div>
                    <div class="logo-text">AI-Kubernetes-Upgrader</div>
                    <div class="logo-subtitle">Upgrade Feasibility & Risk Assessment Engine</div>
                </div>
            </div>
            <span class="header-badge">v1.0.0 · Enterprise Edition</span>
        </div>
    </header>

    <main class="main">
        <!-- Config Panel -->
        <div class="config-panel">
            <div class="config-title">⚙️ Assessment Configuration</div>
            <form id="assessmentForm" enctype="multipart/form-data">
                <div class="config-grid">
                    <div class="form-group">
                        <label>Source Version</label>
                        <input type="text" id="sourceVersion" name="source_version" value="1.27" placeholder="e.g. 1.27" required>
                    </div>
                    <div class="form-group">
                        <label>Target Version</label>
                        <input type="text" id="targetVersion" name="target_version" value="1.30" placeholder="e.g. 1.30" required>
                    </div>
                    <div class="form-group">
                        <label>Mode</label>
                        <select id="modeSelect" name="mode" onchange="toggleUploadArea()">
                            <option value="sample">📦 Use Sample Cluster</option>
                            <option value="snapshot">📁 Upload JSON Snapshot</option>
                            <option value="live">🔌 Live Cluster (kubectl)</option>
                        </select>
                    </div>
                    <div>
                        <button type="submit" class="btn btn-primary" id="runBtn">
                            <span>▶ Run Assessment</span>
                        </button>
                    </div>
                </div>

                <!-- Upload area (hidden by default) -->
                <div id="uploadArea" class="upload-area" style="display:none;" onclick="document.getElementById('snapshotFile').click()">
                    <input type="file" id="snapshotFile" name="snapshot_file" accept=".json">
                    <div>📂 Click to upload cluster snapshot JSON</div>
                    <div style="font-size:0.75rem; color: var(--text-muted); margin-top:4px;">or drag and drop</div>
                </div>
            </form>
            <div class="spinner" id="spinner" style="margin-top:1rem;">
                <div class="spin"></div>
                <span>Running assessment... analyzing all 17 steps</span>
            </div>
            <div id="formError" style="margin-top:0.5rem;"></div>
        </div>

        <!-- Results -->
        <div id="resultsSection" style="display:none;">
            <div class="results-grid">
                <!-- Left: Scores -->
                <div class="score-panel">
                    <!-- Decision -->
                    <div class="score-card">
                        <div class="score-label">Upgrade Decision</div>
                        <div id="decisionBadge" class="decision-badge" style="margin:0.75rem auto; display:inline-block;"></div>
                        <div style="font-size:0.75rem; color:var(--text-muted);" id="upgradeRange"></div>
                    </div>

                    <!-- Readiness Score -->
                    <div class="score-card">
                        <div class="score-label">Readiness Score</div>
                        <div class="score-number" id="readinessScore"></div>
                        <div class="score-bar-container">
                            <div class="score-bar" id="readinessBar"></div>
                        </div>
                        <div style="font-size:0.8rem;" id="readinessLabel"></div>
                    </div>

                    <!-- Confidence Score -->
                    <div class="score-card">
                        <div class="score-label">Confidence Score</div>
                        <div class="score-number" id="confidenceScore" style="font-size:2.5rem;"></div>
                        <div class="score-bar-container">
                            <div class="score-bar" id="confidenceBar"></div>
                        </div>
                        <div style="font-size:0.75rem; color:var(--text-muted);">Based on data completeness</div>
                    </div>

                    <!-- Stats -->
                    <div class="score-card" style="text-align:left;">
                        <div class="score-label" style="margin-bottom:0.75rem;">Quick Stats</div>
                        <div id="quickStats" style="font-size:0.85rem;"></div>
                    </div>
                </div>

                <!-- Right: Content -->
                <div class="content-area" id="contentArea">
                    <!-- Risk Matrix -->
                    <div class="matrix-card">
                        <div class="matrix-header">📊 Risk Matrix</div>
                        <div id="riskMatrixContent"></div>
                    </div>

                    <!-- Critical Issues -->
                    <div class="panel" id="criticalPanel">
                        <div class="panel-header" onclick="togglePanel(this)">
                            <div class="panel-title">🚨 Critical Issues & High Risks</div>
                            <span class="chevron">▾</span>
                        </div>
                        <div class="panel-body" id="criticalBody"></div>
                    </div>

                    <!-- API Analysis -->
                    <div class="panel">
                        <div class="panel-header" onclick="togglePanel(this)">
                            <div class="panel-title">🔌 API Removal & Deprecation Analysis</div>
                            <span class="chevron">▾</span>
                        </div>
                        <div class="panel-body" id="apiBody"></div>
                    </div>

                    <!-- Controllers -->
                    <div class="panel">
                        <div class="panel-header" onclick="togglePanel(this)">
                            <div class="panel-title">🎛️ Controller Compatibility</div>
                            <span class="chevron">▾</span>
                        </div>
                        <div class="panel-body" id="controllerBody"></div>
                    </div>

                    <!-- Failure Scenarios -->
                    <div class="panel">
                        <div class="panel-header" onclick="togglePanel(this)">
                            <div class="panel-title">💥 Failure Scenario Analysis</div>
                            <span class="chevron">▾</span>
                        </div>
                        <div class="panel-body" id="scenarioBody"></div>
                    </div>

                    <!-- Required Actions -->
                    <div class="panel">
                        <div class="panel-header" onclick="togglePanel(this)">
                            <div class="panel-title">📋 Required Actions Before Upgrade</div>
                            <span class="chevron">▾</span>
                        </div>
                        <div class="panel-body" id="actionsBody"></div>
                    </div>

                    <!-- Upgrade Order -->
                    <div class="panel">
                        <div class="panel-header" onclick="togglePanel(this)">
                            <div class="panel-title">📈 Recommended Upgrade Order</div>
                            <span class="chevron">▾</span>
                        </div>
                        <div class="panel-body" id="orderBody"></div>
                    </div>
                </div>
            </div>

            <!-- Export bar -->
            <div class="export-bar">
                <span>📄 Assessment complete. Export the full report:</span>
                <button class="btn btn-secondary" onclick="exportReport('markdown')">📝 Export Markdown</button>
                <button class="btn btn-secondary" onclick="exportReport('json')">📦 Export JSON</button>
            </div>
        </div>
    </main>

    <script>
        let lastReport = null;

        function toggleUploadArea() {
            const mode = document.getElementById('modeSelect').value;
            const ua = document.getElementById('uploadArea');
            ua.style.display = mode === 'snapshot' ? 'block' : 'none';
        }

        function togglePanel(header) {
            header.classList.toggle('open');
            const body = header.nextElementSibling;
            body.classList.toggle('active');
        }

        function getScoreColor(score) {
            if (score >= 90) return '#10b981';
            if (score >= 75) return '#f59e0b';
            if (score >= 50) return '#f97316';
            return '#ef4444';
        }

        function getStatusClass(status) {
            const map = {
                'PASS': 'status-pass', 'GOOD': 'status-good',
                'WARNING': 'status-warning', 'HIGH RISK': 'status-high', 'CRITICAL': 'status-critical'
            };
            return map[status] || 'status-warning';
        }

        function getStatusEmoji(status) {
            const map = { 'PASS': '✅', 'GOOD': '🟢', 'WARNING': '⚠️', 'HIGH RISK': '🔴', 'CRITICAL': '🚨' };
            return map[status] || '❓';
        }

        function getSeverityClass(severity) {
            const map = { 'Critical': 'sev-critical', 'High': 'sev-high', 'Medium': 'sev-medium', 'Low': 'sev-low' };
            return map[severity] || 'sev-low';
        }

        function getDecisionClass(decision) {
            if (decision === 'APPROVED') return 'decision-approved';
            if (decision === 'CONDITIONAL') return 'decision-conditional';
            return 'decision-not-recommended';
        }

        async function runAssessment(e) {
            e.preventDefault();
            const form = document.getElementById('assessmentForm');
            const spinner = document.getElementById('spinner');
            const resultsSection = document.getElementById('resultsSection');
            const formError = document.getElementById('formError');

            spinner.classList.add('active');
            resultsSection.style.display = 'none';
            formError.innerHTML = '';

            const formData = new FormData(form);

            try {
                const resp = await fetch('/api/assess', { method: 'POST', body: formData });
                const data = await resp.json();

                if (!resp.ok || data.error) {
                    formError.innerHTML = `<div class="alert alert-error">❌ ${data.error || 'Assessment failed.'}</div>`;
                    return;
                }

                lastReport = data;
                renderResults(data);
                resultsSection.style.display = 'block';
                resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

            } catch (err) {
                formError.innerHTML = `<div class="alert alert-error">❌ ${err.message}</div>`;
            } finally {
                spinner.classList.remove('active');
            }
        }

        function renderResults(data) {
            const scoring = data.scoring;
            const assessment = data.assessment;

            // Scores
            const readiness = scoring.readiness_score;
            document.getElementById('readinessScore').textContent = `${readiness}/100`;
            document.getElementById('readinessScore').style.color = getScoreColor(readiness);
            document.getElementById('readinessBar').style.width = `${readiness}%`;
            document.getElementById('readinessBar').style.background = getScoreColor(readiness);
            document.getElementById('readinessLabel').textContent = scoring.readiness_label;

            const confidence = scoring.confidence_score;
            document.getElementById('confidenceScore').textContent = `${confidence}%`;
            document.getElementById('confidenceScore').style.color = getScoreColor(confidence);
            document.getElementById('confidenceBar').style.width = `${confidence}%`;
            document.getElementById('confidenceBar').style.background = getScoreColor(confidence);

            // Decision
            const decisionBadge = document.getElementById('decisionBadge');
            decisionBadge.textContent = scoring.upgrade_decision;
            decisionBadge.className = `decision-badge ${getDecisionClass(scoring.upgrade_decision)}`;

            document.getElementById('upgradeRange').textContent =
                `v${assessment.source_version} → v${assessment.target_version}`;

            // Quick stats
            document.getElementById('quickStats').innerHTML = `
                <div style="display:flex;flex-direction:column;gap:6px;">
                    <div>🚨 Critical Issues: <strong>${scoring.critical_issues.length}</strong></div>
                    <div>🔴 High Risks: <strong>${scoring.high_risks.length}</strong></div>
                    <div>⚠️ Warnings: <strong>${scoring.warnings.length}</strong></div>
                    <div>🔌 API Removals: <strong>${assessment.api_removals.length}</strong></div>
                    <div>🎛️ Controllers Checked: <strong>${assessment.controller_compatibility.length}</strong></div>
                    <div>📋 Actions Required: <strong>${scoring.required_actions_before.length}</strong></div>
                </div>
            `;

            // Risk Matrix
            const matrixHtml = assessment.risk_matrix.map(entry => `
                <div class="matrix-row">
                    <div class="area-name">${entry.area}</div>
                    <div><span class="status-badge ${getStatusClass(entry.status)}">
                        ${getStatusEmoji(entry.status)} ${entry.status}
                    </span></div>
                    <div><span class="severity-badge ${getSeverityClass(entry.severity)}">${entry.severity}</span></div>
                    <div class="explanation">${entry.explanation}</div>
                </div>
            `).join('');
            document.getElementById('riskMatrixContent').innerHTML = matrixHtml;

            // Critical issues
            const critHtml = [...scoring.critical_issues, ...scoring.high_risks].map(issue => `
                <div class="issue-item ${issue.startsWith('PSP') || issue.includes('CRITICAL') ? 'issue-critical' : 'issue-high'}">
                    <span>${issue.includes('CRITICAL') ? '🚨' : '🔴'}</span>
                    <span>${issue}</span>
                </div>
            `).join('') || '<div class="empty-state">✅ No critical issues or high risks detected.</div>';
            document.getElementById('criticalBody').innerHTML = critHtml;
            document.getElementById('criticalPanel').querySelector('.panel-header').classList.add('open');
            document.getElementById('criticalPanel').querySelector('.panel-body').classList.add('active');

            // API Analysis
            let apiHtml = '';
            if (assessment.api_removals.length > 0) {
                apiHtml += `<div style="margin-bottom:1rem; font-weight:600; color:#ef4444;">🚨 ${assessment.api_removals.length} Removed API(s):</div>`;
                apiHtml += assessment.api_removals.map(api => `
                    <div class="issue-item issue-critical">
                        <span>🚨</span>
                        <div>
                            <strong>${api.kind}</strong> using <code>${api.current_api}</code><br>
                            <span style="font-size:0.75rem; color:var(--text-muted);">
                                Removed in K8s ${api.removal_version} · Replacement: ${api.replacement_api}
                            </span>
                        </div>
                    </div>
                `).join('');
            } else {
                apiHtml += '<div class="alert alert-success">✅ No removed APIs detected in active use.</div>';
            }

            if (assessment.deprecated_apis.length > 0) {
                apiHtml += `<div style="margin:1rem 0 0.5rem; font-weight:600; color:#f59e0b;">⚠️ ${assessment.deprecated_apis.length} Deprecated API(s):</div>`;
                apiHtml += `<table><thead><tr><th>Kind</th><th>API Version</th><th>Risk</th><th>Planned Removal</th></tr></thead><tbody>`;
                apiHtml += assessment.deprecated_apis.map(api => `
                    <tr>
                        <td>${api.kind}</td>
                        <td><code>${api.api_version}</code></td>
                        <td><span class="tag ${api.risk_level === 'HIGH' ? 'sev-high' : 'sev-medium'}">${api.risk_level}</span></td>
                        <td>v${api.planned_removal}</td>
                    </tr>
                `).join('');
                apiHtml += '</tbody></table>';
            }
            document.getElementById('apiBody').innerHTML = apiHtml;

            // Controllers
            let ctlHtml = '';
            if (assessment.controller_compatibility.length > 0) {
                ctlHtml += `<table><thead><tr><th>Controller</th><th>Installed</th><th>Status</th><th>Upgrade Timing</th></tr></thead><tbody>`;
                ctlHtml += assessment.controller_compatibility.map(ctl => `
                    <tr>
                        <td><strong>${ctl.name}</strong></td>
                        <td><code>${ctl.installed_version}</code></td>
                        <td><span class="status-badge ${getStatusClass(ctl.status)}">${getStatusEmoji(ctl.status)} ${ctl.status}</span></td>
                        <td style="font-size:0.8rem; color:var(--text-secondary);">${ctl.upgrade_timing}</td>
                    </tr>
                `).join('');
                ctlHtml += '</tbody></table>';
            } else {
                ctlHtml = '<div class="empty-state">No controllers detected.</div>';
            }
            document.getElementById('controllerBody').innerHTML = ctlHtml;

            // Failure Scenarios
            const scenarioHtml = assessment.failure_scenarios.map(s => {
                const cls = s.answer === 'YES' ? 'scenario-answer-yes' : (s.answer === 'NO' ? 'scenario-answer-no' : 'scenario-answer-possible');
                const emoji = s.answer === 'YES' ? '🔴' : (s.answer === 'NO' ? '✅' : '⚠️');
                return `
                    <div class="scenario-item">
                        <div class="scenario-question">❓ ${s.scenario}</div>
                        <div class="${cls}" style="font-weight:700; font-size:0.9rem;">${emoji} ${s.answer}</div>
                        <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:4px;">${s.reason}</div>
                    </div>
                `;
            }).join('');
            document.getElementById('scenarioBody').innerHTML = scenarioHtml;

            // Required Actions
            const actionsHtml = scoring.required_actions_before.map((action, i) => `
                <div class="action-item">
                    <span class="action-number">${i + 1}.</span>
                    <span>${action.replace(/^\d+\.?\s*/, '')}</span>
                </div>
            `).join('') || '<div class="empty-state">No required actions. Proceed with upgrade.</div>';
            document.getElementById('actionsBody').innerHTML = actionsHtml;

            // Upgrade Order
            const orderHtml = scoring.recommended_upgrade_order.map((step, i) => `
                <div class="action-item">
                    <span class="action-number">${i + 1}.</span>
                    <span>${step}</span>
                </div>
            `).join('');
            document.getElementById('orderBody').innerHTML = orderHtml;
        }

        function exportReport(format) {
            if (!lastReport) return;
            const src = document.getElementById('sourceVersion').value;
            const tgt = document.getElementById('targetVersion').value;
            window.open(`/api/export?format=${format}&source=${src}&target=${tgt}`, '_blank');
        }

        document.getElementById('assessmentForm').addEventListener('submit', runAssessment);

        // Drag and drop for file upload
        const uploadArea = document.getElementById('uploadArea');
        uploadArea.addEventListener('dragover', (e) => { e.preventDefault(); uploadArea.classList.add('drag-over'); });
        uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('drag-over'));
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            const file = e.dataTransfer.files[0];
            if (file) {
                const dt = new DataTransfer();
                dt.items.add(file);
                document.getElementById('snapshotFile').files = dt.files;
                uploadArea.querySelector('div').textContent = `📂 ${file.name}`;
            }
        });

        document.getElementById('snapshotFile').addEventListener('change', (e) => {
            if (e.target.files[0]) {
                uploadArea.querySelector('div').textContent = `📂 ${e.target.files[0].name}`;
            }
        });
    </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/assess", methods=["POST"])
def api_assess():
    """Run assessment and return JSON results."""
    try:
        source = request.form.get("source_version", "1.27").strip().lstrip("v")
        target = request.form.get("target_version", "1.30").strip().lstrip("v")
        mode = request.form.get("mode", "sample")

        # Collect cluster state
        if mode == "sample":
            from ai_k8s_upgrader.cluster_collector import SnapshotClusterCollector
            cluster_data = generate_sample_cluster(source_version=source, target_version=target)

            # Write temp file for snapshot collector
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump(cluster_data, f)
                tmp_path = f.name

            collector = SnapshotClusterCollector(tmp_path)
            snapshot = collector.collect()
            snapshot.source_mode = "sample"
            os.unlink(tmp_path)

        elif mode == "snapshot":
            file = request.files.get("snapshot_file")
            if not file:
                return jsonify({"error": "No snapshot file uploaded."}), 400

            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                file.save(f.name)
                tmp_path = f.name

            from ai_k8s_upgrader.cluster_collector import SnapshotClusterCollector
            collector = SnapshotClusterCollector(tmp_path)
            snapshot = collector.collect()
            os.unlink(tmp_path)

        elif mode == "live":
            snapshot = collect_cluster_state(mode="live")

        else:
            return jsonify({"error": f"Unknown mode: {mode}"}), 400

        # Run assessment
        engine = AssessmentEngine(source, target, snapshot)
        result = engine.run_all()

        # Score
        scorer = ScoringEngine(result)
        scoring = scorer.calculate()

        # Build response
        response = {
            "assessment": {
                "source_version": result.source_version,
                "target_version": result.target_version,
                "intermediate_versions": result.intermediate_versions,
                "api_removals": [
                    {
                        "kind": f.kind,
                        "current_api": f.current_api,
                        "removal_version": f.removal_version,
                        "replacement_api": f.replacement_api,
                        "severity": f.severity,
                        "category": f.category,
                    }
                    for f in result.api_removal_findings
                ],
                "deprecated_apis": [
                    {
                        "kind": f.object_name,
                        "api_version": f.api_version,
                        "risk_level": f.risk_level,
                        "planned_removal": f.planned_removal_version,
                    }
                    for f in result.deprecated_api_findings
                ],
                "controller_compatibility": [
                    {
                        "name": f.controller_name,
                        "installed_version": f.installed_version,
                        "status": f.status,
                        "upgrade_timing": f.upgrade_timing,
                    }
                    for f in result.controller_compatibility_findings
                ],
                "failure_scenarios": [
                    {
                        "scenario": f.scenario,
                        "answer": f.answer,
                        "reason": f.reason,
                        "severity": f.severity,
                    }
                    for f in result.failure_scenarios
                ],
                "risk_matrix": [
                    {
                        "area": e.area,
                        "status": e.status,
                        "severity": e.severity,
                        "explanation": e.explanation,
                    }
                    for e in scoring.risk_matrix
                ],
            },
            "scoring": {
                "upgrade_decision": scoring.upgrade_decision,
                "readiness_score": scoring.readiness_score,
                "readiness_label": scoring.readiness_label,
                "confidence_score": scoring.confidence_score,
                "critical_issues": scoring.critical_issues,
                "high_risks": scoring.high_risks,
                "warnings": scoring.warnings,
                "required_actions_before": scoring.required_actions_before,
                "recommended_upgrade_order": scoring.recommended_upgrade_order,
                "post_upgrade_validations": scoring.post_upgrade_validations,
                "final_recommendation": scoring.final_recommendation,
            },
            # Store for export
            "_result": result,
            "_scoring": scoring,
        }

        # Store in app context for export
        app.config["last_result"] = result
        app.config["last_scoring"] = scoring

        # Remove non-serializable keys
        del response["_result"]
        del response["_scoring"]

        return jsonify(response)

    except Exception as e:
        import traceback
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route("/api/export")
def api_export():
    """Export the last assessment as markdown or JSON."""
    fmt = request.args.get("format", "markdown")
    source = request.args.get("source", "unknown")
    target = request.args.get("target", "unknown")

    result = app.config.get("last_result")
    scoring = app.config.get("last_scoring")

    if not result or not scoring:
        return "No assessment available to export. Run an assessment first.", 404

    if fmt == "markdown":
        content = generate_markdown_report(result, scoring)
        filename = f"k8s_upgrade_{source}_to_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name
        return send_file(tmp_path, as_attachment=True, download_name=filename, mimetype="text/markdown")
    else:
        content = generate_json_report(result, scoring)
        filename = f"k8s_upgrade_{source}_to_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name
        return send_file(tmp_path, as_attachment=True, download_name=filename, mimetype="application/json")


def run_dashboard(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    """Start the web dashboard."""
    print(f"\nAI-Kubernetes-Upgrader Dashboard running at http://localhost:{port}")
    print("Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug)
