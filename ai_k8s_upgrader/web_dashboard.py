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

import io
import json
import logging
import os
import re
import tempfile
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from flask import Flask, render_template_string, request, jsonify, send_file
from werkzeug.exceptions import RequestEntityTooLarge, HTTPException

from ai_k8s_upgrader.assessment_engine import AssessmentEngine
from ai_k8s_upgrader.cluster_collector import collect_cluster_state
from ai_k8s_upgrader.scoring_matrix import ScoringEngine
from ai_k8s_upgrader.reporter import generate_markdown_report, generate_json_report
from ai_k8s_upgrader.sample_generator import generate_sample_cluster

logger = logging.getLogger(__name__)

# Deployment & Security Configuration
ALLOW_LIVE_CLUSTER_DEFAULT = os.environ.get("ALLOW_LIVE_CLUSTER", "false").lower() in ("true", "1", "yes")
MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE
app.config.setdefault("ALLOW_LIVE_CLUSTER", ALLOW_LIVE_CLUSTER_DEFAULT)

# ---------------------------------------------------------------------------
# HTML Template
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""
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
            <span class="header-badge">v1.0.0 · {% if allow_live_cluster %}Enterprise Edition{% else %}Public Demo Edition{% endif %}</span>
        </div>
    </header>

    <main class="main">
        <!-- Config Panel -->
        <div class="config-panel">
            <div class="config-title">
                ⚙️ Assessment Configuration
                {% if not allow_live_cluster %}
                <span style="font-size:0.75rem; font-weight:500; background:rgba(6,182,212,0.12); color:var(--accent-cyan); border:1px solid rgba(6,182,212,0.3); padding:3px 10px; border-radius:12px; margin-left:8px;">Public Demo Mode</span>
                {% endif %}
            </div>
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
                            {% if allow_live_cluster %}
                            <option value="live">🔌 Live Cluster (kubectl)</option>
                            {% else %}
                            <option value="live" disabled>🔌 Live Cluster (Disabled in Public Demo)</option>
                            {% endif %}
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
                    <div>📂 Click to upload cluster snapshot JSON (max 5 MB)</div>
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
                let data = null;
                try {
                    data = await resp.json();
                } catch (parseErr) {
                    if (resp.status === 413) {
                        data = { error: 'The uploaded file exceeds the maximum allowed size of 5 MB.' };
                    } else if (resp.status === 429) {
                        data = { error: 'Rate limit exceeded. Please wait a moment before running another assessment.' };
                    } else {
                        data = { error: `Server error (${resp.status} ${resp.statusText})` };
                    }
                }

                if (!resp.ok || !data || data.error) {
                    formError.innerHTML = `<div class="alert alert-error">❌ ${(data && data.error) || 'Assessment failed.'}</div>`;
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
# Rate Limiting & Input Validation
# ---------------------------------------------------------------------------

class InMemoryRateLimiter:
    """Thread-safe sliding-window rate limiter by client IP."""

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.history = defaultdict(deque)
        self.lock = threading.Lock()

    def is_allowed(self, client_id: str) -> Tuple[bool, int]:
        now = time.time()
        cutoff = now - self.window_seconds
        with self.lock:
            q = self.history[client_id]
            while q and q[0] < cutoff:
                q.popleft()

            if len(q) >= self.max_requests:
                retry_after = int(self.window_seconds - (now - q[0])) + 1
                return False, max(1, retry_after)

            q.append(now)
            # Periodic cleanup to prevent memory bloat
            if len(self.history) > 1000:
                expired = [k for k, v in self.history.items() if not v or v[-1] < cutoff]
                for k in expired:
                    del self.history[k]
            return True, 0

    def reset(self):
        with self.lock:
            self.history.clear()


rate_limiter = InMemoryRateLimiter(max_requests=RATE_LIMIT_REQUESTS, window_seconds=RATE_LIMIT_WINDOW)

VERSION_PATTERN = re.compile(r"^v?([1-9]\d*)\.([0-9]\d*)(?:\.([0-9]\d*))?$")


def validate_k8s_version(version_str: str, label: str = "version") -> Tuple[bool, Optional[str], Optional[Tuple[int, int]]]:
    """Validate Kubernetes version format and supported range."""
    if not version_str or not isinstance(version_str, str):
        return False, f"Missing or invalid {label}. Please provide a valid version string (e.g. 1.27).", None

    v_clean = version_str.strip()
    match = VERSION_PATTERN.match(v_clean)
    if not match:
        return False, f"Invalid {label} format: '{version_str}'. Expected format like '1.27' or 'v1.30'.", None

    major = int(match.group(1))
    minor = int(match.group(2))
    if major != 1 or minor < 15 or minor > 40:
        return False, f"Unsupported {label} '1.{minor}'. Supported range is K8s 1.15 to 1.40.", None

    return True, None, (major, minor)


def validate_version_pair(source_str: str, target_str: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """Validate source and target versions and ensure target > source."""
    s_ok, s_err, s_tuple = validate_k8s_version(source_str, "source version")
    if not s_ok:
        return False, s_err, None, None

    t_ok, t_err, t_tuple = validate_k8s_version(target_str, "target version")
    if not t_ok:
        return False, t_err, None, None

    if s_tuple >= t_tuple:
        return (
            False,
            f"Target version ({target_str.strip()}) must be higher than source version ({source_str.strip()}) for upgrade assessment.",
            None,
            None,
        )

    clean_source = source_str.strip().lstrip("v")
    clean_target = target_str.strip().lstrip("v")
    return True, None, clean_source, clean_target


def validate_snapshot_data(data: Any) -> Tuple[bool, Optional[str]]:
    """Validate parsed JSON content for cluster snapshot."""
    if not isinstance(data, dict):
        return False, "Invalid snapshot: root element must be a JSON object (dictionary)."

    recognized_keys = {
        "nodes", "deployments", "statefulsets", "daemonsets", "crds",
        "validating_webhooks", "mutating_webhooks", "storage_classes",
        "persistent_volumes", "persistent_volume_claims", "network_policies",
        "namespaces", "k8s_version"
    }
    found_keys = set(data.keys()).intersection(recognized_keys)
    if not found_keys:
        return False, "Invalid snapshot: file does not contain recognized Kubernetes cluster snapshot data."

    list_keys = [
        "nodes", "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs",
        "crds", "validating_webhooks", "mutating_webhooks", "storage_classes",
        "persistent_volumes", "persistent_volume_claims", "network_policies",
        "namespaces"
    ]
    for key in list_keys:
        if key in data and not isinstance(data[key], list):
            return False, f"Invalid snapshot structure: field '{key}' must be a list."

    dict_item_lists = ["nodes", "deployments", "statefulsets", "daemonsets", "crds", "storage_classes"]
    for key in dict_item_lists:
        if key in data:
            for i, item in enumerate(data[key]):
                if not isinstance(item, dict):
                    return False, f"Invalid snapshot structure: item #{i + 1} in '{key}' must be a JSON object."

    return True, None


# ---------------------------------------------------------------------------
# Error Handlers
# ---------------------------------------------------------------------------

@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(error):
    """Handle files exceeding MAX_CONTENT_LENGTH."""
    logger.warning("Upload rejected: payload exceeds maximum allowed size (5 MB)")
    return jsonify({
        "error": "The uploaded file exceeds the maximum allowed size of 5 MB."
    }), 413


@app.errorhandler(500)
def handle_internal_server_error(error):
    """Generic 500 error handler that does not leak stack traces."""
    logger.exception("Internal server error: %s", error)
    return jsonify({
        "error": "An internal error occurred while processing the request. Please verify your inputs and try again."
    }), 500


# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    allow_live = app.config.get("ALLOW_LIVE_CLUSTER", False)
    return render_template_string(DASHBOARD_HTML, allow_live_cluster=allow_live)


@app.route("/api/assess", methods=["POST"])
def api_assess():
    """Run assessment and return JSON results."""
    # Rate Limiting check
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or "unknown"
    )
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        logger.warning(f"Rate limit exceeded for client {client_ip}")
        response = jsonify({
            "error": "Rate limit exceeded. Please wait a moment before running another assessment."
        })
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response

    try:
        source_raw = request.form.get("source_version", "1.27")
        target_raw = request.form.get("target_version", "1.30")
        mode = request.form.get("mode", "sample").strip().lower()

        # Input Validation: Versions
        v_ok, v_err, source, target = validate_version_pair(source_raw, target_raw)
        if not v_ok:
            return jsonify({"error": v_err}), 400

        # Input Validation: Mode
        if mode not in ("sample", "snapshot", "live"):
            return jsonify({"error": f"Unknown mode: '{mode}'. Must be 'sample', 'snapshot', or 'live'."}), 400

        # Public Demo Security: Enforce ALLOW_LIVE_CLUSTER
        if mode == "live":
            allow_live = app.config.get("ALLOW_LIVE_CLUSTER", False)
            if not allow_live:
                logger.warning(f"Blocked live cluster request from {client_ip}: ALLOW_LIVE_CLUSTER is disabled")
                return jsonify({
                    "error": "Live cluster mode is disabled in this public demo environment. Please use Sample Mode or upload a JSON Snapshot."
                }), 403

        # Collect cluster state
        if mode == "sample":
            from ai_k8s_upgrader.cluster_collector import SnapshotClusterCollector
            cluster_data = generate_sample_cluster(source_version=source, target_version=target)

            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
                    json.dump(cluster_data, f)
                    tmp_path = f.name

                collector = SnapshotClusterCollector(tmp_path)
                snapshot = collector.collect()
                snapshot.source_mode = "sample"
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

        elif mode == "snapshot":
            file = request.files.get("snapshot_file")
            if not file or not file.filename:
                return jsonify({"error": "No snapshot file uploaded."}), 400

            filename = file.filename.lower()
            if not filename.endswith(".json"):
                return jsonify({"error": "Invalid file type. Only JSON (.json) snapshot files are supported."}), 400

            # Read and parse JSON content safely
            try:
                raw_bytes = file.read()
                if not raw_bytes or len(raw_bytes.strip()) == 0:
                    return jsonify({"error": "Uploaded snapshot file is empty."}), 400
                data = json.loads(raw_bytes.decode("utf-8"))
            except UnicodeDecodeError:
                return jsonify({"error": "Failed to decode snapshot file. Ensure the file is UTF-8 encoded."}), 400
            except json.JSONDecodeError as jde:
                logger.info(f"JSON decode error in snapshot upload: {jde}")
                return jsonify({"error": f"Invalid JSON format in snapshot file: {jde.msg}."}), 400

            # Validate snapshot structure
            is_valid_snap, snap_err = validate_snapshot_data(data)
            if not is_valid_snap:
                return jsonify({"error": snap_err}), 400

            # Parse with collector and guarantee cleanup
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
                    json.dump(data, f)
                    tmp_path = f.name

                from ai_k8s_upgrader.cluster_collector import SnapshotClusterCollector
                collector = SnapshotClusterCollector(tmp_path)
                snapshot = collector.collect()
            except (TypeError, KeyError, ValueError) as pe:
                logger.warning(f"Snapshot structure parsing error: {pe}")
                return jsonify({
                    "error": "Failed to parse snapshot: content does not match the required Kubernetes cluster schema."
                }), 400
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass

        elif mode == "live":
            snapshot = collect_cluster_state(mode="live")

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
        }

        # Store in app config for export
        app.config["last_result"] = result
        app.config["last_scoring"] = scoring

        return jsonify(response)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in api_assess: %s", e)
        return jsonify({
            "error": "An internal error occurred while processing the assessment. Please verify your inputs and try again."
        }), 500


@app.route("/api/export")
def api_export():
    """Export the last assessment as markdown or JSON (in-memory streaming, no disk leaks)."""
    fmt = request.args.get("format", "markdown").strip().lower()
    raw_source = request.args.get("source", "unknown")
    raw_target = request.args.get("target", "unknown")

    # Sanitize version strings for safe file naming
    safe_source = re.sub(r'[^a-zA-Z0-9._-]', '', raw_source)
    safe_target = re.sub(r'[^a-zA-Z0-9._-]', '', raw_target)

    result = app.config.get("last_result")
    scoring = app.config.get("last_scoring")

    if not result or not scoring:
        return jsonify({"error": "No assessment available to export. Run an assessment first."}), 404

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if fmt == "json":
        content = generate_json_report(result, scoring)
        filename = f"k8s_upgrade_{safe_source}_to_{safe_target}_{timestamp}.json"
        return send_file(
            io.BytesIO(content.encode("utf-8")),
            as_attachment=True,
            download_name=filename,
            mimetype="application/json"
        )
    else:
        content = generate_markdown_report(result, scoring)
        filename = f"k8s_upgrade_{safe_source}_to_{safe_target}_{timestamp}.md"
        return send_file(
            io.BytesIO(content.encode("utf-8")),
            as_attachment=True,
            download_name=filename,
            mimetype="text/markdown"
        )


def run_dashboard(host: Optional[str] = None, port: Optional[int] = None, debug: Optional[bool] = None):
    """
    Start the web dashboard.
    Binds dynamically to host and port supplied by environment variables (e.g., Render $PORT).
    """
    if host is None:
        host = os.environ.get("HOST", "0.0.0.0")
    if port is None:
        port = int(os.environ.get("PORT", 5000))
    if debug is None:
        debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("true", "1", "yes")

    print(f"\nAI-Kubernetes-Upgrader Dashboard running at http://{host}:{port}")
    print("Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_dashboard()
