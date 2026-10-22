"""
web_dashboard.py
================
Enterprise Flask web dashboard for the Kubernetes Upgrade Assessor.

Features:
- Multi-page UI with Assess, Documentation, Architecture, Privacy Policy, and Terms of Service
- Strict 2-brand color architecture (Dark Slate #0B1120 + Cobalt Blue #2563EB)
- Cohesive SVG stroke icons (no emojis, no purple gradients, no pill buttons)
- In-memory sliding-window rate limiting per IP
- Zero-credential public demo mode (ALLOW_LIVE_CLUSTER guard)
- Strict snapshot schema & size validation (5 MB limit)
- Leak-free temporary file cleanup & in-memory report streaming
- Strict security headers (CSP, X-Frame-Options, X-Content-Type-Options)
- Protected administrative endpoints
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

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_file,
    send_from_directory,
)
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from ai_k8s_upgrader.assessment_engine import AssessmentEngine
from ai_k8s_upgrader.cluster_collector import collect_cluster_state
from ai_k8s_upgrader.scoring_matrix import ScoringEngine
from ai_k8s_upgrader.reporter import generate_markdown_report, generate_json_report
from ai_k8s_upgrader.sample_generator import generate_sample_cluster

logger = logging.getLogger(__name__)

# Deployment & Security Configuration
ALLOW_LIVE_CLUSTER_DEFAULT = os.environ.get("ALLOW_LIVE_CLUSTER", "false").lower() in ("true", "1", "yes")
MAX_UPLOAD_SIZE = int(os.environ.get("MAX_UPLOAD_SIZE", 5 * 1024 * 1024))  # 5 MB
RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
WEB_CONCURRENCY = int(os.environ.get("WEB_CONCURRENCY", "1"))

if WEB_CONCURRENCY > 1:
    logger.warning(
        "WEB_CONCURRENCY=%d: InMemoryRateLimiter tracks sliding-window counts in process memory. "
        "Each gunicorn worker maintains isolated limits. For distributed deployments, configure an external backend.",
        WEB_CONCURRENCY,
    )

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE
app.config.setdefault("ALLOW_LIVE_CLUSTER", ALLOW_LIVE_CLUSTER_DEFAULT)


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------

@app.after_request
def apply_security_headers(response):
    """Inject strict security headers into all responses."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


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
        "namespaces", "k8s_version", "all_resources", "pod_security_policies",
        "jobs", "cronjobs"
    }
    found_keys = set(data.keys()).intersection(recognized_keys)
    if not found_keys:
        return False, "Invalid snapshot: file does not contain recognized Kubernetes cluster snapshot data."

    list_keys = [
        "nodes", "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs",
        "crds", "validating_webhooks", "mutating_webhooks", "storage_classes",
        "persistent_volumes", "persistent_volume_claims", "network_policies",
        "namespaces", "all_resources", "pod_security_policies"
    ]
    for key in list_keys:
        if key in data and not isinstance(data[key], list):
            return False, f"Invalid snapshot structure: field '{key}' must be a list."

    dict_item_lists = ["nodes", "deployments", "statefulsets", "daemonsets", "crds", "storage_classes", "all_resources"]
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
# Page Routes (5 Navigation Targets)
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Main Assessment Dashboard."""
    allow_live = app.config.get("ALLOW_LIVE_CLUSTER", False)
    return render_template(
        "index.html",
        allow_live_cluster=allow_live,
        active_nav="assess",
        now_year=datetime.now().year,
    )


@app.route("/docs")
def documentation():
    """Technical Documentation & Architecture page."""
    return render_template(
        "docs.html",
        active_nav="docs",
        now_year=datetime.now().year,
    )


@app.route("/privacy")
def privacy_policy():
    """Privacy Policy page."""
    return render_template(
        "privacy.html",
        active_nav="privacy",
        now_year=datetime.now().year,
    )


@app.route("/terms")
def terms_of_service():
    """Terms and Conditions page."""
    return render_template(
        "terms.html",
        active_nav="terms",
        now_year=datetime.now().year,
    )


@app.route("/favicon.ico")
@app.route("/favicon.svg")
def favicon():
    """Serve vector favicon."""
    return send_from_directory(app.static_folder, "favicon.svg", mimetype="image/svg+xml")


# ---------------------------------------------------------------------------
# Protected Admin Route
# ---------------------------------------------------------------------------

@app.route("/admin", methods=["GET", "POST"])
def admin_portal():
    """
    Administrative portal route protected by token authentication.
    Restricts access so visitors cannot access privileged control panels.
    """
    admin_secret = os.environ.get("ADMIN_SECRET")
    auth_header = request.headers.get("Authorization")
    if not admin_secret or auth_header != f"Bearer {admin_secret}":
        logger.warning(f"Unauthorized admin access attempt from {request.remote_addr}")
        return jsonify({"error": "Unauthorized: administrative access is restricted."}), 401
    return jsonify({"status": "authenticated", "message": "Admin control plane active."})


# ---------------------------------------------------------------------------
# Health Check Endpoints (Liveness / Readiness)
# ---------------------------------------------------------------------------

@app.route("/healthz")
@app.route("/health")
def health_check():
    """Liveness and readiness probe endpoint for hosting environments (e.g. Render)."""
    return jsonify({
        "status": "healthy",
        "service": "ai-kubernetes-upgrader",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
    }), 200


# ---------------------------------------------------------------------------
# Assessment & Export API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/assess", methods=["POST"])
def api_assess():
    """Run assessment and return JSON results."""
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
    Ensures debug mode is turned completely OFF by default.
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
