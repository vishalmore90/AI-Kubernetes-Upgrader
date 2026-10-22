"""
test_web_dashboard.py
=====================
Tests for the AI-Kubernetes-Upgrader Flask web dashboard:
- Public demo mode security (ALLOW_LIVE_CLUSTER enforcement)
- Sample mode assessment generation without credentials
- Snapshot JSON validation and upload handling
- Maximum upload size (5 MB limit enforcement)
- Safe error handling without stack trace leakage
- In-memory rate limiting
- Report export streaming
"""

import io
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_k8s_upgrader.web_dashboard import app, rate_limiter
from ai_k8s_upgrader.sample_generator import generate_sample_cluster


class TestWebDashboard(unittest.TestCase):
    """Test suite for the Flask web dashboard."""

    def setUp(self):
        app.config["TESTING"] = True
        app.config["ALLOW_LIVE_CLUSTER"] = False
        rate_limiter.reset()
        self.client = app.test_client()

    def tearDown(self):
        rate_limiter.reset()

    # -----------------------------------------------------------------------
    # Index & UI
    # -----------------------------------------------------------------------
    def test_index_page(self):
        """GET / should render the dashboard with demo mode indicator."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("AI-Kubernetes-Upgrader", html)
        self.assertIn("Public Demo Mode", html)
        self.assertIn("Disabled in Public Demo", html)

    def test_healthz_endpoint(self):
        """GET /healthz should return 200 with service health status."""
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get("status"), "healthy")
        self.assertEqual(data.get("service"), "ai-kubernetes-upgrader")
        self.assertEqual(data.get("version"), "1.0.0")
        self.assertIn("timestamp", data)

    def test_health_alias_endpoint(self):
        """GET /health should also return 200 matching /healthz."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data.get("status"), "healthy")

    # -----------------------------------------------------------------------
    # Sample Mode
    # -----------------------------------------------------------------------
    def test_sample_mode_produces_assessment(self):
        """Sample mode must run without credentials and return full assessment."""
        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "sample",
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("assessment", data)
        self.assertIn("scoring", data)
        self.assertEqual(data["assessment"]["source_version"], "1.27")
        self.assertEqual(data["assessment"]["target_version"], "1.30")
        self.assertIn("readiness_score", data["scoring"])
        self.assertIn("confidence_score", data["scoring"])
        self.assertIn("upgrade_decision", data["scoring"])
        self.assertIn("risk_matrix", data["assessment"])
        self.assertTrue(len(data["assessment"]["risk_matrix"]) > 0)

    # -----------------------------------------------------------------------
    # Live Cluster Security
    # -----------------------------------------------------------------------
    def test_live_mode_rejected_when_disabled_by_default(self):
        """Live mode must be rejected with 403 when ALLOW_LIVE_CLUSTER is False."""
        app.config["ALLOW_LIVE_CLUSTER"] = False
        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "live",
        })
        self.assertEqual(response.status_code, 403)
        data = response.get_json()
        self.assertIn("error", data)
        self.assertIn("Live cluster mode is disabled", data["error"])

    def test_live_mode_allowed_when_explicitly_configured(self):
        """Live mode should proceed to collector only when ALLOW_LIVE_CLUSTER is True."""
        app.config["ALLOW_LIVE_CLUSTER"] = True
        sample_snap = MagicMock()
        sample_snap.nodes = []
        sample_snap.deployments = []
        sample_snap.crds = []
        sample_snap.k8s_version = "1.27"
        sample_snap.k8s_git_version = "v1.27.0"
        sample_snap.api_server_version = "v1.27.0"
        sample_snap.platform = "linux/amd64"
        sample_snap.cluster_name = "mock-cluster"
        sample_snap.managed_provider = "self-managed"
        sample_snap.is_managed = False
        sample_snap.ha_control_plane = True
        sample_snap.control_plane_count = 1
        sample_snap.worker_count = 1
        sample_snap.namespaces = ["default"]

        with patch("ai_k8s_upgrader.web_dashboard.collect_cluster_state", return_value=sample_snap):
            response = self.client.post("/api/assess", data={
                "source_version": "1.27",
                "target_version": "1.30",
                "mode": "live",
            })
            self.assertEqual(response.status_code, 200)

    # -----------------------------------------------------------------------
    # Input Validation: Versions
    # -----------------------------------------------------------------------
    def test_invalid_source_version_format(self):
        """Malformed source version strings must return 400 Bad Request."""
        response = self.client.post("/api/assess", data={
            "source_version": "invalid_version",
            "target_version": "1.30",
            "mode": "sample",
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid source version format", response.get_json()["error"])

    def test_invalid_target_version_format(self):
        """Malformed target version strings must return 400 Bad Request."""
        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "not-a-version",
            "mode": "sample",
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid target version format", response.get_json()["error"])

    def test_downgrade_version_rejected(self):
        """Target version <= source version must return 400 Bad Request."""
        response = self.client.post("/api/assess", data={
            "source_version": "1.30",
            "target_version": "1.27",
            "mode": "sample",
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("must be higher than source version", response.get_json()["error"])

    def test_equal_versions_rejected(self):
        """Target version equal to source version must return 400 Bad Request."""
        response = self.client.post("/api/assess", data={
            "source_version": "1.28",
            "target_version": "1.28",
            "mode": "sample",
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("must be higher than source version", response.get_json()["error"])

    def test_unknown_mode_rejected(self):
        """Invalid mode parameter must return 400 Bad Request."""
        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "remote_hack",
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("Unknown mode", response.get_json()["error"])

    # -----------------------------------------------------------------------
    # Snapshot Upload Validation
    # -----------------------------------------------------------------------
    def test_snapshot_missing_file(self):
        """Snapshot mode without file upload must return 400 Bad Request."""
        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "snapshot",
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("No snapshot file uploaded", response.get_json()["error"])

    def test_snapshot_invalid_extension(self):
        """Non-JSON file uploads must return 400 Bad Request."""
        file_data = (io.BytesIO(b"hello world"), "test.yaml")
        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "snapshot",
            "snapshot_file": file_data,
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("Only JSON (.json) snapshot files are supported", response.get_json()["error"])

    def test_snapshot_empty_file(self):
        """Empty snapshot file must return 400 Bad Request."""
        file_data = (io.BytesIO(b""), "cluster.json")
        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "snapshot",
            "snapshot_file": file_data,
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("Uploaded snapshot file is empty", response.get_json()["error"])

    def test_snapshot_malformed_json(self):
        """Corrupted JSON must return 400 Bad Request with safe error."""
        file_data = (io.BytesIO(b"{invalid_json: 123"), "cluster.json")
        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "snapshot",
            "snapshot_file": file_data,
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid JSON format", response.get_json()["error"])

    def test_snapshot_root_not_dict(self):
        """JSON where root is not a dictionary must return 400 Bad Request."""
        file_data = (io.BytesIO(b"[\"item1\", \"item2\"]"), "cluster.json")
        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "snapshot",
            "snapshot_file": file_data,
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("root element must be a JSON object", response.get_json()["error"])

    def test_snapshot_unrecognized_cluster_data(self):
        """Arbitrary JSON object lacking Kubernetes fields must return 400 Bad Request."""
        file_data = (io.BytesIO(b"{\"arbitrary_key\": \"arbitrary_value\"}"), "cluster.json")
        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "snapshot",
            "snapshot_file": file_data,
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("does not contain recognized Kubernetes cluster snapshot data", response.get_json()["error"])

    def test_snapshot_valid_upload_success(self):
        """A valid snapshot JSON must process cleanly and produce assessment."""
        sample_data = generate_sample_cluster(source_version="1.27", target_version="1.30")
        raw_bytes = json.dumps(sample_data).encode("utf-8")
        file_data = (io.BytesIO(raw_bytes), "cluster_valid.json")

        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "snapshot",
            "snapshot_file": file_data,
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("assessment", data)
        self.assertIn("scoring", data)

    # -----------------------------------------------------------------------
    # Maximum Upload Size (5 MB)
    # -----------------------------------------------------------------------
    def test_max_upload_size_limit(self):
        """Uploads exceeding 5 MB must trigger 413 Payload Too Large."""
        # 5.5 MB payload
        large_payload = b"x" * (int(5.5 * 1024 * 1024))
        file_data = (io.BytesIO(large_payload), "huge_cluster.json")

        response = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "snapshot",
            "snapshot_file": file_data,
        })
        self.assertEqual(response.status_code, 413)
        data = response.get_json()
        self.assertIn("error", data)
        self.assertIn("exceeds the maximum allowed size of 5 MB", data["error"])

    # -----------------------------------------------------------------------
    # Safe Error Responses (No stack trace exposure)
    # -----------------------------------------------------------------------
    def test_safe_error_response_on_unexpected_exception(self):
        """Internal exceptions must return 500 without leaking stack traces or internal paths."""
        with patch("ai_k8s_upgrader.web_dashboard.AssessmentEngine") as mock_engine:
            mock_engine.side_effect = RuntimeError("Internal secret DB connection failed at /var/secrets")

            response = self.client.post("/api/assess", data={
                "source_version": "1.27",
                "target_version": "1.30",
                "mode": "sample",
            })
            self.assertEqual(response.status_code, 500)
            data = response.get_json()
            self.assertIn("error", data)
            # Ensure internal exception details are NEVER leaked to the client
            self.assertNotIn("Internal secret DB connection failed", data["error"])
            self.assertNotIn("/var/secrets", data["error"])
            self.assertNotIn("trace", data)
            self.assertIn("An internal error occurred", data["error"])

    # -----------------------------------------------------------------------
    # Rate Limiting
    # -----------------------------------------------------------------------
    def test_rate_limiting_triggers_429(self):
        """Exceeding request limit from same client must return 429 Too Many Requests."""
        # Rate limit is 30 by default; let's verify multiple calls trigger 429
        client_ip = "198.51.100.42"
        headers = {"X-Forwarded-For": client_ip}

        # Exhaust limit
        for i in range(30):
            res = self.client.post("/api/assess", data={
                "source_version": "1.27",
                "target_version": "1.30",
                "mode": "sample",
            }, headers=headers)
            self.assertEqual(res.status_code, 200)

        # 31st request should be blocked by rate limiter
        blocked_res = self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "sample",
        }, headers=headers)
        self.assertEqual(blocked_res.status_code, 429)
        self.assertIn("Retry-After", blocked_res.headers)
        data = blocked_res.get_json()
        self.assertIn("Rate limit exceeded", data["error"])

    # -----------------------------------------------------------------------
    # Export Endpoint
    # -----------------------------------------------------------------------
    def test_export_without_prior_assessment_returns_404(self):
        """GET /api/export without running an assessment must return 404."""
        app.config["last_result"] = None
        app.config["last_scoring"] = None
        response = self.client.get("/api/export?format=markdown")
        self.assertEqual(response.status_code, 404)

    def test_export_markdown_and_json_streaming(self):
        """GET /api/export should return streaming file downloads for markdown and json."""
        # First run sample assessment to populate last_result
        self.client.post("/api/assess", data={
            "source_version": "1.27",
            "target_version": "1.30",
            "mode": "sample",
        })

        # Test Markdown export
        md_resp = self.client.get("/api/export?format=markdown&source=1.27&target=1.30")
        self.assertEqual(md_resp.status_code, 200)
        self.assertIn("text/markdown", md_resp.content_type)
        self.assertIn("Kubernetes Upgrade Assessment Report", md_resp.data.decode("utf-8"))

        # Test JSON export
        json_resp = self.client.get("/api/export?format=json&source=1.27&target=1.30")
        self.assertEqual(json_resp.status_code, 200)
        self.assertIn("application/json", json_resp.content_type)
        exported_data = json.loads(json_resp.data.decode("utf-8"))
        self.assertIn("meta", exported_data)
        self.assertIn("executive_summary", exported_data)

    # -----------------------------------------------------------------------
    # Security Headers & Multi-Page Routes
    # -----------------------------------------------------------------------
    def test_security_headers_present(self):
        """Responses must include modern security headers (CSP, nosniff, DENY)."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("Permissions-Policy", response.headers)

    def test_docs_page(self):
        """GET /docs should render documentation and architecture."""
        response = self.client.get("/docs")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Documentation & Architecture", html)
        self.assertIn("Assessment Methodology", html)

    def test_privacy_page(self):
        """GET /privacy should render Privacy Policy."""
        response = self.client.get("/privacy")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Privacy Policy", html)
        self.assertIn("Zero Credential Collection", html)

    def test_terms_page(self):
        """GET /terms should render Terms of Service."""
        response = self.client.get("/terms")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Terms of Service", html)
        self.assertIn("Disclaimer of Warranty", html)

    def test_favicon_route(self):
        """GET /favicon.svg and /favicon.ico should return vector SVG favicon."""
        svg_resp = self.client.get("/favicon.svg")
        self.assertEqual(svg_resp.status_code, 200)
        self.assertIn("image/svg+xml", svg_resp.content_type)

        ico_resp = self.client.get("/favicon.ico")
        self.assertEqual(ico_resp.status_code, 200)
        self.assertIn("image/svg+xml", ico_resp.content_type)

    def test_admin_route_unauthorized_by_default(self):
        """Admin portal must reject unauthenticated requests with 401."""
        response = self.client.get("/admin")
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertIn("error", data)
        self.assertIn("administrative access is restricted", data["error"])

    def test_admin_route_authorized_with_token(self):
        """Admin portal must grant access when valid ADMIN_SECRET bearer token is supplied."""
        with patch.dict(os.environ, {"ADMIN_SECRET": "test-super-secret-token-123"}):
            headers = {"Authorization": "Bearer test-super-secret-token-123"}
            response = self.client.get("/admin", headers=headers)
            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            self.assertEqual(data.get("status"), "authenticated")


if __name__ == "__main__":
    unittest.main()
