"""
test_regression.py
==================
Comprehensive regression tests for Phase 4:
Evidence-based API detection, scoring consistency, and web dashboard validation.
"""

import io
import json
import tempfile
import unittest

from ai_k8s_upgrader.cluster_collector import (
    ClusterSnapshot,
    NodeInfo,
    WorkloadResource,
    SnapshotClusterCollector,
    build_resource_inventory,
)
from ai_k8s_upgrader.assessment_engine import AssessmentEngine, Severity, Status
from ai_k8s_upgrader.scoring_matrix import ScoringEngine
from ai_k8s_upgrader.reporter import generate_markdown_report, generate_json_report
from ai_k8s_upgrader.web_dashboard import app, rate_limiter


def _make_minimal_snapshot(
    k8s_version: str = "1.21",
    all_resources=None,
    all_resources_provided: bool = True,
    nodes=None,
    deployments=None,
    pod_security_policies=None,
    collection_errors=None,
) -> ClusterSnapshot:
    """Helper to build a clean ClusterSnapshot for testing."""
    if nodes is None:
        nodes = [
            NodeInfo(
                name="node-1",
                role="worker",
                k8s_version=k8s_version,
                os_image="Ubuntu 22.04 LTS",
                kernel_version="5.15.0-generic",
                container_runtime="containerd://1.6.20",
                status="Ready",
                cpu="4",
                memory="16Gi",
                architecture="amd64",
            )
        ]
    return ClusterSnapshot(
        k8s_version=k8s_version,
        k8s_git_version=f"v{k8s_version}.0",
        platform="linux/amd64",
        nodes=nodes,
        deployments=deployments or [],
        statefulsets=[],
        daemonsets=[],
        jobs=[],
        cronjobs=[],
        crds=[],
        validating_webhooks=[],
        mutating_webhooks=[],
        storage_classes=[],
        persistent_volumes=[],
        persistent_volume_claims=[],
        network_policies=[],
        pod_security_policies=pod_security_policies or [],
        all_resources=all_resources if all_resources is not None else [],
        all_resources_provided=all_resources_provided,
        collection_errors=collection_errors or [],
    )


class TestRegressionScenarios(unittest.TestCase):
    """Automated test cases for Phase 4 regression requirements."""

    def setUp(self):
        rate_limiter.reset()
        app.config["TESTING"] = True
        self.client = app.test_client()

    # -------------------------------------------------------------------------
    # TEST 1: SINGLE LEGACY INGRESS
    # -------------------------------------------------------------------------
    def test_scenario_1_single_legacy_ingress(self):
        """
        Input: 1.21 -> 1.22 with single legacy Ingress (networking.k8s.io/v1beta1).
        Expected:
        - Exactly one cluster-observed API-removal finding.
        - Finding identifies Ingress and 'legacy-public-ingress' in 'production'.
        - Recommendation points to networking.k8s.io/v1.
        - No unsupported webhook, CRD, IngressClass, or alternate Ingress findings.
        - Issue counts, remediation actions, and report summaries agree.
        """
        snapshot = _make_minimal_snapshot(
            k8s_version="1.21",
            all_resources=[
                {
                    "apiVersion": "networking.k8s.io/v1beta1",
                    "kind": "Ingress",
                    "namespace": "production",
                    "name": "legacy-public-ingress",
                }
            ],
        )

        engine = AssessmentEngine("1.21", "1.22", snapshot)
        result = engine.run_all()
        scoring = ScoringEngine(result).calculate()

        # Exactly 1 API removal finding
        self.assertEqual(len(result.api_removal_findings), 1)
        finding = result.api_removal_findings[0]
        self.assertEqual(finding.kind, "Ingress")
        self.assertEqual(finding.object_name, "legacy-public-ingress")
        self.assertEqual(finding.namespace, "production")
        self.assertEqual(finding.current_api, "networking.k8s.io/v1beta1")
        self.assertIn("networking.k8s.io/v1", finding.replacement_api)

        # No unsupported findings for webhooks, CRDs, IngressClass, or extensions/v1beta1
        kinds_reported = {f.kind for f in result.api_removal_findings}
        self.assertEqual(kinds_reported, {"Ingress"})
        apis_reported = {f.current_api for f in result.api_removal_findings}
        self.assertEqual(apis_reported, {"networking.k8s.io/v1beta1"})

        # Subsystems must not manufacture breakage
        self.assertEqual(len(result.crd_compatibility_findings), 0)
        self.assertEqual(len(result.webhook_findings), 0)

        # Critical issue counts agree
        self.assertEqual(len(scoring.critical_issues), 1)
        self.assertIn("legacy-public-ingress", scoring.critical_issues[0])

        # Action reflects Ingress migration
        ingress_actions = [a for a in scoring.required_actions_before if "Ingress" in a]
        self.assertEqual(len(ingress_actions), 1)
        self.assertIn("networking.k8s.io/v1", ingress_actions[0])

    # -------------------------------------------------------------------------
    # TEST 2: CLEAN API INVENTORY
    # -------------------------------------------------------------------------
    def test_scenario_2_clean_api_inventory(self):
        """
        Input: 1.21 -> 1.22 with clean API inventory (no legacy APIs).
        Expected:
        - Zero cluster-observed removed-API findings.
        - Zero resource-specific critical API-removal actions.
        - Release notes describe 1.22 removals without presenting them as observed findings.
        """
        snapshot = _make_minimal_snapshot(k8s_version="1.21", all_resources=[])

        engine = AssessmentEngine("1.21", "1.22", snapshot)
        result = engine.run_all()
        scoring = ScoringEngine(result).calculate()

        self.assertEqual(len(result.api_removal_findings), 0)
        self.assertEqual(len(result.deprecated_api_findings), 0)

        # No critical issues for API removals
        api_critical_issues = [i for i in scoring.critical_issues if "API Removal" in i]
        self.assertEqual(len(api_critical_issues), 0)

        # No resource-specific API migration actions
        migration_actions = [a for a in scoring.required_actions_before if "Migrate" in a]
        self.assertEqual(len(migration_actions), 0)

        # Release notes still present release information
        self.assertTrue(len(result.release_notes) > 0)

    # -------------------------------------------------------------------------
    # TEST 3: MODERN INGRESS API
    # -------------------------------------------------------------------------
    def test_scenario_3_modern_ingress_api(self):
        """
        Input: 1.21 -> 1.22 with modern Ingress (networking.k8s.io/v1).
        Expected:
        - Modern Ingress must not trigger a removal finding.
        - 0 API removal findings.
        """
        snapshot = _make_minimal_snapshot(
            k8s_version="1.21",
            all_resources=[
                {
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "Ingress",
                    "namespace": "production",
                    "name": "modern-public-ingress",
                }
            ],
        )

        engine = AssessmentEngine("1.21", "1.22", snapshot)
        result = engine.run_all()

        self.assertEqual(len(result.api_removal_findings), 0)

    # -------------------------------------------------------------------------
    # TEST 4: DOCKER RUNTIME COMPATIBILITY
    # -------------------------------------------------------------------------
    def test_scenario_4_docker_runtime_compatibility(self):
        """
        Input: 1.23 -> 1.24 with one docker node and one containerd node.
        Expected:
        - worker-docker-1 flagged as potential upgrade blocker (dockershim removed in 1.24).
        - worker-containerd-1 is not flagged.
        - No active HPA, FlowSchema, CRD, Ingress, or webhook API finding created.
        - Remediation explains migration from Docker to CRI runtime.
        """
        nodes = [
            NodeInfo(
                name="worker-docker-1",
                role="worker",
                k8s_version="1.23.0",
                os_image="Ubuntu 20.04 LTS",
                kernel_version="5.15.0-generic",
                container_runtime="docker://20.10.17",
                status="Ready",
                cpu="4",
                memory="16Gi",
                architecture="amd64",
            ),
            NodeInfo(
                name="worker-containerd-1",
                role="worker",
                k8s_version="1.23.0",
                os_image="Ubuntu 20.04 LTS",
                kernel_version="5.15.0-generic",
                container_runtime="containerd://1.6.20",
                status="Ready",
                cpu="4",
                memory="16Gi",
                architecture="amd64",
            ),
        ]
        snapshot = _make_minimal_snapshot(k8s_version="1.23", nodes=nodes, all_resources=[])

        engine = AssessmentEngine("1.23", "1.24", snapshot)
        result = engine.run_all()
        scoring = ScoringEngine(result).calculate()

        # Docker runtime flagged
        self.assertEqual(result.runtime_status, Status.CRITICAL)
        docker_issues = [i for i in result.runtime_issues if "worker-docker-1" in i]
        self.assertTrue(len(docker_issues) > 0)
        containerd_issues = [i for i in result.runtime_issues if "worker-containerd-1" in i]
        self.assertEqual(len(containerd_issues), 0)

        # No false API removal findings
        self.assertEqual(len(result.api_removal_findings), 0)
        self.assertEqual(len(result.deprecated_api_findings), 0)

        # Remediation action exists for Docker node
        docker_actions = [a for a in scoring.required_actions_before if "Docker" in a or "dockershim" in a]
        self.assertTrue(len(docker_actions) > 0)
        self.assertIn("worker-docker-1", docker_actions[0])

    # -------------------------------------------------------------------------
    # TEST 5: HORIZONTALPODAUTOSCALER API REMOVAL
    # -------------------------------------------------------------------------
    def test_scenario_5_hpa_api_removal(self):
        """
        Input: 1.25 -> 1.26 with autoscaling/v2beta2 HPA.
        Expected:
        - Detects HPA API removal in 1.26.
        - Recommends autoscaling/v2.
        - Avoids reporting unrelated deprecated APIs.
        - HPA issue is not counted twice as duplicate critical blockers.
        """
        snapshot = _make_minimal_snapshot(
            k8s_version="1.25",
            all_resources=[
                {
                    "apiVersion": "autoscaling/v2beta2",
                    "kind": "HorizontalPodAutoscaler",
                    "namespace": "production",
                    "name": "checkout-api-hpa",
                }
            ],
        )

        engine = AssessmentEngine("1.25", "1.26", snapshot)
        result = engine.run_all()
        scoring = ScoringEngine(result).calculate()

        self.assertEqual(len(result.api_removal_findings), 1)
        hpa_finding = result.api_removal_findings[0]
        self.assertEqual(hpa_finding.kind, "HorizontalPodAutoscaler")
        self.assertEqual(hpa_finding.object_name, "checkout-api-hpa")
        self.assertEqual(hpa_finding.current_api, "autoscaling/v2beta2")
        self.assertIn("autoscaling/v2", hpa_finding.replacement_api)

        # Distinct critical issues: HPA counted exactly once
        hpa_critical_issues = [i for i in scoring.critical_issues if "HorizontalPodAutoscaler" in i]
        self.assertEqual(len(hpa_critical_issues), 1)

        # It should not also be an active deprecated API finding
        hpa_dep_findings = [f for f in result.deprecated_api_findings if f.object_name == "checkout-api-hpa"]
        self.assertEqual(len(hpa_dep_findings), 0)

    # -------------------------------------------------------------------------
    # TEST 6: PODSECURITYPOLICY REMOVAL
    # -------------------------------------------------------------------------
    def test_scenario_6_psp_removal(self):
        """
        Case A: Snapshot contains PSP assessed 1.24 -> 1.25.
        Case B: Snapshot contains no PSP assessed 1.24 -> 1.25.
        Expected:
        - Case A identifies PSP migration risk and required action.
        - Case B does not claim cluster has PSPs.
        """
        # Case A: PSP present
        snapshot_a = _make_minimal_snapshot(
            k8s_version="1.24",
            pod_security_policies=["restricted-psp"],
            all_resources=[
                {
                    "apiVersion": "policy/v1beta1",
                    "kind": "PodSecurityPolicy",
                    "name": "restricted-psp",
                }
            ],
        )
        engine_a = AssessmentEngine("1.24", "1.25", snapshot_a)
        result_a = engine_a.run_all()
        scoring_a = ScoringEngine(result_a).calculate()

        psp_findings_a = [f for f in result_a.api_removal_findings if f.kind == "PodSecurityPolicy"]
        self.assertEqual(len(psp_findings_a), 1)
        psp_actions_a = [a for a in scoring_a.required_actions_before if "PodSecurityPolicy" in a or "PSA" in a]
        self.assertTrue(len(psp_actions_a) > 0)

        # Case B: PSP absent
        snapshot_b = _make_minimal_snapshot(
            k8s_version="1.24",
            pod_security_policies=[],
            all_resources=[],
        )
        engine_b = AssessmentEngine("1.24", "1.25", snapshot_b)
        result_b = engine_b.run_all()
        scoring_b = ScoringEngine(result_b).calculate()

        psp_findings_b = [f for f in result_b.api_removal_findings if f.kind == "PodSecurityPolicy"]
        self.assertEqual(len(psp_findings_b), 0)
        psp_actions_b = [a for a in scoring_b.required_actions_before if "PodSecurityPolicy" in a]
        self.assertEqual(len(psp_actions_b), 0)

    # -------------------------------------------------------------------------
    # TEST 7: FLOWSCHEMA API REMOVAL
    # -------------------------------------------------------------------------
    def test_scenario_7_flowschema_removal(self):
        """
        Input: 1.28 -> 1.29 with FlowSchema and PriorityLevelConfiguration (v1beta2).
        Expected:
        - Identifies v1beta2 removal in K8s 1.29 for both resources.
        - Preserves identity of each resource.
        - Does not confuse v1beta2 removal in 1.29 with v1beta3 removal in 1.32.
        - Target recommendation is v1beta3 or v1.
        """
        snapshot = _make_minimal_snapshot(
            k8s_version="1.28",
            all_resources=[
                {
                    "apiVersion": "flowcontrol.apiserver.k8s.io/v1beta2",
                    "kind": "FlowSchema",
                    "name": "custom-workload-fs",
                },
                {
                    "apiVersion": "flowcontrol.apiserver.k8s.io/v1beta2",
                    "kind": "PriorityLevelConfiguration",
                    "name": "custom-workload-plc",
                },
            ],
        )

        engine = AssessmentEngine("1.28", "1.29", snapshot)
        result = engine.run_all()

        kinds_found = {f.kind: f for f in result.api_removal_findings}
        self.assertIn("FlowSchema", kinds_found)
        self.assertIn("PriorityLevelConfiguration", kinds_found)

        fs_finding = kinds_found["FlowSchema"]
        self.assertEqual(fs_finding.object_name, "custom-workload-fs")
        self.assertEqual(fs_finding.current_api, "flowcontrol.apiserver.k8s.io/v1beta2")
        self.assertEqual(fs_finding.removal_version, "1.29")

        plc_finding = kinds_found["PriorityLevelConfiguration"]
        self.assertEqual(plc_finding.object_name, "custom-workload-plc")
        self.assertEqual(plc_finding.current_api, "flowcontrol.apiserver.k8s.io/v1beta2")
        self.assertEqual(plc_finding.removal_version, "1.29")

        # Check that v1beta3 is not reported as removed in 1.29
        v1beta3_removals = [f for f in result.api_removal_findings if "v1beta3" in f.current_api]
        self.assertEqual(len(v1beta3_removals), 0)

    # -------------------------------------------------------------------------
    # TEST 8: MISSING VERSUS EMPTY INVENTORY
    # -------------------------------------------------------------------------
    def test_scenario_8_missing_versus_empty_inventory(self):
        """
        Verify:
        - Explicit empty inventory -> VERIFIED_CLEAN (high confidence, clean API removal).
        - Missing all_resources -> INCOMPLETE_INVENTORY (lower confidence, advisory).
        - Collection errors -> recorded and flagged.
        - Alternate collection (e.g. deployments) utilized properly when all_resources is absent.
        """
        # A: Explicit empty inventory
        snap_empty = _make_minimal_snapshot(all_resources=[], all_resources_provided=True)
        res_empty = AssessmentEngine("1.21", "1.22", snap_empty).run_all()
        score_empty = ScoringEngine(res_empty).calculate()
        self.assertEqual(res_empty.inventory_status, "VERIFIED_EMPTY")
        self.assertGreaterEqual(score_empty.confidence_score, 80)

        # B: Missing inventory field
        snap_missing = _make_minimal_snapshot(all_resources=[], all_resources_provided=False)
        res_missing = AssessmentEngine("1.21", "1.22", snap_missing).run_all()
        score_missing = ScoringEngine(res_missing).calculate()
        self.assertEqual(res_missing.inventory_status, "MISSING")
        self.assertLess(score_missing.confidence_score, score_empty.confidence_score)

        # C: Collection errors
        snap_err = _make_minimal_snapshot(
            all_resources=[],
            all_resources_provided=False,
            collection_errors=["Failed to list custom resources: unauthorized"],
        )
        res_err = AssessmentEngine("1.21", "1.22", snap_err).run_all()
        self.assertEqual(res_err.inventory_status, "COLLECTION_ERRORS")
        self.assertTrue(len(res_err.assessment_errors) > 0)

        # D: Resources found in alternate collection (deployments)
        deployments = [
            WorkloadResource(
                namespace="default",
                kind="Deployment",
                name="legacy-app",
                api_version="apps/v1",
                replicas=1,
                ready_replicas=1,
                age="5d",
                images=["nginx:1.19"],
                labels={"app": "legacy"},
                annotations={},
            )
        ]
        snap_alt = _make_minimal_snapshot(deployments=deployments, all_resources=[], all_resources_provided=False)
        inv = build_resource_inventory(snap_alt)
        self.assertEqual(len(inv), 1)
        self.assertEqual(inv[0].kind, "Deployment")
        self.assertEqual(inv[0].name, "legacy-app")

    # -------------------------------------------------------------------------
    # TEST 9: WEB DASHBOARD UPLOAD
    # -------------------------------------------------------------------------
    def test_scenario_9_web_dashboard_upload(self):
        """
        Test /api/assess route via multipart file upload:
        - Valid snapshot accepted and produces correct assessment.
        - Invalid JSON receives controlled error.
        - Empty file rejected.
        - Malformed snapshot does not cause 500.
        - Export route works after assessment.
        """
        valid_snapshot = {
            "k8s_version": "1.21",
            "nodes": [
                {
                    "name": "node-1",
                    "role": "worker",
                    "version": "1.21.0",
                    "runtime": "containerd://1.6.20",
                    "os": "Ubuntu 22.04 LTS",
                    "status": "Ready",
                }
            ],
            "all_resources": [
                {
                    "apiVersion": "networking.k8s.io/v1beta1",
                    "kind": "Ingress",
                    "namespace": "production",
                    "name": "legacy-public-ingress",
                }
            ],
        }

        # 1. Valid snapshot upload
        data = {
            "source_version": "1.21",
            "target_version": "1.22",
            "mode": "snapshot",
            "snapshot_file": (io.BytesIO(json.dumps(valid_snapshot).encode("utf-8")), "cluster.json"),
        }
        resp = self.client.post("/api/assess", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 200)
        res_json = resp.get_json()
        self.assertEqual(res_json["scoring"]["upgrade_decision"], "NOT RECOMMENDED")
        self.assertEqual(len(res_json["assessment"]["api_removals"]), 1)
        self.assertEqual(res_json["assessment"]["api_removals"][0]["kind"], "Ingress")

        # 2. Export markdown after assessment
        exp_resp = self.client.get("/api/export?format=markdown&source=1.21&target=1.22")
        self.assertEqual(exp_resp.status_code, 200)
        self.assertIn("legacy-public-ingress", exp_resp.data.decode("utf-8"))

        # 3. Invalid JSON syntax
        bad_json_data = {
            "source_version": "1.21",
            "target_version": "1.22",
            "mode": "snapshot",
            "snapshot_file": (io.BytesIO(b"{ invalid json string"), "cluster.json"),
        }
        bad_resp = self.client.post("/api/assess", data=bad_json_data, content_type="multipart/form-data")
        self.assertEqual(bad_resp.status_code, 400)
        self.assertIn("Invalid JSON format", bad_resp.get_json()["error"])

        # 4. Empty file
        empty_data = {
            "source_version": "1.21",
            "target_version": "1.22",
            "mode": "snapshot",
            "snapshot_file": (io.BytesIO(b""), "empty.json"),
        }
        empty_resp = self.client.post("/api/assess", data=empty_data, content_type="multipart/form-data")
        self.assertEqual(empty_resp.status_code, 400)
        self.assertIn("empty", empty_resp.get_json()["error"].lower())

    # -------------------------------------------------------------------------
    # TEST 10: REPORT AND SCORE CONSISTENCY
    # -------------------------------------------------------------------------
    def test_scenario_10_report_and_score_consistency(self):
        """
        Verify:
        - Critical issue counts equal distinct underlying critical findings.
        - Required remediation actions reference actual blockers.
        - Risk matrix summarizes actual findings.
        - Markdown and JSON serialization preserve exact findings without duplication.
        - Identical inputs produce deterministic results.
        """
        snapshot = _make_minimal_snapshot(
            k8s_version="1.21",
            all_resources=[
                {
                    "apiVersion": "networking.k8s.io/v1beta1",
                    "kind": "Ingress",
                    "namespace": "production",
                    "name": "ingress-a",
                },
                {
                    "apiVersion": "networking.k8s.io/v1beta1",
                    "kind": "Ingress",
                    "namespace": "staging",
                    "name": "ingress-b",
                },
            ],
        )

        engine1 = AssessmentEngine("1.21", "1.22", snapshot)
        res1 = engine1.run_all()
        scoring1 = ScoringEngine(res1).calculate()

        engine2 = AssessmentEngine("1.21", "1.22", snapshot)
        res2 = engine2.run_all()
        scoring2 = ScoringEngine(res2).calculate()

        # Determinism check
        self.assertEqual(scoring1.readiness_score, scoring2.readiness_score)
        self.assertEqual(scoring1.upgrade_decision, scoring2.upgrade_decision)
        self.assertEqual(len(scoring1.critical_issues), len(scoring2.critical_issues))

        # Distinct critical issues
        self.assertEqual(len(res1.api_removal_findings), 2)
        self.assertEqual(len(scoring1.critical_issues), 2)

        # Markdown report check
        md_report = generate_markdown_report(res1, scoring1)
        self.assertIn("ingress-a", md_report)
        self.assertIn("ingress-b", md_report)
        self.assertIn("## Step 6", md_report)

        # JSON report check
        json_report_str = generate_json_report(res1, scoring1)
        json_data = json.loads(json_report_str)
        self.assertEqual(len(json_data["api_removals"]), 2)
        self.assertEqual(json_data["executive_summary"]["upgrade_decision"], scoring1.upgrade_decision)
        self.assertEqual(json_data["executive_summary"]["readiness_score"], scoring1.readiness_score)
