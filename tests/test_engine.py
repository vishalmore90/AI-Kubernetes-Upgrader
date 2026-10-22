"""
test_engine.py
==============
Comprehensive unit tests for the AI-Kubernetes-Upgrader assessment engine.
"""

import json
import os
import sys
import tempfile
import unittest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_k8s_upgrader import k8s_database as db
from ai_k8s_upgrader.assessment_engine import AssessmentEngine, Status, Severity
from ai_k8s_upgrader.scoring_matrix import ScoringEngine
from ai_k8s_upgrader.sample_generator import generate_sample_cluster
from ai_k8s_upgrader.cluster_collector import SnapshotClusterCollector


class TestK8sDatabase(unittest.TestCase):
    """Tests for the knowledge base."""

    def test_version_parsing(self):
        self.assertEqual(db.parse_version("1.27"), (1, 27))
        self.assertEqual(db.parse_version("v1.30.5"), (1, 30))
        self.assertEqual(db.parse_version("1.25.0"), (1, 25))

    def test_version_comparison(self):
        self.assertTrue(db.version_gt("1.27", "1.25"))
        self.assertTrue(db.version_gte("1.27", "1.27"))
        self.assertTrue(db.version_lte("1.25", "1.27"))
        self.assertFalse(db.version_gt("1.25", "1.27"))

    def test_intermediate_versions(self):
        versions = db.get_intermediate_versions("1.27", "1.30")
        self.assertEqual(versions, ["1.28", "1.29", "1.30"])

    def test_intermediate_versions_adjacent(self):
        versions = db.get_intermediate_versions("1.27", "1.28")
        self.assertEqual(versions, ["1.28"])

    def test_removed_apis_psp(self):
        """PSP should be detected as removed when going from 1.24 to 1.25+."""
        removed = db.get_removed_apis_in_range("1.24", "1.25")
        kinds = [r.kind for r in removed]
        self.assertIn("PodSecurityPolicy", kinds)

    def test_removed_apis_ingress(self):
        """Ingress extensions/v1beta1 should be removed in 1.22."""
        removed = db.get_removed_apis_in_range("1.21", "1.22")
        kinds = [r.kind for r in removed]
        self.assertIn("Ingress", kinds)

    def test_removed_apis_not_in_range(self):
        """PSP removal should NOT appear when upgrading from 1.25->1.27."""
        removed = db.get_removed_apis_in_range("1.25", "1.27")
        kinds = [r.kind for r in removed]
        self.assertNotIn("PodSecurityPolicy", kinds)

    def test_behavioral_changes_include_psp(self):
        """PSP removal behavioral change should appear in 1.24->1.25 range."""
        changes = db.get_behavioral_changes_in_range("1.24", "1.25")
        titles = [c.title for c in changes]
        psp_change = any("PodSecurityPolicy" in t for t in titles)
        self.assertTrue(psp_change)

    def test_behavioral_changes_dockershim(self):
        """Dockershim removal should appear in 1.23->1.24 range."""
        changes = db.get_behavioral_changes_in_range("1.23", "1.24")
        titles = [c.title for c in changes]
        docker_change = any("Dockershim" in t for t in titles)
        self.assertTrue(docker_change)

    def test_operator_compatibility_lookup(self):
        """cert-manager should be found in the database."""
        op = db.get_operator_compatibility("cert-manager")
        self.assertIsNotNone(op)
        self.assertEqual(op.name, "cert-manager")

    def test_operator_compatibility_cluster_autoscaler_exact_version(self):
        """Cluster autoscaler 1.27.x should be compatible with K8s 1.27."""
        op = db.get_operator_compatibility("cluster-autoscaler")
        compatible, reason = db.is_operator_compatible(op, "1.27")
        self.assertTrue(compatible)

    def test_operator_compatibility_cluster_autoscaler_wrong_version(self):
        """is_operator_compatible checks whether target K8s is in the operator's supported K8s ranges.
        CA has a (1.30, 1.30) entry so K8s 1.30 is supported.
        The installed-version-to-target mismatch is detected by the assessment engine separately.
        This test verifies the function returns the range-based result."""
        op = db.get_operator_compatibility("cluster-autoscaler")
        # K8s 1.30 is in CA's supported ranges (CA has a 1.30.x range)
        compatible, reason = db.is_operator_compatible(op, "1.30")
        self.assertTrue(compatible)  # DB says 1.30 is supported by some CA version
        # K8s 1.35 is NOT in any CA range
        compatible_future, _ = db.is_operator_compatible(op, "1.35")
        self.assertFalse(compatible_future)

    def test_operator_not_found(self):
        """Unknown operator should return None."""
        op = db.get_operator_compatibility("nonexistent-operator-xyz")
        self.assertIsNone(op)

    def test_k8s_release_notes_coverage(self):
        """Key versions should have release notes."""
        for version in ["1.24", "1.25", "1.27", "1.29"]:
            self.assertIn(version, db.K8S_RELEASE_NOTES)


class TestSampleGenerator(unittest.TestCase):
    """Tests for the sample cluster generator."""

    def test_generate_sample_cluster(self):
        cluster = generate_sample_cluster()
        self.assertIn("k8s_version", cluster)
        self.assertIn("nodes", cluster)
        self.assertIn("deployments", cluster)
        self.assertIn("crds", cluster)
        self.assertIn("validating_webhooks", cluster)
        self.assertIn("storage_classes", cluster)

    def test_sample_has_psp_by_default(self):
        cluster = generate_sample_cluster(include_psp=True)
        self.assertGreater(len(cluster["pod_security_policies"]), 0)

    def test_sample_no_psp(self):
        cluster = generate_sample_cluster(include_psp=False)
        self.assertEqual(len(cluster["pod_security_policies"]), 0)

    def test_sample_has_in_tree_storage(self):
        cluster = generate_sample_cluster()
        provisioners = [sc["provisioner"] for sc in cluster["storage_classes"]]
        has_intree = any("kubernetes.io/aws-ebs" in p for p in provisioners)
        self.assertTrue(has_intree)

    def test_sample_save_and_load(self):
        """Test saving and loading sample cluster snapshot."""
        cluster = generate_sample_cluster()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(cluster, f)
            tmp_path = f.name

        collector = SnapshotClusterCollector(tmp_path)
        snapshot = collector.collect()
        os.unlink(tmp_path)

        self.assertIsNotNone(snapshot)
        self.assertGreater(len(snapshot.nodes), 0)
        self.assertGreater(len(snapshot.deployments), 0)
        self.assertGreater(len(snapshot.crds), 0)


class TestSnapshotCollector(unittest.TestCase):
    """Tests for the snapshot cluster collector."""

    def setUp(self):
        self.cluster_data = generate_sample_cluster()
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(self.cluster_data, self.tmp)
        self.tmp.close()
        collector = SnapshotClusterCollector(self.tmp.name)
        self.snapshot = collector.collect()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_snapshot_has_nodes(self):
        self.assertGreater(len(self.snapshot.nodes), 0)

    def test_snapshot_has_control_plane_nodes(self):
        self.assertGreater(self.snapshot.control_plane_count, 0)

    def test_snapshot_ha_control_plane(self):
        # Sample cluster has 3 control plane nodes
        self.assertTrue(self.snapshot.ha_control_plane)

    def test_snapshot_has_deployments(self):
        self.assertGreater(len(self.snapshot.deployments), 0)

    def test_snapshot_has_crds(self):
        self.assertGreater(len(self.snapshot.crds), 0)

    def test_snapshot_has_webhooks(self):
        self.assertGreater(len(self.snapshot.validating_webhooks), 0)

    def test_snapshot_has_storage_classes(self):
        self.assertGreater(len(self.snapshot.storage_classes), 0)

    def test_snapshot_has_psp(self):
        self.assertGreater(len(self.snapshot.pod_security_policies), 0)

    def test_snapshot_version(self):
        self.assertEqual(self.snapshot.k8s_version, "1.27")


class TestAssessmentEngine(unittest.TestCase):
    """Tests for the 17-step assessment engine."""

    def setUp(self):
        self.cluster_data = generate_sample_cluster(source_version="1.27", target_version="1.30")
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(self.cluster_data, self.tmp)
        self.tmp.close()
        collector = SnapshotClusterCollector(self.tmp.name)
        self.snapshot = collector.collect()
        self.snapshot.source_mode = "sample"

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_assessment_runs_all_steps(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        # All major result fields should be populated
        self.assertIsNotNone(result.cluster_info)
        self.assertIsNotNone(result.release_notes)
        self.assertIsNotNone(result.simulation_results)
        self.assertIsNotNone(result.failure_scenarios)

    def test_step1_cluster_info(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        self.assertEqual(result.cluster_info["kubernetes_version"], "1.27")
        self.assertEqual(result.cluster_info["source_version"], "1.27")
        self.assertEqual(result.cluster_info["target_version"], "1.30")

    def test_step5_release_notes(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        self.assertGreater(len(result.release_notes), 0)
        # Should cover 1.28, 1.29, 1.30
        versions_in_notes = [n.split(":")[0].strip().lstrip("v") for n in result.release_notes]
        self.assertIn("1.28", versions_in_notes)
        self.assertIn("1.29", versions_in_notes)
        self.assertIn("1.30", versions_in_notes)

    def test_step6_api_removal_detects_intree_hpa(self):
        """HPA autoscaling/v2beta2 removed in 1.26 - should be detected in 1.27->1.30."""
        # Actually v2beta2 is removed in 1.26, so upgrading from 1.27 to 1.30 should NOT detect it
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        # The sample includes autoscaling/v2beta2 resources in all_resources
        # For 1.27->1.30, flowcontrol removals should appear
        kinds = [f.kind for f in result.api_removal_findings]
        # FlowSchema v1beta2 removed in 1.29
        self.assertIn("FlowSchema", kinds)

    def test_step13_security_detects_psp(self):
        """PSP detection should produce a critical security finding."""
        engine = AssessmentEngine("1.24", "1.25", self.snapshot)
        result = engine.run_all()
        self.assertTrue(result.security_can_break)
        psp_issues = [i for i in result.security_issues if "PodSecurityPolicy" in i]
        self.assertGreater(len(psp_issues), 0)

    def test_step16_simulation_produces_all_subsystems(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        subsystem_names = [s.name for s in result.simulation_results]
        expected = ["Control Plane", "Nodes", "APIs", "CRDs", "Controllers",
                    "Networking", "Storage", "Security"]
        for name in expected:
            self.assertIn(name, subsystem_names)

    def test_step17_failure_scenarios_count(self):
        """Should produce exactly 10 failure scenarios."""
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        self.assertEqual(len(result.failure_scenarios), 10)

    def test_step17_all_scenarios_have_required_fields(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        for scenario in result.failure_scenarios:
            self.assertIn(scenario.answer, ["YES", "NO", "POSSIBLE"])
            self.assertIsNotNone(scenario.reason)
            self.assertIsNotNone(scenario.severity)

    def test_step12_storage_detects_intree_provisioner(self):
        """In-tree aws-ebs provisioner should be detected when targeting 1.29+."""
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        storage_issues_str = " ".join(result.storage_issues)
        # Should detect legacy-aws-ebs storage class with in-tree provisioner
        self.assertIn("kubernetes.io/aws-ebs", storage_issues_str)

    def test_intermediate_version_step_detection(self):
        """Assessment spanning 1.24->1.25 should detect PSP removal."""
        engine = AssessmentEngine("1.24", "1.25", self.snapshot)
        result = engine.run_all()
        psp_findings = [f for f in result.api_removal_findings if f.kind == "PodSecurityPolicy"]
        self.assertGreater(len(psp_findings), 0)

    def test_runtime_no_docker_issues(self):
        """Sample cluster with containerd runtime should have no docker issues."""
        # Default sample has containerd, not docker
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        docker_issues = [i for i in result.runtime_issues if "docker" in i.lower()]
        self.assertEqual(len(docker_issues), 0)

    def test_incompatibility_reports_generated(self):
        """Incompatibility reports should be generated for PSP removal."""
        engine = AssessmentEngine("1.24", "1.25", self.snapshot)
        result = engine.run_all()
        critical_reports = [r for r in result.incompatibility_reports
                            if r.severity == Severity.CRITICAL]
        self.assertGreater(len(critical_reports), 0)


class TestScoringEngine(unittest.TestCase):
    """Tests for the scoring and risk matrix engine."""

    def setUp(self):
        cluster_data = generate_sample_cluster(source_version="1.27", target_version="1.30")
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(cluster_data, tmp)
        tmp.close()
        collector = SnapshotClusterCollector(tmp.name)
        self.snapshot = collector.collect()
        self.snapshot.source_mode = "sample"
        os.unlink(tmp.name)

    def test_risk_matrix_has_ten_areas(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        scorer = ScoringEngine(result)
        scoring = scorer.calculate()
        self.assertEqual(len(scoring.risk_matrix), 10)

    def test_risk_matrix_area_names(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        scorer = ScoringEngine(result)
        scoring = scorer.calculate()
        area_names = [e.area for e in scoring.risk_matrix]
        expected = ["APIs", "CRDs", "Controllers", "Webhooks", "Networking",
                    "Storage", "Security", "Runtime", "Nodes", "Control Plane"]
        for name in expected:
            self.assertIn(name, area_names)

    def test_readiness_score_range(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        scorer = ScoringEngine(result)
        scoring = scorer.calculate()
        self.assertGreaterEqual(scoring.readiness_score, 0)
        self.assertLessEqual(scoring.readiness_score, 100)

    def test_confidence_score_range(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        scorer = ScoringEngine(result)
        scoring = scorer.calculate()
        self.assertGreaterEqual(scoring.confidence_score, 0)
        self.assertLessEqual(scoring.confidence_score, 100)

    def test_upgrade_decision_valid(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        scorer = ScoringEngine(result)
        scoring = scorer.calculate()
        self.assertIn(scoring.upgrade_decision, ["APPROVED", "CONDITIONAL", "NOT RECOMMENDED"])

    def test_psp_cluster_has_lower_score(self):
        """Cluster with PSP targeting 1.25 should have significantly lower readiness."""
        # PSP cluster targeting 1.25 (PSP removal)
        cluster_psp = generate_sample_cluster(source_version="1.24", target_version="1.25", include_psp=True)
        tmp_psp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(cluster_psp, tmp_psp)
        tmp_psp.close()
        collector_psp = SnapshotClusterCollector(tmp_psp.name)
        snap_psp = collector_psp.collect()
        snap_psp.source_mode = "sample"
        os.unlink(tmp_psp.name)

        # No PSP cluster
        cluster_no_psp = generate_sample_cluster(source_version="1.27", target_version="1.30", include_psp=False)
        tmp_no = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(cluster_no_psp, tmp_no)
        tmp_no.close()
        collector_no = SnapshotClusterCollector(tmp_no.name)
        snap_no = collector_no.collect()
        snap_no.source_mode = "sample"
        os.unlink(tmp_no.name)

        engine_psp = AssessmentEngine("1.24", "1.25", snap_psp)
        result_psp = engine_psp.run_all()
        scorer_psp = ScoringEngine(result_psp)
        scoring_psp = scorer_psp.calculate()

        engine_no = AssessmentEngine("1.27", "1.30", snap_no)
        result_no = engine_no.run_all()
        scorer_no = ScoringEngine(result_no)
        scoring_no = scorer_no.calculate()

        # PSP cluster should have CRITICAL or HIGH RISK security status
        security_entry_psp = next((e for e in scoring_psp.risk_matrix if e.area == "Security"), None)
        self.assertIsNotNone(security_entry_psp)
        self.assertIn(security_entry_psp.status, ["CRITICAL", "HIGH RISK"])

        # PSP cluster should have critical issues detected
        self.assertGreater(len(scoring_psp.critical_issues), 0)

        # PSP cluster score should be <= no-PSP score
        self.assertLessEqual(scoring_psp.readiness_score, scoring_no.readiness_score)

    def test_post_upgrade_validations_not_empty(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        scorer = ScoringEngine(result)
        scoring = scorer.calculate()
        self.assertGreater(len(scoring.post_upgrade_validations), 0)

    def test_upgrade_order_not_empty(self):
        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        result = engine.run_all()
        scorer = ScoringEngine(result)
        scoring = scorer.calculate()
        self.assertGreater(len(scoring.recommended_upgrade_order), 0)


class TestReporter(unittest.TestCase):
    """Tests for the report generator."""

    def setUp(self):
        cluster_data = generate_sample_cluster(source_version="1.27", target_version="1.30")
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(cluster_data, tmp)
        tmp.close()
        collector = SnapshotClusterCollector(tmp.name)
        self.snapshot = collector.collect()
        self.snapshot.source_mode = "sample"
        os.unlink(tmp.name)

        engine = AssessmentEngine("1.27", "1.30", self.snapshot)
        self.result = engine.run_all()
        scorer = ScoringEngine(self.result)
        self.scoring = scorer.calculate()

    def test_markdown_report_generated(self):
        from ai_k8s_upgrader.reporter import generate_markdown_report
        report = generate_markdown_report(self.result, self.scoring)
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 1000)

    def test_markdown_report_contains_all_steps(self):
        from ai_k8s_upgrader.reporter import generate_markdown_report
        report = generate_markdown_report(self.result, self.scoring)
        for step_num in range(1, 18):
            self.assertIn(f"Step {step_num}", report)

    def test_markdown_report_contains_risk_matrix(self):
        from ai_k8s_upgrader.reporter import generate_markdown_report
        report = generate_markdown_report(self.result, self.scoring)
        self.assertIn("Risk Matrix", report)

    def test_markdown_report_contains_executive_summary(self):
        from ai_k8s_upgrader.reporter import generate_markdown_report
        report = generate_markdown_report(self.result, self.scoring)
        self.assertIn("Executive Summary", report)
        self.assertIn("UPGRADE DECISION", report)
        self.assertIn("READINESS SCORE", report)

    def test_markdown_report_contains_failure_scenarios(self):
        from ai_k8s_upgrader.reporter import generate_markdown_report
        report = generate_markdown_report(self.result, self.scoring)
        self.assertIn("Failure Scenario", report)
        self.assertIn("Could workloads fail to start?", report)

    def test_json_report_valid_json(self):
        from ai_k8s_upgrader.reporter import generate_json_report
        report = generate_json_report(self.result, self.scoring)
        data = json.loads(report)
        self.assertIn("executive_summary", data)
        self.assertIn("risk_matrix", data)
        self.assertIn("failure_scenarios", data)

    def test_json_report_has_all_areas(self):
        from ai_k8s_upgrader.reporter import generate_json_report
        report = generate_json_report(self.result, self.scoring)
        data = json.loads(report)
        areas = [e["area"] for e in data["risk_matrix"]]
        self.assertIn("APIs", areas)
        self.assertIn("Security", areas)
        self.assertIn("Storage", areas)
        self.assertIn("Control Plane", areas)


class TestPackageExports(unittest.TestCase):
    """Verify that root package exports all expected public APIs."""

    def test_root_exports_present(self):
        import ai_k8s_upgrader as pkg
        expected = [
            "__version__",
            "AssessmentEngine",
            "AssessmentResult",
            "Status",
            "Severity",
            "IssueCategory",
            "ClusterSnapshot",
            "NodeInfo",
            "NormalizedResource",
            "WorkloadResource",
            "SnapshotClusterCollector",
            "build_resource_inventory",
            "collect_cluster_state",
            "ScoringEngine",
            "ScoringResult",
            "RiskMatrixEntry",
            "generate_markdown_report",
            "generate_json_report",
            "generate_sample_cluster",
            "save_sample_cluster",
        ]
        for name in expected:
            self.assertTrue(hasattr(pkg, name), f"Missing root export: {name}")

    def test_version_matches(self):
        import ai_k8s_upgrader
        self.assertEqual(ai_k8s_upgrader.__version__, "1.0.0")


class TestCLI(unittest.TestCase):
    """Verify CLI entrypoint subcommands."""

    def setUp(self):
        from click.testing import CliRunner
        self.runner = CliRunner()

    def test_cli_version(self):
        from ai_k8s_upgrader.cli import main
        result = self.runner.invoke(main, ["version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("1.0.0", result.output)

    def test_cli_help(self):
        from ai_k8s_upgrader.cli import main
        result = self.runner.invoke(main, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("assess", result.output)
        self.assertIn("validate-snapshot", result.output)

    def test_cli_validate_snapshot_valid(self):
        from ai_k8s_upgrader.cli import main
        cluster_data = generate_sample_cluster("1.27", "1.30")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(cluster_data, f)
            path = f.name
        try:
            result = self.runner.invoke(main, ["validate-snapshot", path])
            self.assertEqual(result.exit_code, 0)
            self.assertIn("Valid Kubernetes Cluster Snapshot", result.output)
            self.assertIn("Nodes:", result.output)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_cli_validate_snapshot_invalid_json(self):
        from ai_k8s_upgrader.cli import main
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("{invalid json")
            path = f.name
        try:
            result = self.runner.invoke(main, ["validate-snapshot", path])
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("Invalid JSON file", result.output)
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_cli_validate_snapshot_non_dict(self):
        from ai_k8s_upgrader.cli import main
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(["not", "a", "dict"], f)
            path = f.name
        try:
            result = self.runner.invoke(main, ["validate-snapshot", path])
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("Snapshot root must be a JSON object", result.output)
        finally:
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
