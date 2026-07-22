"""
Unit Tests for AI-Kubernetes-Upgrader.
"""

import unittest
import os
import json

from ai_k8s_upgrader.k8s_database import parse_version, format_version, REMOVED_APIS
from ai_k8s_upgrader.sample_generator import generate_sample_cluster_data
from ai_k8s_upgrader.assessment_engine import AssessmentEngine
from ai_k8s_upgrader.scoring_matrix import ScoringMatrixEngine
from ai_k8s_upgrader.reporter import ReportGenerator

class TestKubernetesUpgrader(unittest.TestCase):

    def test_version_parser(self):
        self.assertEqual(parse_version("v1.25.0"), (1, 25))
        self.assertEqual(parse_version("1.29"), (1, 29))
        self.assertEqual(format_version((1, 28)), "v1.28")

    def test_assessment_sample_cluster(self):
        sample_data = generate_sample_cluster_data()
        engine = AssessmentEngine(sample_data, source_version="v1.25.0", target_version="v1.29.0")
        res = engine.run_assessment()

        # Verify step 6 API removals
        removals = res["step6_api_removals"]
        self.assertGreater(len(removals), 0)
        
        # Verify CronJob batch/v1beta1 removal is flagged
        cronjob_flagged = any(r["kind"] == "CronJob" and r["current_api"] == "batch/v1beta1" for r in removals)
        self.assertTrue(cronjob_flagged)

        # Verify HPA autoscaling/v2beta2 removal is flagged
        hpa_flagged = any(r["kind"] == "HorizontalPodAutoscaler" and r["current_api"] == "autoscaling/v2beta2" for r in removals)
        self.assertTrue(hpa_flagged)

    def test_scoring_matrix(self):
        sample_data = generate_sample_cluster_data()
        engine = AssessmentEngine(sample_data, source_version="v1.25.0", target_version="v1.29.0")
        assessment_res = engine.run_assessment()

        scoring = ScoringMatrixEngine(assessment_res)
        scoring_res = scoring.generate_report_sections()

        readiness = scoring_res["readiness_score"]
        decision = scoring_res["executive_summary"]["upgrade_decision"]

        self.assertIn(decision, ["APPROVED", "CONDITIONAL", "NOT RECOMMENDED"])
        self.assertIsInstance(readiness, int)
        self.assertLess(readiness, 100) # Must be lower than 100 due to issues in sample cluster

    def test_report_generation(self):
        sample_data = generate_sample_cluster_data()
        engine = AssessmentEngine(sample_data, source_version="v1.25.0", target_version="v1.29.0")
        assessment_res = engine.run_assessment()

        scoring = ScoringMatrixEngine(assessment_res)
        scoring_res = scoring.generate_report_sections()

        reporter = ReportGenerator(assessment_res, scoring_res)
        md = reporter.generate_markdown()

        self.assertIn("# Kubernetes Upgrade Feasibility, Compatibility, and Risk Assessment Report", md)
        self.assertIn("v1.25.0", md)
        self.assertIn("v1.29.0", md)
        self.assertIn("# Risk Matrix", md)
        self.assertIn("# Readiness Score", md)
        self.assertIn("# Step 17 - Failure Scenario Analysis", md)

if __name__ == "__main__":
    unittest.main()
