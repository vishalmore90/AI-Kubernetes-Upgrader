"""
scoring_matrix.py
=================
Risk Matrix builder, Readiness Score calculator, and Confidence Score calculator.

Implements the 10-area Risk Matrix, 0-100 Readiness Score, and Confidence Score
per the specification.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ai_k8s_upgrader.assessment_engine import (
    AssessmentResult, Status, Severity, IssueCategory
)


# ---------------------------------------------------------------------------
# Risk Matrix Entry
# ---------------------------------------------------------------------------

@dataclass
class RiskMatrixEntry:
    area: str
    status: str     # PASS | GOOD | WARNING | HIGH RISK | CRITICAL
    severity: str   # Critical | High | Medium | Low
    explanation: str


@dataclass
class ScoringResult:
    """Complete scoring results including risk matrix, scores, and decision."""
    risk_matrix: List[RiskMatrixEntry] = field(default_factory=list)
    readiness_score: int = 0
    readiness_label: str = ""
    confidence_score: int = 0
    confidence_factors: List[str] = field(default_factory=list)
    upgrade_decision: str = ""    # APPROVED | CONDITIONAL | NOT RECOMMENDED
    critical_issues: List[str] = field(default_factory=list)
    high_risks: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    required_actions_before: List[str] = field(default_factory=list)
    recommended_upgrade_order: List[str] = field(default_factory=list)
    post_upgrade_validations: List[str] = field(default_factory=list)
    final_recommendation: str = ""


# ---------------------------------------------------------------------------
# Status Severity Mapping
# ---------------------------------------------------------------------------

STATUS_WEIGHTS = {
    Status.PASS: 0,
    Status.GOOD: 0,
    Status.WARNING: 10,
    Status.HIGH_RISK: 25,
    Status.CRITICAL: 50,
}

STATUS_SEVERITY_MAP = {
    Status.PASS: Severity.LOW,
    Status.GOOD: Severity.LOW,
    Status.WARNING: Severity.MEDIUM,
    Status.HIGH_RISK: Severity.HIGH,
    Status.CRITICAL: Severity.CRITICAL,
}


# ---------------------------------------------------------------------------
# Scoring Engine
# ---------------------------------------------------------------------------

class ScoringEngine:
    """Calculates all scores and the upgrade decision from AssessmentResult."""

    def __init__(self, result: AssessmentResult):
        self.result = result

    def calculate(self) -> ScoringResult:
        scoring = ScoringResult()

        # Build Risk Matrix
        scoring.risk_matrix = self._build_risk_matrix()

        # Calculate Readiness Score
        scoring.readiness_score, scoring.readiness_label = self._calculate_readiness(scoring.risk_matrix)

        # Calculate Confidence Score
        scoring.confidence_score, scoring.confidence_factors = self._calculate_confidence()

        # Determine Upgrade Decision
        scoring.upgrade_decision = self._determine_decision(scoring.readiness_score)

        # Generate Executive Summary components
        scoring.critical_issues = self._collect_critical_issues()
        scoring.high_risks = self._collect_high_risks()
        scoring.warnings = self._collect_warnings()
        scoring.required_actions_before = self._generate_required_actions()
        scoring.recommended_upgrade_order = self._generate_upgrade_order()
        scoring.post_upgrade_validations = self._generate_post_upgrade_validations()
        scoring.final_recommendation = self._generate_final_recommendation(scoring)

        return scoring

    def _build_risk_matrix(self) -> List[RiskMatrixEntry]:
        """Build the 10-area risk matrix from assessment results."""
        result = self.result
        matrix = []

        # 1. APIs
        critical_apis = [f for f in result.api_removal_findings if f.severity == Severity.CRITICAL]
        deprecated_count = len(result.deprecated_api_findings)
        if critical_apis:
            api_status = Status.CRITICAL
            api_explanation = (
                f"{len(critical_apis)} removed API(s) detected in active use. "
                + ", ".join([f"{f.kind} ({f.current_api})" for f in critical_apis[:3]])
            )
        elif deprecated_count > 0:
            api_status = Status.WARNING
            api_explanation = f"{deprecated_count} deprecated API(s) require migration planning."
        else:
            api_status = Status.PASS
            api_explanation = "All cluster APIs compatible with target version."
        matrix.append(RiskMatrixEntry("APIs", api_status, STATUS_SEVERITY_MAP[api_status], api_explanation))

        # 2. CRDs
        breaking_crds = [f for f in result.crd_compatibility_findings if f.will_break]
        warned_crds = [f for f in result.crd_compatibility_findings if not f.will_break]
        if breaking_crds:
            crd_status = Status.HIGH_RISK
            crd_explanation = (
                f"{len(breaking_crds)} CRD(s) may break after upgrade: "
                + ", ".join([f.crd_name for f in breaking_crds[:3]])
            )
        elif warned_crds:
            crd_status = Status.WARNING
            crd_explanation = f"{len(warned_crds)} CRD(s) have warnings. No breaking issues confirmed."
        elif result.snapshot.crds:
            crd_status = Status.GOOD
            crd_explanation = f"{len(result.snapshot.crds)} CRD(s) appear compatible with target version."
        else:
            crd_status = Status.PASS
            crd_explanation = "No CRDs installed."
        matrix.append(RiskMatrixEntry("CRDs", crd_status, STATUS_SEVERITY_MAP[crd_status], crd_explanation))

        # 3. Controllers
        critical_ctls = [f for f in result.controller_compatibility_findings if f.status == Status.CRITICAL]
        high_ctls = [f for f in result.controller_compatibility_findings if f.status == Status.HIGH_RISK]
        unknown_ctls = [f for f in result.controller_compatibility_findings if "UNKNOWN" in f.supported_k8s_versions]
        if critical_ctls:
            ctl_status = Status.CRITICAL
            ctl_explanation = (
                f"{len(critical_ctls)} controller(s) MUST be upgraded before K8s upgrade: "
                + ", ".join([f.controller_name for f in critical_ctls])
            )
        elif high_ctls:
            ctl_status = Status.HIGH_RISK
            ctl_explanation = (
                f"{len(high_ctls)} controller(s) incompatible with K8s {result.target_version}: "
                + ", ".join([f.controller_name for f in high_ctls])
            )
        elif unknown_ctls:
            ctl_status = Status.WARNING
            ctl_explanation = f"{len(unknown_ctls)} controller(s) with unknown compatibility. Manual review required."
        elif result.controller_compatibility_findings:
            ctl_status = Status.GOOD
            ctl_explanation = f"All {len(result.controller_compatibility_findings)} detected controller(s) verified compatible."
        else:
            ctl_status = Status.WARNING
            ctl_explanation = "No controllers detected. Verify manually."
        matrix.append(RiskMatrixEntry("Controllers", ctl_status, STATUS_SEVERITY_MAP[ctl_status], ctl_explanation))

        # 4. Webhooks
        blocking_wh = [f for f in result.webhook_findings if f.can_block_workloads]
        failing_wh = [f for f in result.webhook_findings if f.can_fail_after_upgrade]
        if failing_wh:
            wh_status = Status.HIGH_RISK
            wh_explanation = (
                f"{len(failing_wh)} webhook(s) may fail after upgrade. "
                + ", ".join([f.name for f in failing_wh[:3]])
            )
        elif blocking_wh:
            wh_status = Status.WARNING
            wh_explanation = (
                f"{len(blocking_wh)} webhook(s) with FailurePolicy=Fail. "
                "Ensure webhook endpoints remain available during upgrade."
            )
        elif result.webhook_findings:
            wh_status = Status.WARNING
            wh_explanation = f"{len(result.webhook_findings)} webhook(s) have minor issues. Review configuration."
        elif (result.snapshot.validating_webhooks or result.snapshot.mutating_webhooks):
            wh_status = Status.GOOD
            wh_explanation = "Webhooks configured without critical issues."
        else:
            wh_status = Status.PASS
            wh_explanation = "No admission webhooks installed."
        matrix.append(RiskMatrixEntry("Webhooks", wh_status, STATUS_SEVERITY_MAP[wh_status], wh_explanation))

        # 5. Networking
        matrix.append(RiskMatrixEntry(
            "Networking",
            result.networking_status,
            STATUS_SEVERITY_MAP.get(result.networking_status, Severity.MEDIUM),
            result.networking_reason[:200] if result.networking_reason else "Networking not analyzed.",
        ))

        # 6. Storage
        matrix.append(RiskMatrixEntry(
            "Storage",
            result.storage_status,
            STATUS_SEVERITY_MAP.get(result.storage_status, Severity.MEDIUM),
            result.storage_reason[:200] if result.storage_reason else "Storage not analyzed.",
        ))

        # 7. Security
        matrix.append(RiskMatrixEntry(
            "Security",
            result.security_status,
            STATUS_SEVERITY_MAP.get(result.security_status, Severity.MEDIUM),
            result.security_reason[:200] if result.security_reason else "Security not analyzed.",
        ))

        # 8. Runtime
        runtime_criticals = [i for i in result.runtime_issues if "CRITICAL" in i]
        runtime_warnings = [i for i in result.runtime_issues if "CRITICAL" not in i]
        if runtime_criticals:
            rt_status = Status.CRITICAL
            rt_explanation = "; ".join(runtime_criticals[:2])
        elif runtime_warnings:
            rt_status = Status.WARNING
            rt_explanation = "; ".join(runtime_warnings[:2])
        else:
            rt_status = Status.GOOD
            rt_explanation = "Container runtime versions appear compatible with target Kubernetes version."
        matrix.append(RiskMatrixEntry("Runtime", rt_status, STATUS_SEVERITY_MAP[rt_status], rt_explanation))

        # 9. Nodes
        not_ready = [n for n in result.snapshot.nodes if n.status != "Ready"]
        pressure_issues = result.resource_pressure_issues
        if not_ready:
            node_status = Status.HIGH_RISK
            node_explanation = (
                f"{len(not_ready)} node(s) not Ready: " +
                ", ".join([n.name for n in not_ready[:3]])
            )
        elif pressure_issues:
            node_status = Status.WARNING
            node_explanation = f"{len(pressure_issues)} node resource pressure issue(s) detected."
        else:
            node_status = Status.GOOD
            node_explanation = (
                f"All {len(result.snapshot.nodes)} node(s) Ready. "
                f"{result.snapshot.control_plane_count} control-plane, {result.snapshot.worker_count} workers."
            )
        matrix.append(RiskMatrixEntry("Nodes", node_status, STATUS_SEVERITY_MAP[node_status], node_explanation))

        # 10. Control Plane
        cp_criticals = [r for r in result.incompatibility_reports
                        if r.severity == Severity.CRITICAL and "Control Plane" in r.when_it_will_break]
        if cp_criticals:
            cp_status = Status.CRITICAL
            cp_explanation = (
                f"{len(cp_criticals)} critical issue(s) will impact control plane upgrade: "
                + "; ".join([r.what_will_break for r in cp_criticals[:2]])
            )
        elif not result.snapshot.ha_control_plane and result.snapshot.control_plane_count > 0:
            cp_status = Status.WARNING
            cp_explanation = (
                "Non-HA control plane (single control-plane node). "
                "Upgrade will cause brief API server unavailability."
            )
        elif result.snapshot.control_plane_count > 0:
            cp_status = Status.GOOD
            cp_explanation = (
                f"HA control plane with {result.snapshot.control_plane_count} node(s). "
                "Rolling upgrade should maintain availability."
            )
        else:
            cp_status = Status.WARNING
            cp_explanation = "Control plane topology unknown. Manual verification required."
        matrix.append(RiskMatrixEntry("Control Plane", cp_status, STATUS_SEVERITY_MAP[cp_status], cp_explanation))

        return matrix

    def _calculate_readiness(self, matrix: List[RiskMatrixEntry]) -> Tuple[int, str]:
        """
        Calculate readiness score (0-100) from risk matrix.
        Base: 100, deduct points per status severity.
        """
        score = 100
        for entry in matrix:
            deduction = STATUS_WEIGHTS.get(entry.status, 0)
            score -= deduction

        # Additional deductions for incompatibility reports
        critical_incompat = [r for r in self.result.incompatibility_reports
                             if r.severity == Severity.CRITICAL]
        high_incompat = [r for r in self.result.incompatibility_reports
                        if r.severity == Severity.HIGH]

        score -= len(critical_incompat) * 15
        score -= len(high_incompat) * 5

        # PSP removal is a hard -30 if detected
        if self.result.snapshot.pod_security_policies and hasattr(self.result.snapshot, 'k8s_version'):
            from ai_k8s_upgrader.k8s_database import version_gte
            if version_gte(self.result.target_version, "1.25"):
                score -= 30

        score = max(0, min(100, score))

        if score >= 90:
            label = "Ready"
        elif score >= 75:
            label = "Ready with remediation"
        elif score >= 50:
            label = "Significant risk"
        else:
            label = "Not recommended"

        return score, label

    def _calculate_confidence(self) -> Tuple[int, List[str]]:
        """Calculate confidence score based on available evidence."""
        score = 100
        factors = []

        # Snapshot mode penalty
        if self.result.snapshot.source_mode == "snapshot":
            score -= 5
            factors.append("-5: Analysis based on cluster snapshot (not live cluster)")
        elif self.result.snapshot.source_mode == "sample":
            score -= 20
            factors.append("-20: Analysis based on generated sample data (not real cluster)")

        # Collection errors
        if self.result.snapshot.collection_errors:
            penalty = min(20, len(self.result.snapshot.collection_errors) * 5)
            score -= penalty
            factors.append(f"-{penalty}: {len(self.result.snapshot.collection_errors)} data collection error(s)")

        # No workloads detected
        total_workloads = (len(self.result.snapshot.deployments) +
                           len(self.result.snapshot.statefulsets) +
                           len(self.result.snapshot.daemonsets))
        if total_workloads == 0:
            score -= 10
            factors.append("-10: No workloads detected (may be incomplete collection)")

        # No controllers detected
        if not self.result.detected_controllers:
            score -= 10
            factors.append("-10: No controllers detected (may have unverified operators)")

        # Unknown controllers
        unknown_ctls = [f for f in self.result.controller_compatibility_findings
                        if "UNKNOWN" in f.supported_k8s_versions]
        if unknown_ctls:
            penalty = min(15, len(unknown_ctls) * 5)
            score -= penalty
            factors.append(f"-{penalty}: {len(unknown_ctls)} controller(s) with unknown compatibility")

        # No CRDs detected when there should be
        if not self.result.snapshot.crds and self.result.detected_controllers:
            score -= 5
            factors.append("-5: Controllers detected but no CRDs found (possibly incomplete collection)")

        # Version information missing
        if not self.result.snapshot.k8s_version:
            score -= 15
            factors.append("-15: Kubernetes version not available from cluster")

        # No node information
        if not self.result.snapshot.nodes:
            score -= 10
            factors.append("-10: No node information available")

        # Positive factors
        if self.result.snapshot.nodes:
            factors.append(f"+: Node data available ({len(self.result.snapshot.nodes)} nodes)")
        if self.result.snapshot.crds:
            factors.append(f"+: CRD data available ({len(self.result.snapshot.crds)} CRDs)")
        if self.result.controller_compatibility_findings:
            verified_count = len([f for f in self.result.controller_compatibility_findings
                                   if f.category == IssueCategory.VERIFIED])
            factors.append(f"+: {verified_count} controller(s) verified against compatibility matrix")

        score = max(10, min(100, score))
        return score, factors

    def _determine_decision(self, readiness_score: int) -> str:
        """Determine upgrade decision based on readiness score."""
        if readiness_score >= 90:
            return "APPROVED"
        elif readiness_score >= 50:
            return "CONDITIONAL"
        else:
            return "NOT RECOMMENDED"

    def _collect_critical_issues(self) -> List[str]:
        """Collect all critical issues for executive summary."""
        issues = []

        # PSP removal
        if self.result.snapshot.pod_security_policies:
            from ai_k8s_upgrader.k8s_database import version_gte
            if version_gte(self.result.target_version, "1.25"):
                issues.append(
                    f"PodSecurityPolicy removal: {len(self.result.snapshot.pod_security_policies)} PSP(s) in use - "
                    f"ALL workloads will fail to start after upgrade"
                )

        # API removals
        for f in self.result.api_removal_findings:
            if f.severity == Severity.CRITICAL:
                issues.append(f"API Removal: {f.kind} using {f.current_api} will be removed in K8s {f.removal_version}")

        # Incompatible controllers (must-upgrade-before)
        for f in self.result.controller_compatibility_findings:
            if f.status == Status.CRITICAL:
                issues.append(f"Controller incompatibility: {f.controller_name} must be upgraded BEFORE Kubernetes upgrade")

        # Runtime issues
        for i in self.result.runtime_issues:
            if "CRITICAL" in i:
                issues.append(i)

        return issues[:10]  # Cap at 10

    def _collect_high_risks(self) -> List[str]:
        """Collect high risk items for executive summary."""
        risks = []

        for f in self.result.controller_compatibility_findings:
            if f.status == Status.HIGH_RISK:
                risks.append(f"Controller: {f.controller_name} - {f.target_compatibility}")

        for f in self.result.crd_compatibility_findings:
            if f.will_break:
                risks.append(f"CRD: {f.crd_name} may become unreadable after upgrade")

        for f in self.result.webhook_findings:
            if f.can_fail_after_upgrade:
                risks.append(f"Webhook: {f.name} ({f.kind}) may fail after upgrade")

        if self.result.networking_can_break:
            risks.append(f"Networking: {self.result.networking_issues[0] if self.result.networking_issues else 'CNI compatibility issue'}")

        if self.result.storage_can_break:
            risks.append(f"Storage: {self.result.storage_issues[0] if self.result.storage_issues else 'Storage compatibility issue'}")

        for change in self.result.behavioral_changes:
            if change.severity in [Severity.HIGH, Severity.CRITICAL]:
                risks.append(f"Behavioral change in v{change.version}: {change.title}")

        return risks[:10]

    def _collect_warnings(self) -> List[str]:
        """Collect warnings for executive summary."""
        warnings = []

        for f in self.result.deprecated_api_findings:
            warnings.append(f"Deprecated API: {f.object_name} ({f.api_version}) - planned removal in {f.planned_removal_version}")

        for f in self.result.webhook_findings:
            if not f.can_fail_after_upgrade and f.can_block_workloads:
                warnings.append(f"Webhook: {f.name} has FailurePolicy=Fail - ensure endpoint stability during upgrade")

        for change in self.result.behavioral_changes:
            if change.severity == Severity.MEDIUM:
                warnings.append(f"v{change.version} behavioral change: {change.title}")

        if self.result.resource_pressure_issues:
            warnings.extend(self.result.resource_pressure_issues[:3])

        if not self.result.snapshot.ha_control_plane:
            warnings.append("Non-HA control plane: upgrade will cause brief API server downtime")

        return warnings[:10]

    def _generate_required_actions(self) -> List[str]:
        """Generate ordered list of required actions before upgrade."""
        actions = []
        priority = 1

        # PSP migration
        if self.result.snapshot.pod_security_policies:
            from ai_k8s_upgrader.k8s_database import version_gte
            if version_gte(self.result.target_version, "1.25"):
                actions.append(
                    f"{priority}. CRITICAL: Migrate all PodSecurityPolicy objects to Pod Security Admission or Kyverno/OPA. "
                    f"Test with PSA labels before removing PSPs."
                )
                priority += 1

        # Docker runtime migration
        for node in self.result.snapshot.nodes:
            if "docker" in node.container_runtime.lower() and "containerd" not in node.container_runtime.lower():
                from ai_k8s_upgrader.k8s_database import version_gte
                if version_gte(self.result.target_version, "1.24"):
                    actions.append(
                        f"{priority}. CRITICAL: Migrate node '{node.name}' from Docker to containerd or CRI-O "
                        f"(dockershim removed in K8s 1.24)."
                    )
                    priority += 1
                    break

        # Must-upgrade-before controllers
        for f in self.result.controller_compatibility_findings:
            if f.status == Status.CRITICAL and "Before" in f.upgrade_timing:
                actions.append(
                    f"{priority}. Upgrade {f.controller_name} to a version compatible with K8s {self.result.target_version} "
                    f"BEFORE upgrading Kubernetes."
                )
                priority += 1

        # API migration
        for f in self.result.api_removal_findings[:3]:
            actions.append(
                f"{priority}. Migrate {f.kind} resources from {f.current_api} to {f.replacement_api}."
            )
            priority += 1

        # Backup
        actions.append(
            f"{priority}. Take a full etcd backup and workload state snapshot (use Velero if available) before starting upgrade."
        )
        priority += 1

        # Test on non-prod
        actions.append(
            f"{priority}. Test the upgrade on a non-production cluster with identical configuration first."
        )

        return actions

    def _generate_upgrade_order(self) -> List[str]:
        """Generate recommended upgrade order."""
        order = []

        # Must-before controllers
        must_before = [f for f in self.result.controller_compatibility_findings
                       if "Before" in f.upgrade_timing]
        for f in must_before:
            order.append(f"Upgrade {f.controller_name} to K8s {self.result.target_version}-compatible version")

        # Standard upgrade order
        order.extend([
            "Upgrade control plane components (API server, controller-manager, scheduler) - rolling if HA",
            "Verify control plane health (kubectl get nodes, API server logs)",
            "Upgrade kubelet and kubectl on control-plane nodes",
            "Upgrade cluster-autoscaler (if deployed) to match target K8s version",
            "Upgrade worker nodes one at a time (cordon, drain, upgrade kubelet, uncordon)",
            "Upgrade CNI plugin (if version update required)",
            "Upgrade remaining operators/controllers (cert-manager, ingress-nginx, etc.)",
        ])

        return order

    def _generate_post_upgrade_validations(self) -> List[str]:
        """Generate post-upgrade validation checklist."""
        validations = [
            "1. Verify all nodes are Ready: kubectl get nodes",
            "2. Verify all system pods are running: kubectl get pods -n kube-system",
            "3. Check for pending/failed pods cluster-wide: kubectl get pods -A | grep -v Running",
            "4. Validate CRD resources are accessible: kubectl get <crd-name> -A",
            "5. Verify webhook endpoints are responding (check admission controller logs)",
            "6. Run end-to-end smoke test: deploy test workload, verify scheduling, networking, storage",
            "7. Check cluster-autoscaler scaling behavior (if deployed)",
            "8. Verify ingress rules are routing traffic correctly",
            "9. Check monitoring dashboards for anomalies (Prometheus/Grafana)",
            "10. Verify DNS resolution within cluster: kubectl run test --image=busybox -- nslookup kubernetes",
        ]

        # Add PSP-specific validation
        if self.result.snapshot.pod_security_policies:
            validations.append(
                "11. Verify all previously PSP-controlled workloads are running without PSP admission controller"
            )

        return validations

    def _generate_final_recommendation(self, scoring: ScoringResult) -> str:
        """Generate the final detailed recommendation."""
        score = scoring.readiness_score
        decision = scoring.upgrade_decision
        criticals = len(scoring.critical_issues)
        high_risks = len(scoring.high_risks)

        if decision == "APPROVED":
            return (
                f"The cluster appears ready for upgrade from K8s {self.result.source_version} to "
                f"{self.result.target_version} with a readiness score of {score}/100. "
                f"No critical blockers detected. Proceed with the recommended upgrade order, "
                f"monitor cluster health at each step, and complete all post-upgrade validations. "
                f"Ensure etcd backup is taken before starting."
            )
        elif decision == "CONDITIONAL":
            return (
                f"The upgrade from K8s {self.result.source_version} to {self.result.target_version} is "
                f"CONDITIONAL with a readiness score of {score}/100. "
                f"{criticals} critical issue(s) and {high_risks} high-risk item(s) must be addressed. "
                f"Complete ALL required actions before starting the upgrade. "
                f"Test on a non-production cluster first. "
                f"Follow the recommended upgrade order exactly. "
                f"Have a rollback plan (etcd backup restore) ready before proceeding."
            )
        else:
            return (
                f"The upgrade from K8s {self.result.source_version} to {self.result.target_version} is "
                f"NOT RECOMMENDED at this time with a readiness score of {score}/100. "
                f"{criticals} critical issue(s) and {high_risks} high-risk item(s) must be resolved. "
                f"Resolving these issues may significantly increase the readiness score. "
                f"DO NOT proceed with the upgrade until all critical issues are remediated and retested. "
                f"Consider upgrading through intermediate versions to reduce risk scope."
            )
