"""
assessment_engine.py
====================
The core 17-step Kubernetes Upgrade Assessment Engine.

Implements every assessment step from the specification:
1.  Cluster Info Collection
2.  Workload Inventory
3.  CRD Discovery
4.  Controller/Operator Detection
5.  Release Note Analysis
6.  API Removal Analysis
7.  Deprecated API Analysis
8.  CRD Compatibility Analysis
9.  Controller Compatibility Analysis
10. Webhook Analysis
11. Networking Compatibility
12. Storage Compatibility
13. Security Compatibility
14. Runtime Compatibility
15. Resource Pressure Analysis
16. Upgrade Simulation
17. Failure Scenario Modeling

Output: AssessmentResult dataclass containing all findings.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ai_k8s_upgrader.cluster_collector import (
    ClusterSnapshot, NodeInfo, WorkloadResource, build_resource_inventory, NormalizedResource
)
from ai_k8s_upgrader import k8s_database as db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Status Constants
# ---------------------------------------------------------------------------

class Status:
    PASS = "PASS"
    GOOD = "GOOD"
    WARNING = "WARNING"
    HIGH_RISK = "HIGH RISK"
    CRITICAL = "CRITICAL"


class Severity:
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class IssueCategory:
    VERIFIED = "Verified Issue"
    PROBABLE = "Probable Issue"
    POSSIBLE = "Possible Issue"
    UNKNOWN = "Unknown Risk"


# ---------------------------------------------------------------------------
# Issue / Finding Data Structures
# ---------------------------------------------------------------------------

@dataclass
class APIRemovalFinding:
    namespace: str
    object_name: str
    kind: str
    current_api: str
    removal_version: str
    replacement_api: str
    impact: str
    severity: str
    required_action: str
    category: str = IssueCategory.VERIFIED


@dataclass
class DeprecatedAPIFinding:
    namespace: str
    object_name: str
    api_version: str
    risk_level: str
    planned_removal_version: str
    migration_required: str
    category: str = IssueCategory.VERIFIED


@dataclass
class CRDCompatibilityFinding:
    crd_name: str
    group: str
    kind: str
    issue: str
    will_break: bool
    severity: str
    reason: str
    category: str = IssueCategory.PROBABLE


@dataclass
class ControllerCompatibilityFinding:
    controller_name: str
    installed_version: str
    supported_k8s_versions: str
    target_compatibility: str
    status: str
    upgrade_timing: str
    notes: str
    category: str = IssueCategory.VERIFIED


@dataclass
class WebhookFinding:
    name: str
    kind: str
    failure_policy: str
    side_effects: str
    can_block_workloads: bool
    can_fail_after_upgrade: bool
    severity: str
    reason: str
    category: str = IssueCategory.PROBABLE


@dataclass
class FailureScenario:
    scenario: str
    answer: str           # "YES" | "NO" | "POSSIBLE"
    reason: str
    severity: str
    category: str


@dataclass
class SubsystemStatus:
    name: str
    status: str           # PASS | GOOD | WARNING | HIGH RISK | CRITICAL
    severity: str
    explanation: str


@dataclass
class IncompatibilityReport:
    what_will_break: str
    when_it_will_break: str
    impact: str
    severity: str
    remediation: str
    category: str


@dataclass
class AssessmentResult:
    """Complete result of all 17 assessment steps."""
    source_version: str
    target_version: str
    intermediate_versions: List[str]
    snapshot: ClusterSnapshot

    # Step 1: Cluster Info
    cluster_info: Dict = field(default_factory=dict)

    # Step 2: Workload Inventory
    workload_inventory: List[Dict] = field(default_factory=list)

    # Step 3: CRD Discovery
    crd_inventory: List[Dict] = field(default_factory=list)

    # Step 4: Controller Detection
    detected_controllers: Dict[str, str] = field(default_factory=dict)

    # Step 5: Release Notes
    release_notes: List[str] = field(default_factory=list)
    behavioral_changes: List[db.BehavioralChange] = field(default_factory=list)

    # Step 6: API Removal Findings
    api_removal_findings: List[APIRemovalFinding] = field(default_factory=list)

    # Step 7: Deprecated API Findings
    deprecated_api_findings: List[DeprecatedAPIFinding] = field(default_factory=list)

    # Step 8: CRD Compatibility
    crd_compatibility_findings: List[CRDCompatibilityFinding] = field(default_factory=list)

    # Step 9: Controller Compatibility
    controller_compatibility_findings: List[ControllerCompatibilityFinding] = field(default_factory=list)

    # Step 10: Webhook Analysis
    webhook_findings: List[WebhookFinding] = field(default_factory=list)

    # Step 11: Networking
    networking_status: str = Status.GOOD
    networking_issues: List[str] = field(default_factory=list)
    networking_can_break: bool = False
    networking_reason: str = ""

    # Step 12: Storage
    storage_status: str = Status.GOOD
    storage_issues: List[str] = field(default_factory=list)
    storage_can_break: bool = False
    storage_reason: str = ""

    # Step 13: Security
    security_status: str = Status.GOOD
    security_issues: List[str] = field(default_factory=list)
    security_can_break: bool = False
    security_reason: str = ""

    # Step 14: Runtime
    runtime_status: str = Status.GOOD
    runtime_issues: List[str] = field(default_factory=list)

    # Step 15: Resource Pressure
    resource_pressure_issues: List[str] = field(default_factory=list)
    resource_pressure_status: str = Status.GOOD

    # Step 16: Upgrade Simulation
    simulation_results: List[SubsystemStatus] = field(default_factory=list)

    # Step 17: Failure Scenarios
    failure_scenarios: List[FailureScenario] = field(default_factory=list)

    # Incompatibility reports (mandatory rule)
    incompatibility_reports: List[IncompatibilityReport] = field(default_factory=list)

    # Completeness and upcoming changes
    inventory_status: str = "AVAILABLE"  # "AVAILABLE" | "VERIFIED_EMPTY" | "MISSING" | "COLLECTION_ERRORS"
    upcoming_release_changes: List[Dict[str, str]] = field(default_factory=list)

    # Errors during assessment
    assessment_errors: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Assessment Engine
# ---------------------------------------------------------------------------

class AssessmentEngine:
    """
    Runs all 17 assessment steps against a ClusterSnapshot
    and returns a complete AssessmentResult.
    """

    def __init__(self, source_version: str, target_version: str, snapshot: ClusterSnapshot):
        self.source = source_version.lstrip("v")
        self.target = target_version.lstrip("v")
        self.snapshot = snapshot
        self.intermediate = db.get_intermediate_versions(self.source, self.target)

        # Determine inventory completeness
        if self.snapshot.collection_errors:
            inv_status = "COLLECTION_ERRORS"
        elif not getattr(self.snapshot, "all_resources_provided", True):
            inv_status = "MISSING"
        else:
            inv = build_resource_inventory(self.snapshot)
            inv_status = "AVAILABLE" if inv else "VERIFIED_EMPTY"

        self.result = AssessmentResult(
            source_version=self.source,
            target_version=self.target,
            intermediate_versions=self.intermediate,
            snapshot=snapshot,
            inventory_status=inv_status,
        )

    def run_all(self) -> AssessmentResult:
        """Run all 17 assessment steps."""
        logger.info(f"Starting assessment: {self.source} -> {self.target}")

        self._step1_cluster_info()
        self._step2_workload_inventory()
        self._step3_crd_discovery()
        self._step4_controller_detection()
        self._step5_release_notes()
        self._step6_api_removal()
        self._step7_deprecated_apis()
        self._step8_crd_compatibility()
        self._step9_controller_compatibility()
        self._step10_webhook_analysis()
        self._step11_networking()
        self._step12_storage()
        self._step13_security()
        self._step14_runtime()
        self._step15_resource_pressure()
        self._step16_upgrade_simulation()
        self._step17_failure_scenarios()

        logger.info("Assessment complete.")
        return self.result

    # ------------------------------------------------------------------
    # Step 1: Cluster Info
    # ------------------------------------------------------------------
    def _step1_cluster_info(self):
        snap = self.snapshot
        self.result.cluster_info = {
            "kubernetes_version": snap.k8s_version,
            "git_version": snap.k8s_git_version,
            "api_server_version": snap.api_server_version,
            "platform": snap.platform,
            "cluster_name": snap.cluster_name,
            "managed_provider": snap.managed_provider,
            "is_managed": snap.is_managed,
            "ha_control_plane": snap.ha_control_plane,
            "control_plane_nodes": snap.control_plane_count,
            "worker_nodes": snap.worker_count,
            "total_nodes": len(snap.nodes),
            "namespaces": len(snap.namespaces),
            "node_details": [
                {
                    "name": n.name,
                    "role": n.role,
                    "version": n.k8s_version,
                    "os": n.os_image,
                    "runtime": n.container_runtime,
                    "status": n.status,
                }
                for n in snap.nodes
            ],
            "source_version": self.source,
            "target_version": self.target,
            "intermediate_versions": self.intermediate,
        }

    # ------------------------------------------------------------------
    # Step 2: Workload Inventory
    # ------------------------------------------------------------------
    def _step2_workload_inventory(self):
        all_workloads = []
        for w in (self.snapshot.deployments + self.snapshot.statefulsets +
                  self.snapshot.daemonsets + self.snapshot.jobs + self.snapshot.cronjobs):
            all_workloads.append({
                "namespace": w.namespace,
                "kind": w.kind,
                "name": w.name,
                "api_version": w.api_version,
                "replicas": w.replicas,
                "ready": w.ready_replicas,
                "age": w.age,
                "images": w.images,
            })
        self.result.workload_inventory = all_workloads

    # ------------------------------------------------------------------
    # Step 3: CRD Discovery
    # ------------------------------------------------------------------
    def _step3_crd_discovery(self):
        self.result.crd_inventory = [
            {
                "name": c.name,
                "group": c.group,
                "kind": c.kind,
                "versions": c.versions,
                "storage_version": c.storage_version,
                "served_versions": c.served_versions,
                "scope": c.scope,
                "has_conversion_webhook": c.has_conversion_webhook,
                "conversion_strategy": c.conversion_strategy,
                "has_validation_schema": c.has_validation_schema,
                "established": c.established,
            }
            for c in self.snapshot.crds
        ]

    # ------------------------------------------------------------------
    # Step 4: Controller Detection
    # ------------------------------------------------------------------
    def _step4_controller_detection(self):
        self.result.detected_controllers = self.snapshot.detected_operators

    # ------------------------------------------------------------------
    # Step 5: Release Notes
    # ------------------------------------------------------------------
    def _step5_release_notes(self):
        versions_to_review = self.intermediate
        notes = []
        for v in versions_to_review:
            note = db.K8S_RELEASE_NOTES.get(v, f"v{v}: No summary available. Check https://kubernetes.io/releases/")
            notes.append(f"v{v}: {note}")

        self.result.release_notes = notes
        self.result.behavioral_changes = db.get_behavioral_changes_in_range(self.source, self.target)

    # ------------------------------------------------------------------
    # Step 6: API Removal Analysis
    # ------------------------------------------------------------------
    def _step6_api_removal(self):
        inventory = build_resource_inventory(self.snapshot)
        removed_apis = db.get_removed_apis_in_range(self.source, self.target)
        findings = []

        if self.snapshot.collection_errors:
            self.result.inventory_status = "COLLECTION_ERRORS"
            for err in self.snapshot.collection_errors:
                self.result.assessment_errors.append(f"Collection error: {err}")
        elif not self.snapshot.all_resources_provided:
            self.result.inventory_status = "MISSING"
        elif len(inventory) == 0:
            self.result.inventory_status = "VERIFIED_EMPTY"
        else:
            self.result.inventory_status = "AVAILABLE"

        is_cluster_scoped = {
            "ClusterRole", "ClusterRoleBinding", "PodSecurityPolicy",
            "IngressClass", "CustomResourceDefinition", "FlowSchema",
            "PriorityLevelConfiguration", "StorageClass", "CSIDriver", "CSINode"
        }

        for removed in removed_apis:
            api_ver = f"{removed.group}/{removed.version}" if removed.group else removed.version

            # Match strictly against observed cluster resources
            matching = [
                res for res in inventory
                if res.kind == removed.kind and (
                    (res.group == removed.group and res.version == removed.version)
                    or res.api_version == api_ver
                )
            ]

            if not matching:
                continue

            replacement = (
                f"{removed.replacement_group}/{removed.replacement_version} {removed.replacement_kind}"
                if (removed.replacement_group or removed.replacement_version or removed.replacement_kind)
                else "NO REPLACEMENT (API completely removed)"
            )

            for res in matching:
                ns = res.namespace if res.namespace else ("cluster-wide" if removed.kind in is_cluster_scoped else "default")
                obj_name = res.name if res.name else f"{removed.kind}"
                loc = f" '{ns}/{obj_name}'" if ns != "cluster-wide" else f" '{obj_name}'"

                findings.append(APIRemovalFinding(
                    namespace=ns,
                    object_name=obj_name,
                    kind=removed.kind,
                    current_api=res.api_version,
                    removal_version=removed.removal_version,
                    replacement_api=replacement,
                    impact=f"Resource{loc} uses {res.api_version} which is removed in Kubernetes v{removed.removal_version}",
                    severity=Severity.CRITICAL,
                    required_action=f"Migrate {removed.kind} '{obj_name}' to {replacement}. {removed.notes}",
                    category=IssueCategory.VERIFIED,
                ))

                self.result.incompatibility_reports.append(IncompatibilityReport(
                    what_will_break=f"{removed.kind} '{obj_name}' using API {res.api_version}",
                    when_it_will_break="Control Plane Upgrade",
                    impact="Outage - all PSP-controlled workloads fail to start" if removed.kind == "PodSecurityPolicy" else "Deployment Failure / Resource Unavailability",
                    severity=Severity.CRITICAL,
                    remediation=f"Before upgrading: migrate {removed.kind} '{obj_name}' to {replacement}. {removed.notes}",
                    category=IssueCategory.VERIFIED,
                ))

        self.result.api_removal_findings = findings

    # ------------------------------------------------------------------
    # Step 7: Deprecated API Analysis
    # ------------------------------------------------------------------
    def _step7_deprecated_apis(self):
        inventory = build_resource_inventory(self.snapshot)
        deprecated_apis = db.get_deprecated_apis_in_range(self.source, self.target)
        findings = []
        upcoming = []

        is_cluster_scoped = {
            "ClusterRole", "ClusterRoleBinding", "PodSecurityPolicy",
            "IngressClass", "CustomResourceDefinition", "FlowSchema",
            "PriorityLevelConfiguration", "StorageClass", "CSIDriver", "CSINode"
        }

        for dep in deprecated_apis:
            # If the API was removed within the requested upgrade range,
            # it is already captured as an API removal finding in Step 6.
            # Avoid duplicating the same issue as both a critical removal and an independent deprecated finding.
            if db.version_gt(dep.planned_removal_version, self.source) and db.version_lte(dep.planned_removal_version, self.target):
                continue

            api_ver = f"{dep.group}/{dep.version}" if dep.group else dep.version
            replacement = f"{dep.replacement_group}/{dep.replacement_version} {dep.replacement_kind}"

            # Check if this deprecated API is ACTUALLY present in the cluster inventory
            matching = [
                res for res in inventory
                if res.kind == dep.kind and (
                    (res.group == dep.group and res.version == dep.version)
                    or res.api_version == api_ver
                )
            ]

            for res in matching:
                ns = res.namespace if res.namespace else ("cluster-wide" if dep.kind in is_cluster_scoped else "default")
                obj_name = res.name if res.name else f"{dep.kind}"
                findings.append(DeprecatedAPIFinding(
                    namespace=ns,
                    object_name=obj_name,
                    api_version=res.api_version,
                    risk_level="MEDIUM",
                    planned_removal_version=dep.planned_removal_version,
                    migration_required=f"RECOMMENDED: API planned for removal in v{dep.planned_removal_version}. Migrate to: {replacement}",
                    category=IssueCategory.VERIFIED,
                ))

            # Record upcoming release changes for future versions (informational only)
            if db.version_gt(dep.planned_removal_version, self.target):
                upcoming.append({
                    "kind": dep.kind,
                    "api_version": api_ver,
                    "planned_removal": dep.planned_removal_version,
                    "replacement": replacement,
                })

        self.result.deprecated_api_findings = findings
        self.result.upcoming_release_changes = upcoming

    # ------------------------------------------------------------------
    # Step 8: CRD Compatibility Analysis
    # ------------------------------------------------------------------
    def _step8_crd_compatibility(self):
        findings = []

        for crd in self.snapshot.crds:
            issues = []
            will_break = False
            severity = Severity.LOW

            # Check conversion webhook
            if crd.has_conversion_webhook:
                issues.append("Has conversion webhook - must verify webhook compatibility with target K8s version")
                severity = Severity.HIGH
                will_break = True  # Conservative: flag for review

            # Check for multiple versions
            if len(crd.versions) > 1:
                if crd.has_conversion_webhook:
                    issues.append(f"Multi-version CRD ({', '.join(crd.versions)}) with webhook conversion needs careful validation")
                else:
                    issues.append(f"Multi-version CRD ({', '.join(crd.versions)}) - ensure storage version is correct")

            # Check storage version defined
            if not crd.storage_version:
                issues.append("No storage version defined - may cause deserialization issues")
                severity = Severity.MEDIUM

            # Check validation schema
            if not crd.has_validation_schema:
                issues.append("No validation schema - structural schema required for v1 CRDs (may have been created with v1beta1 CRD)")
                if db.version_gte(self.target, "1.22"):
                    severity = Severity.HIGH
                    will_break = True

            # Check if CRD itself is established
            if not crd.established:
                issues.append("CRD is not in 'Established' condition - may indicate prior installation issues")
                severity = Severity.MEDIUM

            if issues:
                findings.append(CRDCompatibilityFinding(
                    crd_name=crd.name,
                    group=crd.group,
                    kind=crd.kind,
                    issue="; ".join(issues),
                    will_break=will_break,
                    severity=severity,
                    reason="; ".join(issues),
                    category=IssueCategory.PROBABLE if will_break else IssueCategory.POSSIBLE,
                ))

        self.result.crd_compatibility_findings = findings

    # ------------------------------------------------------------------
    # Step 9: Controller Compatibility Analysis
    # ------------------------------------------------------------------
    def _step9_controller_compatibility(self):
        findings = []
        detected = self.snapshot.detected_operators or self.result.detected_controllers

        for op_name, installed_version in detected.items():
            op_data = db.get_operator_compatibility(op_name)
            if not op_data:
                # Unknown operator
                findings.append(ControllerCompatibilityFinding(
                    controller_name=op_name,
                    installed_version=installed_version,
                    supported_k8s_versions="UNKNOWN",
                    target_compatibility="UNKNOWN",
                    status=Status.WARNING,
                    upgrade_timing="Optional",
                    notes=f"Unknown operator '{op_name}'. Cannot verify K8s compatibility. Manual review required.",
                    category=IssueCategory.UNKNOWN,
                ))
                continue

            compatible, reason = db.is_operator_compatible(op_data, self.target)

            if compatible:
                status = Status.PASS
                timing = "Optional"
            elif op_data.must_upgrade_before:
                status = Status.CRITICAL
                timing = "Before Kubernetes upgrade"
            else:
                status = Status.HIGH_RISK
                timing = "After Kubernetes upgrade"

            supported_ranges = ", ".join([f"{mn}–{mx}" for mn, mx in op_data.supported_ranges])

            findings.append(ControllerCompatibilityFinding(
                controller_name=op_name,
                installed_version=installed_version,
                supported_k8s_versions=supported_ranges,
                target_compatibility=reason,
                status=status,
                upgrade_timing=timing,
                notes=f"{op_data.notes} Upgrade URL: {op_data.compatibility_url}",
                category=IssueCategory.VERIFIED if compatible else IssueCategory.VERIFIED,
            ))

            if not compatible:
                self.result.incompatibility_reports.append(IncompatibilityReport(
                    what_will_break=f"{op_data.display_name} controller",
                    when_it_will_break="Control Plane Upgrade" if op_data.must_upgrade_before else "After Kubernetes upgrade",
                    impact="Reconciliation Failure / Partial Outage",
                    severity=Severity.CRITICAL if op_data.must_upgrade_before else Severity.HIGH,
                    remediation=f"{op_data.upgrade_notes} See: {op_data.compatibility_url}",
                    category=IssueCategory.VERIFIED,
                ))

        self.result.controller_compatibility_findings = findings

    # ------------------------------------------------------------------
    # Step 10: Webhook Analysis
    # ------------------------------------------------------------------
    def _step10_webhook_analysis(self):
        findings = []
        all_webhooks = self.snapshot.validating_webhooks + self.snapshot.mutating_webhooks

        for wh in all_webhooks:
            can_block = wh.failure_policy == "Fail"
            can_fail = False
            severity = Severity.LOW
            reasons = []

            if wh.failure_policy == "Fail":
                reasons.append("FailurePolicy=Fail: if webhook endpoint is unavailable, ALL matching requests will be blocked")
                severity = Severity.HIGH
                can_block = True
                can_fail = True

            if wh.side_effects not in ["None", "NoneOnDryRun"]:
                reasons.append(f"SideEffects={wh.side_effects}: webhook has side effects, must declare 'NoneOnDryRun' for dry-run safety")
                severity = Severity.MEDIUM

            if not wh.admission_review_versions:
                reasons.append("No admissionReviewVersions specified - may be incompatible with target K8s API")
                can_fail = True
                severity = Severity.HIGH
            elif "v1" not in wh.admission_review_versions:
                reasons.append(f"admissionReviewVersions {wh.admission_review_versions} does not include 'v1' - required for K8s 1.22+")
                can_fail = True
                severity = Severity.HIGH

            if wh.timeout_seconds > 25:
                reasons.append(f"timeoutSeconds={wh.timeout_seconds} is too high (max 30s, recommended <10s)")
                severity = max(severity, Severity.MEDIUM)

            if reasons:
                findings.append(WebhookFinding(
                    name=wh.name,
                    kind=wh.kind,
                    failure_policy=wh.failure_policy,
                    side_effects=wh.side_effects,
                    can_block_workloads=can_block,
                    can_fail_after_upgrade=can_fail,
                    severity=severity,
                    reason="; ".join(reasons),
                    category=IssueCategory.PROBABLE if can_fail else IssueCategory.POSSIBLE,
                ))

        self.result.webhook_findings = findings

    # ------------------------------------------------------------------
    # Step 11: Networking Compatibility
    # ------------------------------------------------------------------
    def _step11_networking(self):
        issues = []
        can_break = False

        # Check CNI plugin
        cni = self.snapshot.cni_plugin.lower() if self.snapshot.cni_plugin else ""

        if "cilium" in cni:
            # Cilium must match k8s version closely
            cilium_op = db.get_operator_compatibility("cilium")
            if cilium_op:
                compatible, reason = db.is_operator_compatible(cilium_op, self.target)
                if not compatible:
                    issues.append(f"CRITICAL: Cilium CNI may be incompatible with K8s {self.target}. {reason}")
                    can_break = True
                    self.result.incompatibility_reports.append(IncompatibilityReport(
                        what_will_break="Cilium CNI - cluster networking",
                        when_it_will_break="Control Plane Upgrade",
                        impact="Outage - complete cluster networking failure",
                        severity=Severity.CRITICAL,
                        remediation="Upgrade Cilium to a compatible version BEFORE upgrading Kubernetes.",
                        category=IssueCategory.PROBABLE,
                    ))

        # Check ingress controller version
        ingress_detected = "ingress-nginx" in (self.result.detected_controllers or {})
        if ingress_detected:
            ing_op = db.get_operator_compatibility("ingress-nginx")
            if ing_op:
                compatible, reason = db.is_operator_compatible(ing_op, self.target)
                if not compatible:
                    issues.append(f"ingress-nginx may not support K8s {self.target}: {reason}")
                    can_break = True

        # Check nftables change in 1.29
        if db.version_gt(self.target, "1.29") and db.version_lte(self.source, "1.28"):
            issues.append("kube-proxy nftables backend available in 1.29+. Verify CNI compatibility if switching modes.")

        # Check CoreDNS (generally compatible but worth noting)
        if db.version_gt(self.target, "1.27"):
            issues.append("Verify CoreDNS version compatibility with target K8s. CoreDNS 1.10+ recommended for K8s 1.27+.")

        # Check AppArmor if targeting 1.30+
        if db.version_gte(self.target, "1.30"):
            issues.append("AppArmor pod security fields graduated to GA in 1.30. Review AppArmor profiles if used.")

        # Ingress API check
        if db.version_gte(self.target, "1.22") and db.version_lt(self.source, "1.22"):
            ingress_removals = [f for f in self.result.api_removal_findings if "Ingress" in f.kind]
            if ingress_removals:
                issues.append(f"ADVISORY: {len(ingress_removals)} Ingress resource(s) require migration to networking.k8s.io/v1.")

        status = Status.CRITICAL if any("CRITICAL" in i for i in issues) else (
            Status.HIGH_RISK if can_break else (
                Status.WARNING if issues else Status.GOOD
            )
        )

        self.result.networking_status = status
        self.result.networking_issues = issues
        self.result.networking_can_break = can_break
        self.result.networking_reason = "; ".join(issues) if issues else "No critical networking issues detected."

    # ------------------------------------------------------------------
    # Step 12: Storage Compatibility
    # ------------------------------------------------------------------
    def _step12_storage(self):
        issues = []
        can_break = False

        # Check if using in-tree storage drivers that may be removed
        in_tree_provisioners = {
            "kubernetes.io/aws-ebs": "AWS EBS",
            "kubernetes.io/gce-pd": "GCE Persistent Disk",
            "kubernetes.io/azure-disk": "Azure Disk",
            "kubernetes.io/azure-file": "Azure File",
            "kubernetes.io/cinder": "OpenStack Cinder",
            "kubernetes.io/vsphere-volume": "vSphere Volume",
        }

        for sc in self.snapshot.storage_classes:
            provisioner = sc.provisioner.lower()
            for intree, name in in_tree_provisioners.items():
                if intree in provisioner:
                    if db.version_gte(self.target, "1.29"):
                        issues.append(
                            f"CRITICAL: StorageClass '{sc.name}' uses in-tree provisioner '{sc.provisioner}' ({name}). "
                            f"In-tree cloud providers are being removed. Migrate to CSI driver equivalent."
                        )
                        can_break = True
                    else:
                        issues.append(
                            f"WARNING: StorageClass '{sc.name}' uses in-tree provisioner '{sc.provisioner}'. "
                            f"Plan migration to CSI driver."
                        )

        # Check for no default storage class
        default_scs = [sc for sc in self.snapshot.storage_classes if sc.is_default]
        if not default_scs and self.snapshot.persistent_volume_claims:
            issues.append("No default StorageClass defined but PVCs exist - dynamic provisioning may fail.")

        # Check for PVCs in non-Bound state
        bad_pvcs = [pvc for pvc in self.snapshot.persistent_volume_claims if pvc.status not in ["Bound", ""]]
        if bad_pvcs:
            issues.append(f"WARNING: {len(bad_pvcs)} PVC(s) not in Bound state - investigate before upgrade.")

        # CSI migration
        if db.version_gte(self.target, "1.25"):
            issues.append("NOTE: CSI migration is stable in 1.25+. Verify all storage uses CSI drivers.")

        # Volume snapshot API
        if db.version_gte(self.target, "1.29"):
            issues.append("ReadWriteOncePod PVC access mode graduated to GA in 1.29. Verify CSI driver support if used.")

        # Check EBS CSI
        ebs_detected = "ebs-csi-driver" in (self.result.detected_controllers or {})
        if ebs_detected:
            ebs_op = db.get_operator_compatibility("ebs-csi-driver")
            if ebs_op:
                compatible, reason = db.is_operator_compatible(ebs_op, self.target)
                if not compatible:
                    issues.append(f"EBS CSI driver may not support K8s {self.target}: {reason}")
                    can_break = True

        status = Status.CRITICAL if any("CRITICAL" in i for i in issues) else (
            Status.HIGH_RISK if can_break else (
                Status.WARNING if issues else Status.GOOD
            )
        )

        self.result.storage_status = status
        self.result.storage_issues = issues
        self.result.storage_can_break = can_break
        self.result.storage_reason = "; ".join(issues) if issues else "No critical storage issues detected."

    # ------------------------------------------------------------------
    # Step 13: Security Compatibility
    # ------------------------------------------------------------------
    def _step13_security(self):
        issues = []
        can_break = False

        # PSP removal check
        if self.snapshot.pod_security_policies and db.version_gte(self.target, "1.25"):
            count = len(self.snapshot.pod_security_policies)
            issues.append(
                f"CRITICAL: {count} PodSecurityPolicy object(s) detected. PSP is REMOVED in K8s 1.25. "
                f"ALL workloads controlled by PSP will FAIL TO START after upgrade. "
                f"Migrate to Pod Security Admission (PSA) or Kyverno/OPA before upgrading."
            )
            can_break = True
            if not any("PodSecurityPolicy" in r.what_will_break for r in self.result.incompatibility_reports):
                self.result.incompatibility_reports.append(IncompatibilityReport(
                    what_will_break=f"All workloads controlled by {count} PodSecurityPolicy object(s)",
                    when_it_will_break="Control Plane Upgrade",
                    impact="Outage - all PSP-controlled workloads fail to start",
                    severity=Severity.CRITICAL,
                    remediation=(
                        "1. Audit all PSPs and replace with Pod Security Admission namespace labels. "
                        "2. Install alternative policy engine (Kyverno or OPA/Gatekeeper). "
                        "3. Test workloads with PSA before removing PSPs. "
                        "4. Remove PSPs only after migration is validated."
                    ),
                    category=IssueCategory.VERIFIED,
                ))

        # Check PSA
        if not self.snapshot.has_pod_security_admission and db.version_gte(self.target, "1.25"):
            if not self.snapshot.pod_security_policies:
                issues.append(
                    "No Pod Security Admission (PSA) labels detected. Consider adding namespace labels "
                    "for baseline/restricted pod security standards."
                )

        # SeccompDefault
        if db.version_gt(self.target, "1.27"):
            issues.append(
                "SeccompDefault feature graduated to GA in 1.27. If enabled, RuntimeDefault seccomp profile "
                "is applied by default. Verify workloads handle seccomp restrictions."
            )

        # Token changes
        if db.version_gte(self.target, "1.24") and db.version_lt(self.source, "1.24"):
            issues.append(
                "K8s 1.24: ServiceAccount tokens are no longer auto-generated as long-lived secrets. "
                "Applications relying on static SA token secrets must be updated."
            )

        # Privileged workloads
        if self.snapshot.privileged_workloads:
            count = len(self.snapshot.privileged_workloads)
            issues.append(
                f"WARNING: {count} privileged workload(s) detected. "
                f"Review security context changes in target K8s version."
            )

        # RBAC check - ONLY if v1beta1 RBAC resources are observed in cluster!
        inventory = build_resource_inventory(self.snapshot)
        rbac_v1beta1 = [
            r for r in inventory
            if r.group == "rbac.authorization.k8s.io" and r.version == "v1beta1"
        ]
        if rbac_v1beta1 and db.version_gte(self.target, "1.22") and db.version_lt(self.source, "1.22"):
            issues.append(
                f"CRITICAL: {len(rbac_v1beta1)} RBAC resource(s) using rbac.authorization.k8s.io/v1beta1 detected. "
                "All RBAC resources must use rbac.authorization.k8s.io/v1 (v1beta1 RBAC APIs are removed in K8s 1.22)."
            )
            can_break = True

        status = Status.CRITICAL if any("CRITICAL" in i for i in issues) else (
            Status.HIGH_RISK if can_break else (
                Status.WARNING if issues else Status.GOOD
            )
        )

        self.result.security_status = status
        self.result.security_issues = issues
        self.result.security_can_break = can_break
        self.result.security_reason = "; ".join(issues) if issues else "No critical security issues detected."

    # ------------------------------------------------------------------
    # Step 14: Runtime Compatibility
    # ------------------------------------------------------------------
    def _step14_runtime(self):
        issues = []

        for node in self.snapshot.nodes:
            runtime = node.container_runtime.lower()

            # Dockershim check
            if "docker" in runtime and "containerd" not in runtime:
                if db.version_gte(self.target, "1.24"):
                    issues.append(
                        f"CRITICAL: Node '{node.name}' uses Docker runtime ('{node.container_runtime}'). "
                        f"Dockershim was REMOVED in K8s 1.24. Node will fail to join cluster after upgrade."
                    )
                    can_break = True
                    self.result.incompatibility_reports.append(IncompatibilityReport(
                        what_will_break=f"Node '{node.name}' with Docker runtime",
                        when_it_will_break="Node Upgrade",
                        impact="Outage - node fails to register with kubelet",
                        severity=Severity.CRITICAL,
                        remediation="Migrate node container runtime to containerd or CRI-O before upgrading kubelet.",
                        category=IssueCategory.VERIFIED,
                    ))

            # Check containerd version compatibility
            if "containerd" in runtime:
                # Extract version like "containerd://1.6.20"
                try:
                    ver_str = runtime.split("//")[-1].split("-")[0]
                    major = int(ver_str.split(".")[0])
                    minor = int(ver_str.split(".")[1]) if len(ver_str.split(".")) > 1 else 0
                    runtime_ver_str = f"{major}.{minor}"

                    min_containerd = db.CRI_MIN_VERSIONS.get("containerd", {}).get(self.target, "1.3")
                    min_major = int(min_containerd.split(".")[0])
                    min_minor = int(min_containerd.split(".")[1]) if len(min_containerd.split(".")) > 1 else 0

                    if (major, minor) < (min_major, min_minor):
                        issues.append(
                            f"Node '{node.name}': containerd {runtime_ver_str} may be below minimum "
                            f"required {min_containerd} for K8s {self.target}."
                        )
                except (ValueError, IndexError):
                    issues.append(f"Node '{node.name}': Could not parse containerd version from '{node.container_runtime}'")

        status = Status.CRITICAL if any("CRITICAL" in i for i in issues) else (
            Status.WARNING if issues else Status.GOOD
        )
        self.result.runtime_status = status
        self.result.runtime_issues = issues

    # ------------------------------------------------------------------
    # Step 15: Resource Pressure Analysis
    # ------------------------------------------------------------------
    def _step15_resource_pressure(self):
        issues = []

        for node in self.snapshot.nodes:
            if node.status != "Ready":
                issues.append(f"Node '{node.name}' is NOT Ready - upgrade will risk workload eviction on this node.")

        for node_name, pressure in self.snapshot.node_cpu_pressures.items():
            if pressure.lower() not in ["0", "false", ""]:
                issues.append(f"Node '{node_name}' has CPU pressure - upgrade may trigger pod eviction.")

        for node_name, pressure in self.snapshot.node_memory_pressures.items():
            if pressure.lower() not in ["0", "false", ""]:
                issues.append(f"Node '{node_name}' has Memory pressure - OOMKills likely during node drain.")

        for node_name, pressure in self.snapshot.node_disk_pressures.items():
            if pressure.lower() not in ["0", "false", ""]:
                issues.append(f"Node '{node_name}' has Disk pressure - upgrade images/overlay may fail.")

        # General advice for node drain
        if self.snapshot.worker_count > 0:
            issues.append(
                f"ADVISORY: {self.snapshot.worker_count} worker node(s) will need draining during upgrade. "
                f"Ensure sufficient PodDisruptionBudgets and resource capacity."
            )

        status = Status.WARNING if issues else Status.GOOD
        self.result.resource_pressure_issues = issues
        self.result.resource_pressure_status = status

    # ------------------------------------------------------------------
    # Step 16: Upgrade Simulation
    # ------------------------------------------------------------------
    def _step16_upgrade_simulation(self):
        subsystems = []

        # Control Plane
        cp_issues = [r for r in self.result.incompatibility_reports if "Control Plane" in r.when_it_will_break]
        critical_cp = [r for r in cp_issues if r.severity == Severity.CRITICAL]
        cp_status = Status.CRITICAL if critical_cp else (Status.WARNING if cp_issues else Status.GOOD)
        subsystems.append(SubsystemStatus(
            name="Control Plane",
            status=cp_status,
            severity=Severity.CRITICAL if critical_cp else Severity.LOW,
            explanation=(
                f"{len(critical_cp)} critical issue(s) that will affect control plane upgrade. "
                + "; ".join([r.what_will_break for r in critical_cp])
            ) if critical_cp else "No critical control plane issues detected. Standard rolling upgrade expected."
        ))

        # Nodes
        node_issues = [r for r in self.result.incompatibility_reports if "Node" in r.when_it_will_break]
        runtime_issues = self.result.runtime_issues
        n_status = Status.CRITICAL if any("CRITICAL" in i for i in runtime_issues) else (
            Status.WARNING if runtime_issues or node_issues else Status.GOOD
        )
        subsystems.append(SubsystemStatus(
            name="Nodes",
            status=n_status,
            severity=Severity.CRITICAL if n_status == Status.CRITICAL else Severity.MEDIUM,
            explanation=(
                "; ".join(runtime_issues[:3]) if runtime_issues
                else f"{self.snapshot.worker_count} worker node(s) will need rolling drain/upgrade. No critical issues."
            )
        ))

        # APIs
        critical_apis = [f for f in self.result.api_removal_findings if f.severity == Severity.CRITICAL]
        api_status = Status.CRITICAL if critical_apis else (
            Status.WARNING if self.result.deprecated_api_findings else Status.GOOD
        )
        subsystems.append(SubsystemStatus(
            name="APIs",
            status=api_status,
            severity=Severity.CRITICAL if critical_apis else Severity.LOW,
            explanation=(
                f"{len(critical_apis)} removed API(s) detected in cluster: "
                + ", ".join([f.kind for f in critical_apis[:5]])
            ) if critical_apis else (
                f"{len(self.result.deprecated_api_findings)} deprecated API(s) need migration. No removed APIs in active use."
                if self.result.deprecated_api_findings else "All APIs compatible with target version."
            )
        ))

        # CRDs
        breaking_crds = [f for f in self.result.crd_compatibility_findings if f.will_break]
        crd_status = Status.HIGH_RISK if breaking_crds else (
            Status.WARNING if self.result.crd_compatibility_findings else Status.GOOD
        )
        subsystems.append(SubsystemStatus(
            name="CRDs",
            status=crd_status,
            severity=Severity.HIGH if breaking_crds else Severity.LOW,
            explanation=(
                f"{len(breaking_crds)} CRD(s) may break: " +
                ", ".join([f.crd_name for f in breaking_crds[:3]])
            ) if breaking_crds else (
                f"{len(self.result.crd_compatibility_findings)} CRD(s) have warnings but no breaking issues."
                if self.result.crd_compatibility_findings else f"{len(self.snapshot.crds)} CRD(s) appear compatible."
            )
        ))

        # Controllers
        critical_ctls = [f for f in self.result.controller_compatibility_findings
                         if f.status in [Status.CRITICAL, Status.HIGH_RISK]]
        ctl_status = Status.CRITICAL if any(f.status == Status.CRITICAL for f in critical_ctls) else (
            Status.HIGH_RISK if critical_ctls else (
                Status.WARNING if self.result.controller_compatibility_findings else Status.GOOD
            )
        )
        subsystems.append(SubsystemStatus(
            name="Controllers",
            status=ctl_status,
            severity=Severity.CRITICAL if ctl_status == Status.CRITICAL else Severity.MEDIUM,
            explanation=(
                f"{len(critical_ctls)} controller(s) incompatible with K8s {self.target}: "
                + ", ".join([f.controller_name for f in critical_ctls[:3]])
            ) if critical_ctls else (
                f"{len(self.result.controller_compatibility_findings)} controller(s) verified compatible."
                if self.result.controller_compatibility_findings else "No controllers detected."
            )
        ))

        # Networking
        subsystems.append(SubsystemStatus(
            name="Networking",
            status=self.result.networking_status,
            severity=Severity.CRITICAL if self.result.networking_can_break else Severity.MEDIUM,
            explanation=self.result.networking_reason,
        ))

        # Storage
        subsystems.append(SubsystemStatus(
            name="Storage",
            status=self.result.storage_status,
            severity=Severity.CRITICAL if self.result.storage_can_break else Severity.MEDIUM,
            explanation=self.result.storage_reason,
        ))

        # Security
        subsystems.append(SubsystemStatus(
            name="Security",
            status=self.result.security_status,
            severity=Severity.CRITICAL if self.result.security_can_break else Severity.MEDIUM,
            explanation=self.result.security_reason,
        ))

        self.result.simulation_results = subsystems

    # ------------------------------------------------------------------
    # Step 17: Failure Scenario Modeling
    # ------------------------------------------------------------------
    def _step17_failure_scenarios(self):
        scenarios = []

        # 1. Could workloads fail to start?
        api_removal_critical = bool(self.result.api_removal_findings)
        psp_removed = self.snapshot.pod_security_policies and db.version_gte(self.target, "1.25")

        if api_removal_critical or psp_removed:
            ans = "YES"
            reason = []
            if psp_removed:
                reason.append(f"PSP removal will prevent all PSP-controlled workloads from starting.")
            if api_removal_critical:
                reason.append(f"{len(self.result.api_removal_findings)} removed API(s) may prevent resource creation.")
            severity = Severity.CRITICAL
        else:
            ans = "POSSIBLE"
            reason = ["No confirmed issues. Security context changes or scheduler policy changes could affect specific workloads."]
            severity = Severity.LOW

        scenarios.append(FailureScenario(
            scenario="Could workloads fail to start?",
            answer=ans,
            reason=" ".join(reason) if isinstance(reason, list) else reason,
            severity=severity,
            category=IssueCategory.VERIFIED if ans == "YES" else IssueCategory.POSSIBLE,
        ))

        # 2. Could controllers crash?
        broken_controllers = [f for f in self.result.controller_compatibility_findings
                               if f.status in [Status.CRITICAL, Status.HIGH_RISK]]
        if broken_controllers:
            scenarios.append(FailureScenario(
                scenario="Could controllers crash?",
                answer="YES",
                reason=f"{len(broken_controllers)} controller(s) incompatible with K8s {self.target}: "
                       + ", ".join([f.controller_name for f in broken_controllers]),
                severity=Severity.CRITICAL,
                category=IssueCategory.VERIFIED,
            ))
        else:
            scenarios.append(FailureScenario(
                scenario="Could controllers crash?",
                answer="NO",
                reason="No incompatible controllers detected. Monitor controllers after upgrade.",
                severity=Severity.LOW,
                category=IssueCategory.VERIFIED,
            ))

        # 3. Could CRDs become unreadable?
        breaking_crds = [f for f in self.result.crd_compatibility_findings if f.will_break]
        if breaking_crds:
            scenarios.append(FailureScenario(
                scenario="Could CRDs become unreadable?",
                answer="YES",
                reason=f"{len(breaking_crds)} CRD(s) have potential issues: "
                       + ", ".join([f.crd_name for f in breaking_crds[:3]]),
                severity=Severity.HIGH,
                category=IssueCategory.PROBABLE,
            ))
        elif self.snapshot.crds:
            scenarios.append(FailureScenario(
                scenario="Could CRDs become unreadable?",
                answer="NO",
                reason=f"No CRD breaking issues detected. {len(self.snapshot.crds)} CRD(s) appear compatible.",
                severity=Severity.LOW,
                category=IssueCategory.POSSIBLE,
            ))
        else:
            scenarios.append(FailureScenario(
                scenario="Could CRDs become unreadable?",
                answer="NO",
                reason="No CustomResourceDefinitions installed in the cluster.",
                severity=Severity.LOW,
                category=IssueCategory.VERIFIED,
            ))

        # 4. Could CRD controllers stop reconciling?
        if broken_controllers or breaking_crds:
            scenarios.append(FailureScenario(
                scenario="Could CRD controllers stop reconciling?",
                answer="YES",
                reason="Incompatible controllers or broken CRDs will cause reconciliation failures.",
                severity=Severity.HIGH,
                category=IssueCategory.PROBABLE,
            ))
        elif self.snapshot.crds or broken_controllers:
            scenarios.append(FailureScenario(
                scenario="Could CRD controllers stop reconciling?",
                answer="NO",
                reason="CRDs and controllers appear compatible. First reconciliation cycles post-upgrade should succeed.",
                severity=Severity.LOW,
                category=IssueCategory.POSSIBLE,
            ))
        else:
            scenarios.append(FailureScenario(
                scenario="Could CRD controllers stop reconciling?",
                answer="NO",
                reason="No CRDs or incompatible controllers installed in the cluster.",
                severity=Severity.LOW,
                category=IssueCategory.VERIFIED,
            ))

        # 5. Could admission webhooks block deployments?
        blocking_webhooks = [f for f in self.result.webhook_findings
                              if f.can_block_workloads and f.failure_policy == "Fail"]
        has_webhooks = bool(self.snapshot.validating_webhooks or self.snapshot.mutating_webhooks)
        if blocking_webhooks:
            scenarios.append(FailureScenario(
                scenario="Could admission webhooks block deployments?",
                answer="YES",
                reason=f"{len(blocking_webhooks)} webhook(s) with FailurePolicy=Fail detected. "
                       f"If webhook endpoint fails during upgrade, ALL matching API requests will be blocked.",
                severity=Severity.HIGH,
                category=IssueCategory.PROBABLE,
            ))
        elif has_webhooks:
            scenarios.append(FailureScenario(
                scenario="Could admission webhooks block deployments?",
                answer="POSSIBLE",
                reason="Admission webhooks present without Fail-policy. Monitor webhook endpoints during upgrade.",
                severity=Severity.LOW,
                category=IssueCategory.POSSIBLE,
            ))
        else:
            scenarios.append(FailureScenario(
                scenario="Could admission webhooks block deployments?",
                answer="NO",
                reason="No admission webhooks installed in the cluster.",
                severity=Severity.LOW,
                category=IssueCategory.VERIFIED,
            ))

        # 6. Could storage become inaccessible?
        if self.result.storage_can_break:
            scenarios.append(FailureScenario(
                scenario="Could storage become inaccessible?",
                answer="YES",
                reason="; ".join(self.result.storage_issues[:2]),
                severity=Severity.CRITICAL,
                category=IssueCategory.PROBABLE,
            ))
        else:
            scenarios.append(FailureScenario(
                scenario="Could storage become inaccessible?",
                answer="NO",
                reason="No in-tree provisioner issues or CSI incompatibilities detected.",
                severity=Severity.LOW,
                category=IssueCategory.POSSIBLE,
            ))

        # 7. Could networking break?
        if self.result.networking_can_break:
            scenarios.append(FailureScenario(
                scenario="Could networking break?",
                answer="YES",
                reason="; ".join(self.result.networking_issues[:2]),
                severity=Severity.CRITICAL,
                category=IssueCategory.PROBABLE,
            ))
        else:
            scenarios.append(FailureScenario(
                scenario="Could networking break?",
                answer="NO",
                reason="No critical networking incompatibilities detected.",
                severity=Severity.LOW,
                category=IssueCategory.POSSIBLE,
            ))

        # 8. Could node upgrades fail?
        runtime_criticals = [i for i in self.result.runtime_issues if "CRITICAL" in i]
        if runtime_criticals:
            scenarios.append(FailureScenario(
                scenario="Could node upgrades fail?",
                answer="YES",
                reason="; ".join(runtime_criticals[:2]),
                severity=Severity.CRITICAL,
                category=IssueCategory.VERIFIED,
            ))
        else:
            scenarios.append(FailureScenario(
                scenario="Could node upgrades fail?",
                answer="POSSIBLE",
                reason="No confirmed node upgrade issues. Node drain/upgrade may still encounter workload disruption.",
                severity=Severity.MEDIUM,
                category=IssueCategory.POSSIBLE,
            ))

        # 9. Could kubelets fail to register?
        kubelet_issues = [i for i in self.result.runtime_issues if "docker" in i.lower() or "kubelet" in i.lower()]
        if kubelet_issues:
            scenarios.append(FailureScenario(
                scenario="Could kubelets fail to register?",
                answer="YES",
                reason="; ".join(kubelet_issues[:2]),
                severity=Severity.CRITICAL,
                category=IssueCategory.VERIFIED,
            ))
        else:
            scenarios.append(FailureScenario(
                scenario="Could kubelets fail to register?",
                answer="NO",
                reason="No kubelet or CRI incompatibilities detected. Standard kubelet registration expected.",
                severity=Severity.LOW,
                category=IssueCategory.POSSIBLE,
            ))

        # 10. Could the control plane fail?
        cp_criticals = [r for r in self.result.incompatibility_reports
                        if r.severity == Severity.CRITICAL and "Control Plane" in r.when_it_will_break]
        if cp_criticals:
            scenarios.append(FailureScenario(
                scenario="Could the control plane fail?",
                answer="YES",
                reason=f"{len(cp_criticals)} critical issue(s) affect control plane: "
                       + "; ".join([r.what_will_break for r in cp_criticals[:2]]),
                severity=Severity.CRITICAL,
                category=IssueCategory.PROBABLE,
            ))
        else:
            scenarios.append(FailureScenario(
                scenario="Could the control plane fail?",
                answer="NO",
                reason="No critical control plane issues identified. Monitor API server, etcd, and controller-manager during upgrade.",
                severity=Severity.LOW,
                category=IssueCategory.POSSIBLE,
            ))

        self.result.failure_scenarios = scenarios
