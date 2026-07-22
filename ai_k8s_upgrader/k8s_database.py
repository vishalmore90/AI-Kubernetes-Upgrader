"""
k8s_database.py
===============
Comprehensive Kubernetes Knowledge Base for upgrade assessment.

Contains:
- Release timeline and changelogs (v1.20 to v1.34+)
- Complete removed API database per version
- Deprecated API database per version
- Breaking behavioral changes per version
- Operator / Add-on compatibility matrix
- CRI / OS compatibility data
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class RemovedAPI:
    """Represents an API removed in a specific Kubernetes version."""
    group: str
    version: str
    kind: str
    removal_version: str
    replacement_group: str
    replacement_version: str
    replacement_kind: str
    notes: str


@dataclass
class DeprecatedAPI:
    """Represents an API deprecated but not yet removed."""
    group: str
    version: str
    kind: str
    deprecated_in_version: str
    planned_removal_version: str
    replacement_group: str
    replacement_version: str
    replacement_kind: str


@dataclass
class BehavioralChange:
    """Represents a breaking behavioral change in a specific version."""
    version: str
    category: str        # e.g., Security, Runtime, Networking, API
    severity: str        # Critical / High / Medium / Low
    title: str
    description: str
    impact: str
    mitigation: str


@dataclass
class OperatorCompatibility:
    """Compatibility data for a Kubernetes operator/controller."""
    name: str
    display_name: str
    detection_labels: List[str]         # labels to detect in cluster
    detection_namespaces: List[str]     # typical namespaces
    detection_deployments: List[str]    # typical deployment names
    min_k8s_version: str
    max_k8s_version: str
    supported_ranges: List[Tuple[str, str]]  # list of (min, max) tuples per version
    notes: str
    upgrade_notes: str
    must_upgrade_before: bool           # must upgrade before k8s upgrade
    compatibility_url: str


# ---------------------------------------------------------------------------
# Removed APIs Database
# ---------------------------------------------------------------------------

REMOVED_APIS: List[RemovedAPI] = [
    # ---- Removed in v1.16 ----
    RemovedAPI(
        group="extensions", version="v1beta1", kind="Deployment",
        removal_version="1.16",
        replacement_group="apps", replacement_version="v1", replacement_kind="Deployment",
        notes="Use apps/v1 Deployment. extensions/v1beta1 and apps/v1beta1/v1beta2 all removed."
    ),
    RemovedAPI(
        group="apps", version="v1beta1", kind="Deployment",
        removal_version="1.16",
        replacement_group="apps", replacement_version="v1", replacement_kind="Deployment",
        notes="Use apps/v1 Deployment."
    ),
    RemovedAPI(
        group="apps", version="v1beta2", kind="Deployment",
        removal_version="1.16",
        replacement_group="apps", replacement_version="v1", replacement_kind="Deployment",
        notes="Use apps/v1 Deployment."
    ),
    RemovedAPI(
        group="extensions", version="v1beta1", kind="DaemonSet",
        removal_version="1.16",
        replacement_group="apps", replacement_version="v1", replacement_kind="DaemonSet",
        notes="Use apps/v1 DaemonSet."
    ),
    RemovedAPI(
        group="extensions", version="v1beta1", kind="ReplicaSet",
        removal_version="1.16",
        replacement_group="apps", replacement_version="v1", replacement_kind="ReplicaSet",
        notes="Use apps/v1 ReplicaSet."
    ),
    RemovedAPI(
        group="extensions", version="v1beta1", kind="StatefulSet",
        removal_version="1.16",
        replacement_group="apps", replacement_version="v1", replacement_kind="StatefulSet",
        notes="Use apps/v1 StatefulSet."
    ),
    RemovedAPI(
        group="extensions", version="v1beta1", kind="NetworkPolicy",
        removal_version="1.16",
        replacement_group="networking.k8s.io", replacement_version="v1", replacement_kind="NetworkPolicy",
        notes="Use networking.k8s.io/v1 NetworkPolicy."
    ),
    RemovedAPI(
        group="extensions", version="v1beta1", kind="PodSecurityPolicy",
        removal_version="1.16",
        replacement_group="policy", replacement_version="v1beta1", replacement_kind="PodSecurityPolicy",
        notes="Moved to policy/v1beta1. Note: PSP itself was removed in v1.25."
    ),

    # ---- Removed in v1.22 ----
    RemovedAPI(
        group="admissionregistration.k8s.io", version="v1beta1", kind="MutatingWebhookConfiguration",
        removal_version="1.22",
        replacement_group="admissionregistration.k8s.io", replacement_version="v1", replacement_kind="MutatingWebhookConfiguration",
        notes="Use admissionregistration.k8s.io/v1."
    ),
    RemovedAPI(
        group="admissionregistration.k8s.io", version="v1beta1", kind="ValidatingWebhookConfiguration",
        removal_version="1.22",
        replacement_group="admissionregistration.k8s.io", replacement_version="v1", replacement_kind="ValidatingWebhookConfiguration",
        notes="Use admissionregistration.k8s.io/v1."
    ),
    RemovedAPI(
        group="apiextensions.k8s.io", version="v1beta1", kind="CustomResourceDefinition",
        removal_version="1.22",
        replacement_group="apiextensions.k8s.io", replacement_version="v1", replacement_kind="CustomResourceDefinition",
        notes="Use apiextensions.k8s.io/v1 CRD."
    ),
    RemovedAPI(
        group="apiregistration.k8s.io", version="v1beta1", kind="APIService",
        removal_version="1.22",
        replacement_group="apiregistration.k8s.io", replacement_version="v1", replacement_kind="APIService",
        notes="Use apiregistration.k8s.io/v1."
    ),
    RemovedAPI(
        group="authentication.k8s.io", version="v1beta1", kind="TokenReview",
        removal_version="1.22",
        replacement_group="authentication.k8s.io", replacement_version="v1", replacement_kind="TokenReview",
        notes="Use authentication.k8s.io/v1."
    ),
    RemovedAPI(
        group="authorization.k8s.io", version="v1beta1", kind="SubjectAccessReview",
        removal_version="1.22",
        replacement_group="authorization.k8s.io", replacement_version="v1", replacement_kind="SubjectAccessReview",
        notes="Use authorization.k8s.io/v1."
    ),
    RemovedAPI(
        group="authorization.k8s.io", version="v1beta1", kind="LocalSubjectAccessReview",
        removal_version="1.22",
        replacement_group="authorization.k8s.io", replacement_version="v1", replacement_kind="LocalSubjectAccessReview",
        notes="Use authorization.k8s.io/v1."
    ),
    RemovedAPI(
        group="authorization.k8s.io", version="v1beta1", kind="SelfSubjectAccessReview",
        removal_version="1.22",
        replacement_group="authorization.k8s.io", replacement_version="v1", replacement_kind="SelfSubjectAccessReview",
        notes="Use authorization.k8s.io/v1."
    ),
    RemovedAPI(
        group="certificates.k8s.io", version="v1beta1", kind="CertificateSigningRequest",
        removal_version="1.22",
        replacement_group="certificates.k8s.io", replacement_version="v1", replacement_kind="CertificateSigningRequest",
        notes="Use certificates.k8s.io/v1."
    ),
    RemovedAPI(
        group="coordination.k8s.io", version="v1beta1", kind="Lease",
        removal_version="1.22",
        replacement_group="coordination.k8s.io", replacement_version="v1", replacement_kind="Lease",
        notes="Use coordination.k8s.io/v1."
    ),
    RemovedAPI(
        group="extensions", version="v1beta1", kind="Ingress",
        removal_version="1.22",
        replacement_group="networking.k8s.io", replacement_version="v1", replacement_kind="Ingress",
        notes="Use networking.k8s.io/v1 Ingress."
    ),
    RemovedAPI(
        group="networking.k8s.io", version="v1beta1", kind="Ingress",
        removal_version="1.22",
        replacement_group="networking.k8s.io", replacement_version="v1", replacement_kind="Ingress",
        notes="Use networking.k8s.io/v1 Ingress."
    ),
    RemovedAPI(
        group="networking.k8s.io", version="v1beta1", kind="IngressClass",
        removal_version="1.22",
        replacement_group="networking.k8s.io", replacement_version="v1", replacement_kind="IngressClass",
        notes="Use networking.k8s.io/v1 IngressClass."
    ),
    RemovedAPI(
        group="rbac.authorization.k8s.io", version="v1beta1", kind="ClusterRole",
        removal_version="1.22",
        replacement_group="rbac.authorization.k8s.io", replacement_version="v1", replacement_kind="ClusterRole",
        notes="Use rbac.authorization.k8s.io/v1."
    ),
    RemovedAPI(
        group="rbac.authorization.k8s.io", version="v1beta1", kind="ClusterRoleBinding",
        removal_version="1.22",
        replacement_group="rbac.authorization.k8s.io", replacement_version="v1", replacement_kind="ClusterRoleBinding",
        notes="Use rbac.authorization.k8s.io/v1."
    ),
    RemovedAPI(
        group="rbac.authorization.k8s.io", version="v1beta1", kind="Role",
        removal_version="1.22",
        replacement_group="rbac.authorization.k8s.io", replacement_version="v1", replacement_kind="Role",
        notes="Use rbac.authorization.k8s.io/v1."
    ),
    RemovedAPI(
        group="rbac.authorization.k8s.io", version="v1beta1", kind="RoleBinding",
        removal_version="1.22",
        replacement_group="rbac.authorization.k8s.io", replacement_version="v1", replacement_kind="RoleBinding",
        notes="Use rbac.authorization.k8s.io/v1."
    ),
    RemovedAPI(
        group="scheduling.k8s.io", version="v1beta1", kind="PriorityClass",
        removal_version="1.22",
        replacement_group="scheduling.k8s.io", replacement_version="v1", replacement_kind="PriorityClass",
        notes="Use scheduling.k8s.io/v1."
    ),
    RemovedAPI(
        group="storage.k8s.io", version="v1beta1", kind="CSIDriver",
        removal_version="1.22",
        replacement_group="storage.k8s.io", replacement_version="v1", replacement_kind="CSIDriver",
        notes="Use storage.k8s.io/v1."
    ),
    RemovedAPI(
        group="storage.k8s.io", version="v1beta1", kind="CSINode",
        removal_version="1.22",
        replacement_group="storage.k8s.io", replacement_version="v1", replacement_kind="CSINode",
        notes="Use storage.k8s.io/v1."
    ),
    RemovedAPI(
        group="storage.k8s.io", version="v1beta1", kind="StorageClass",
        removal_version="1.22",
        replacement_group="storage.k8s.io", replacement_version="v1", replacement_kind="StorageClass",
        notes="Use storage.k8s.io/v1."
    ),
    RemovedAPI(
        group="storage.k8s.io", version="v1beta1", kind="VolumeAttachment",
        removal_version="1.22",
        replacement_group="storage.k8s.io", replacement_version="v1", replacement_kind="VolumeAttachment",
        notes="Use storage.k8s.io/v1."
    ),

    # ---- Removed in v1.25 ----
    RemovedAPI(
        group="policy", version="v1beta1", kind="PodSecurityPolicy",
        removal_version="1.25",
        replacement_group="", replacement_version="", replacement_kind="",
        notes="PodSecurityPolicy is removed entirely. Use Pod Security Admission (PSA) or third-party policy engines (Kyverno, Gatekeeper)."
    ),
    RemovedAPI(
        group="policy", version="v1beta1", kind="PodDisruptionBudget",
        removal_version="1.25",
        replacement_group="policy", replacement_version="v1", replacement_kind="PodDisruptionBudget",
        notes="Use policy/v1 PodDisruptionBudget."
    ),
    RemovedAPI(
        group="batch", version="v1beta1", kind="CronJob",
        removal_version="1.25",
        replacement_group="batch", replacement_version="v1", replacement_kind="CronJob",
        notes="Use batch/v1 CronJob."
    ),
    RemovedAPI(
        group="autoscaling", version="v2beta1", kind="HorizontalPodAutoscaler",
        removal_version="1.25",
        replacement_group="autoscaling", replacement_version="v2", replacement_kind="HorizontalPodAutoscaler",
        notes="Use autoscaling/v2 HPA."
    ),
    RemovedAPI(
        group="discovery.k8s.io", version="v1beta1", kind="EndpointSlice",
        removal_version="1.25",
        replacement_group="discovery.k8s.io", replacement_version="v1", replacement_kind="EndpointSlice",
        notes="Use discovery.k8s.io/v1 EndpointSlice."
    ),
    RemovedAPI(
        group="events.k8s.io", version="v1beta1", kind="Event",
        removal_version="1.25",
        replacement_group="events.k8s.io", replacement_version="v1", replacement_kind="Event",
        notes="Use events.k8s.io/v1 Event."
    ),
    RemovedAPI(
        group="node.k8s.io", version="v1beta1", kind="RuntimeClass",
        removal_version="1.25",
        replacement_group="node.k8s.io", replacement_version="v1", replacement_kind="RuntimeClass",
        notes="Use node.k8s.io/v1 RuntimeClass."
    ),

    # ---- Removed in v1.26 ----
    RemovedAPI(
        group="flowcontrol.apiserver.k8s.io", version="v1beta1", kind="FlowSchema",
        removal_version="1.26",
        replacement_group="flowcontrol.apiserver.k8s.io", replacement_version="v1beta2", replacement_kind="FlowSchema",
        notes="Use flowcontrol.apiserver.k8s.io/v1beta2 or v1beta3."
    ),
    RemovedAPI(
        group="flowcontrol.apiserver.k8s.io", version="v1beta1", kind="PriorityLevelConfiguration",
        removal_version="1.26",
        replacement_group="flowcontrol.apiserver.k8s.io", replacement_version="v1beta2", replacement_kind="PriorityLevelConfiguration",
        notes="Use flowcontrol.apiserver.k8s.io/v1beta2 or v1beta3."
    ),
    RemovedAPI(
        group="autoscaling", version="v2beta2", kind="HorizontalPodAutoscaler",
        removal_version="1.26",
        replacement_group="autoscaling", replacement_version="v2", replacement_kind="HorizontalPodAutoscaler",
        notes="Use autoscaling/v2 HPA."
    ),

    # ---- Removed in v1.27 ----
    RemovedAPI(
        group="storage.k8s.io", version="v1beta1", kind="CSIStorageCapacity",
        removal_version="1.27",
        replacement_group="storage.k8s.io", replacement_version="v1", replacement_kind="CSIStorageCapacity",
        notes="Use storage.k8s.io/v1 CSIStorageCapacity."
    ),

    # ---- Removed in v1.29 ----
    RemovedAPI(
        group="flowcontrol.apiserver.k8s.io", version="v1beta2", kind="FlowSchema",
        removal_version="1.29",
        replacement_group="flowcontrol.apiserver.k8s.io", replacement_version="v1beta3", replacement_kind="FlowSchema",
        notes="Use flowcontrol.apiserver.k8s.io/v1beta3 or v1."
    ),
    RemovedAPI(
        group="flowcontrol.apiserver.k8s.io", version="v1beta2", kind="PriorityLevelConfiguration",
        removal_version="1.29",
        replacement_group="flowcontrol.apiserver.k8s.io", replacement_version="v1beta3", replacement_kind="PriorityLevelConfiguration",
        notes="Use flowcontrol.apiserver.k8s.io/v1beta3 or v1."
    ),

    # ---- Removed in v1.32 ----
    RemovedAPI(
        group="flowcontrol.apiserver.k8s.io", version="v1beta3", kind="FlowSchema",
        removal_version="1.32",
        replacement_group="flowcontrol.apiserver.k8s.io", replacement_version="v1", replacement_kind="FlowSchema",
        notes="Use flowcontrol.apiserver.k8s.io/v1."
    ),
    RemovedAPI(
        group="flowcontrol.apiserver.k8s.io", version="v1beta3", kind="PriorityLevelConfiguration",
        removal_version="1.32",
        replacement_group="flowcontrol.apiserver.k8s.io", replacement_version="v1", replacement_kind="PriorityLevelConfiguration",
        notes="Use flowcontrol.apiserver.k8s.io/v1."
    ),
]


# ---------------------------------------------------------------------------
# Deprecated APIs Database
# ---------------------------------------------------------------------------

DEPRECATED_APIS: List[DeprecatedAPI] = [
    DeprecatedAPI(
        group="autoscaling", version="v2beta1", kind="HorizontalPodAutoscaler",
        deprecated_in_version="1.22",
        planned_removal_version="1.25",
        replacement_group="autoscaling", replacement_version="v2", replacement_kind="HorizontalPodAutoscaler",
    ),
    DeprecatedAPI(
        group="autoscaling", version="v2beta2", kind="HorizontalPodAutoscaler",
        deprecated_in_version="1.23",
        planned_removal_version="1.26",
        replacement_group="autoscaling", replacement_version="v2", replacement_kind="HorizontalPodAutoscaler",
    ),
    DeprecatedAPI(
        group="storage.k8s.io", version="v1beta1", kind="CSIStorageCapacity",
        deprecated_in_version="1.24",
        planned_removal_version="1.27",
        replacement_group="storage.k8s.io", replacement_version="v1", replacement_kind="CSIStorageCapacity",
    ),
    DeprecatedAPI(
        group="flowcontrol.apiserver.k8s.io", version="v1beta2", kind="FlowSchema",
        deprecated_in_version="1.26",
        planned_removal_version="1.29",
        replacement_group="flowcontrol.apiserver.k8s.io", replacement_version="v1beta3", replacement_kind="FlowSchema",
    ),
    DeprecatedAPI(
        group="flowcontrol.apiserver.k8s.io", version="v1beta3", kind="FlowSchema",
        deprecated_in_version="1.29",
        planned_removal_version="1.32",
        replacement_group="flowcontrol.apiserver.k8s.io", replacement_version="v1", replacement_kind="FlowSchema",
    ),
]


# ---------------------------------------------------------------------------
# Breaking Behavioral Changes Database
# ---------------------------------------------------------------------------

BEHAVIORAL_CHANGES: List[BehavioralChange] = [
    # v1.22
    BehavioralChange(
        version="1.22",
        category="API",
        severity="Critical",
        title="Ingress GA - extensions/v1beta1 and networking.k8s.io/v1beta1 Ingress removed",
        description="Ingress resources only supported via networking.k8s.io/v1.",
        impact="Ingress controllers and tooling using old API version will fail.",
        mitigation="Upgrade ingress manifests and controller to v1 API."
    ),
    BehavioralChange(
        version="1.22",
        category="API",
        severity="Critical",
        title="Webhook configurations require v1 API",
        description="MutatingWebhookConfiguration and ValidatingWebhookConfiguration only available via admissionregistration.k8s.io/v1.",
        impact="Operators deploying webhooks using beta API will fail.",
        mitigation="Update operator versions that support v1 webhook API."
    ),

    # v1.24
    BehavioralChange(
        version="1.24",
        category="Runtime",
        severity="High",
        title="Dockershim removed from kubelet",
        description="Docker was removed as a container runtime interface. Nodes must use containerd, CRI-O, or another CRI-compatible runtime.",
        impact="Nodes still using Docker as the container runtime will have kubelet fail to start.",
        mitigation="Migrate all nodes to containerd or CRI-O before upgrading to 1.24."
    ),
    BehavioralChange(
        version="1.24",
        category="Security",
        severity="Medium",
        title="LegacyServiceAccountTokenNoAutoGeneration feature gate enabled by default",
        description="Service account token secrets are no longer automatically generated.",
        impact="Workloads relying on auto-generated SA token secrets may fail.",
        mitigation="Explicitly create service account tokens if needed."
    ),
    BehavioralChange(
        version="1.24",
        category="Security",
        severity="High",
        title="Service Account tokens using TokenRequest API",
        description="ServiceAccount tokens are now bound to pod lifetimes via the TokenRequest API.",
        impact="Long-lived static tokens no longer automatically created.",
        mitigation="Update applications to handle token rotation or explicitly create long-lived tokens."
    ),

    # v1.25
    BehavioralChange(
        version="1.25",
        category="Security",
        severity="Critical",
        title="PodSecurityPolicy (PSP) removed",
        description="The PodSecurityPolicy admission controller and API (policy/v1beta1 PodSecurityPolicy) is completely removed.",
        impact="Clusters using PSP will have all workloads fail to start after upgrade. PSP admission controller will be missing.",
        mitigation="Migrate to Pod Security Admission (PSA) built-in labels or third-party policy tools (Kyverno, OPA/Gatekeeper) BEFORE upgrading."
    ),
    BehavioralChange(
        version="1.25",
        category="Runtime",
        severity="High",
        title="cgroup v2 support stabilized",
        description="cgroup v2 is now supported and some distributions enable it by default.",
        impact="Controllers/agents that do not support cgroup v2 may fail.",
        mitigation="Ensure all node agents, monitoring tools, and runtime components support cgroup v2."
    ),
    BehavioralChange(
        version="1.25",
        category="Security",
        severity="Medium",
        title="Pod Security Admission (PSA) graduated to stable",
        description="PSA enforces pod security standards at namespace level.",
        impact="Namespaces labeled with enforce/restricted may block non-compliant workloads.",
        mitigation="Audit namespace labels and workload security contexts."
    ),
    BehavioralChange(
        version="1.25",
        category="API",
        severity="High",
        title="CronJob batch/v1beta1 removed",
        description="CronJob only available via batch/v1.",
        impact="CronJob resources using batch/v1beta1 will fail.",
        mitigation="Update CronJob manifests to batch/v1."
    ),

    # v1.26
    BehavioralChange(
        version="1.26",
        category="API",
        severity="High",
        title="Dynamic kubelet configuration removed",
        description="The --dynamic-config-dir kubelet flag and dynamic kubelet configuration feature is removed.",
        impact="Clusters using dynamic kubelet config will lose that feature.",
        mitigation="Remove dynamic kubelet config and manage kubelet config statically."
    ),
    BehavioralChange(
        version="1.26",
        category="Networking",
        severity="Medium",
        title="CPUManagerPolicyBetaOptionsEnabled feature gate stable",
        description="CPU manager policy options promoted.",
        impact="Minor policy behavior changes for CPU-pinned workloads.",
        mitigation="Review CPU manager configuration."
    ),
    BehavioralChange(
        version="1.26",
        category="API",
        severity="High",
        title="FlowSchema v1beta1 removed",
        description="API priority and fairness (flowcontrol.apiserver.k8s.io/v1beta1) removed.",
        impact="Tooling using v1beta1 flow control resources will fail.",
        mitigation="Use v1beta2 or v1beta3."
    ),

    # v1.27
    BehavioralChange(
        version="1.27",
        category="Security",
        severity="High",
        title="SeccompDefault graduated to GA",
        description="SeccompDefault feature (--seccomp-default flag) graduated. Enables RuntimeDefault seccomp profile by default on nodes with the feature enabled.",
        impact="Containers without explicit seccomp profile may have syscalls blocked.",
        mitigation="Audit seccomp profiles for all workloads. Test with --seccomp-default before enabling."
    ),
    BehavioralChange(
        version="1.27",
        category="API",
        severity="Medium",
        title="StatefulSet PVC auto-deletion feature beta",
        description="StatefulSets can now auto-delete PVCs via the whenDeleted/whenScaled policy.",
        impact="Potentially unexpected PVC deletion if policy is misconfigured.",
        mitigation="Review StatefulSet PVC retention policies."
    ),

    # v1.28
    BehavioralChange(
        version="1.28",
        category="Runtime",
        severity="Medium",
        title="Mixed version proxying for kube-apiserver",
        description="kube-apiserver can proxy requests to older API servers during upgrade.",
        impact="Potential for version skew during rolling upgrades.",
        mitigation="Understand version skew policy during control plane upgrades."
    ),
    BehavioralChange(
        version="1.28",
        category="Security",
        severity="Medium",
        title="Node lifecycle controller improvements",
        description="Node lifecycle controller taint-based eviction improvements.",
        impact="Node taints may cause more aggressive workload eviction.",
        mitigation="Review workload toleration configurations."
    ),
    BehavioralChange(
        version="1.28",
        category="Networking",
        severity="Medium",
        title="Service LoadBalancer IP mode field",
        description="New LoadBalancerIPMode field for Services affects ingress traffic behavior.",
        impact="LoadBalancer-type services behavior change in some CNI configurations.",
        mitigation="Verify LoadBalancer service behavior post-upgrade."
    ),

    # v1.29
    BehavioralChange(
        version="1.29",
        category="API",
        severity="Medium",
        title="ReadWriteOncePod PersistentVolume access mode GA",
        description="ReadWriteOncePod PVC access mode graduated to stable.",
        impact="PVCs using RWOP require compatible CSI driver support.",
        mitigation="Ensure CSI drivers support ReadWriteOncePod."
    ),
    BehavioralChange(
        version="1.29",
        category="Networking",
        severity="Low",
        title="kube-proxy nftables backend beta",
        description="kube-proxy nftables mode available as beta. iptables mode still default.",
        impact="No breaking change unless nftables mode explicitly enabled.",
        mitigation="If testing nftables mode, ensure CNI compatibility."
    ),
    BehavioralChange(
        version="1.29",
        category="API",
        severity="High",
        title="FlowSchema v1beta2 removed",
        description="flowcontrol.apiserver.k8s.io/v1beta2 removed. Use v1beta3 or v1.",
        impact="Tooling using v1beta2 will break.",
        mitigation="Update to v1beta3 or v1."
    ),
    BehavioralChange(
        version="1.29",
        category="Runtime",
        severity="Medium",
        title="In-tree cloud provider code removal continued",
        description="More in-tree cloud provider code removed; external cloud-controller-manager required.",
        impact="Clusters using in-tree cloud provider may lose cloud integration.",
        mitigation="Use external cloud-controller-manager appropriate for cloud provider."
    ),

    # v1.30
    BehavioralChange(
        version="1.30",
        category="Networking",
        severity="Medium",
        title="AppArmor support graduated to GA",
        description="AppArmor pod security policy fields graduated.",
        impact="AppArmor configuration changes may affect existing workloads.",
        mitigation="Review AppArmor profiles for workloads."
    ),

    # v1.31
    BehavioralChange(
        version="1.31",
        category="API",
        severity="Medium",
        title="VolumeAttributesClass API beta",
        description="VolumeAttributesClass introduces dynamic modification of volumes.",
        impact="New API, additive. Storage behavior may change if controllers handle it.",
        mitigation="Update CSI drivers and storage controllers."
    ),

    # v1.32
    BehavioralChange(
        version="1.32",
        category="API",
        severity="High",
        title="FlowSchema v1beta3 removed",
        description="flowcontrol.apiserver.k8s.io/v1beta3 removed. Only v1 remains.",
        impact="Tooling using v1beta3 will break.",
        mitigation="Update to v1."
    ),

    # v1.33
    BehavioralChange(
        version="1.33",
        category="API",
        severity="Medium",
        title="Sidecar containers graduated to GA",
        description="Init containers with restartPolicy=Always (sidecar containers) graduated to stable.",
        impact="Additive feature. No breaking change but behavior now stable.",
        mitigation="Update documentation and tooling to use GA field."
    ),
    BehavioralChange(
        version="1.33",
        category="Security",
        severity="Medium",
        title="PodCertificateRequest API beta",
        description="New API for pods to request certificates from the API server.",
        impact="Additive. Operators may need updated RBAC to use this feature.",
        mitigation="No action required unless using the feature."
    ),
]


# ---------------------------------------------------------------------------
# Operator Compatibility Matrix
# ---------------------------------------------------------------------------

OPERATOR_COMPATIBILITY: List[OperatorCompatibility] = [
    OperatorCompatibility(
        name="cert-manager",
        display_name="cert-manager",
        detection_labels=["app.kubernetes.io/name=cert-manager", "app=cert-manager"],
        detection_namespaces=["cert-manager"],
        detection_deployments=["cert-manager", "cert-manager-cainjector", "cert-manager-webhook"],
        min_k8s_version="1.22",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.21", "1.25"),  # cert-manager v1.8
            ("1.22", "1.27"),  # cert-manager v1.10-v1.11
            ("1.24", "1.29"),  # cert-manager v1.12
            ("1.25", "1.31"),  # cert-manager v1.13-v1.14
            ("1.27", "1.33"),  # cert-manager v1.15+
        ],
        notes="cert-manager v1.12+ required for K8s 1.28+. cert-manager v1.14+ for K8s 1.30+.",
        upgrade_notes="Upgrade cert-manager before upgrading Kubernetes to ensure webhook compatibility.",
        must_upgrade_before=True,
        compatibility_url="https://cert-manager.io/docs/releases/"
    ),
    OperatorCompatibility(
        name="ingress-nginx",
        display_name="ingress-nginx",
        detection_labels=["app.kubernetes.io/name=ingress-nginx"],
        detection_namespaces=["ingress-nginx"],
        detection_deployments=["ingress-nginx-controller"],
        min_k8s_version="1.22",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.19", "1.23"),  # v1.0.x
            ("1.21", "1.25"),  # v1.2.x
            ("1.24", "1.27"),  # v1.5.x
            ("1.25", "1.29"),  # v1.6.x-v1.7.x
            ("1.27", "1.31"),  # v1.8.x-v1.9.x
            ("1.29", "1.34"),  # v1.10.x+
        ],
        notes="Requires networking.k8s.io/v1 Ingress (K8s 1.19+). Older versions break on 1.22.",
        upgrade_notes="Always check ingress-nginx support matrix. Upgrade to latest compatible version first.",
        must_upgrade_before=True,
        compatibility_url="https://github.com/kubernetes/ingress-nginx#supported-versions-table"
    ),
    OperatorCompatibility(
        name="metrics-server",
        display_name="Metrics Server",
        detection_labels=["app.kubernetes.io/name=metrics-server", "k8s-app=metrics-server"],
        detection_namespaces=["kube-system"],
        detection_deployments=["metrics-server"],
        min_k8s_version="1.21",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.21", "1.34"),  # metrics-server v0.6+
        ],
        notes="metrics-server v0.6+ supports Kubernetes 1.21+. Generally very forward compatible.",
        upgrade_notes="Upgrade metrics-server after Kubernetes upgrade if needed.",
        must_upgrade_before=False,
        compatibility_url="https://github.com/kubernetes-sigs/metrics-server#compatibility-matrix"
    ),
    OperatorCompatibility(
        name="cluster-autoscaler",
        display_name="Cluster Autoscaler",
        detection_labels=["app=cluster-autoscaler", "app.kubernetes.io/name=cluster-autoscaler"],
        detection_namespaces=["kube-system"],
        detection_deployments=["cluster-autoscaler"],
        min_k8s_version="1.22",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.22", "1.22"),  # CA 1.22.x - exact minor match required
            ("1.23", "1.23"),  # CA 1.23.x
            ("1.24", "1.24"),  # CA 1.24.x
            ("1.25", "1.25"),  # CA 1.25.x
            ("1.26", "1.26"),  # CA 1.26.x
            ("1.27", "1.27"),  # CA 1.27.x
            ("1.28", "1.28"),  # CA 1.28.x
            ("1.29", "1.29"),  # CA 1.29.x
            ("1.30", "1.30"),  # CA 1.30.x
            ("1.31", "1.31"),  # CA 1.31.x
            ("1.32", "1.32"),  # CA 1.32.x
            ("1.33", "1.33"),  # CA 1.33.x
            ("1.34", "1.34"),  # CA 1.34.x
        ],
        notes="Cluster Autoscaler version must EXACTLY match Kubernetes minor version. Mismatched versions are NOT supported by upstream.",
        upgrade_notes="CRITICAL: Upgrade cluster-autoscaler to match target Kubernetes minor version AFTER control plane upgrade, before node upgrade.",
        must_upgrade_before=False,
        compatibility_url="https://github.com/kubernetes/autoscaler/tree/master/cluster-autoscaler#releases"
    ),
    OperatorCompatibility(
        name="kube-prometheus-stack",
        display_name="kube-prometheus-stack / prometheus-operator",
        detection_labels=["app=kube-prometheus-stack", "app.kubernetes.io/name=kube-prometheus-stack"],
        detection_namespaces=["monitoring", "prometheus"],
        detection_deployments=["prometheus-operator", "kube-prometheus-stack-operator"],
        min_k8s_version="1.21",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.21", "1.27"),  # kps 45.x - 51.x
            ("1.24", "1.30"),  # kps 52.x - 58.x
            ("1.27", "1.34"),  # kps 59.x+
        ],
        notes="Check kube-prometheus-stack chart version vs K8s compatibility. Older versions may have incompatible CRDs.",
        upgrade_notes="Upgrade prometheus-operator after Kubernetes upgrade. CRDs may need migration.",
        must_upgrade_before=False,
        compatibility_url="https://github.com/prometheus-community/helm-charts/tree/main/charts/kube-prometheus-stack"
    ),
    OperatorCompatibility(
        name="argo-cd",
        display_name="Argo CD",
        detection_labels=["app.kubernetes.io/name=argocd-server", "app.kubernetes.io/part-of=argocd"],
        detection_namespaces=["argocd"],
        detection_deployments=["argocd-server", "argocd-application-controller"],
        min_k8s_version="1.21",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.21", "1.26"),  # ArgoCD 2.5.x
            ("1.23", "1.28"),  # ArgoCD 2.6.x - 2.7.x
            ("1.25", "1.30"),  # ArgoCD 2.8.x - 2.9.x
            ("1.27", "1.32"),  # ArgoCD 2.10.x - 2.11.x
            ("1.29", "1.34"),  # ArgoCD 2.12.x+
        ],
        notes="Argo CD follows K8s support matrix. Each ArgoCD minor supports 3 K8s minors.",
        upgrade_notes="Upgrade Argo CD to latest stable compatible version before or after Kubernetes upgrade.",
        must_upgrade_before=False,
        compatibility_url="https://argo-cd.readthedocs.io/en/stable/operator-manual/installation/"
    ),
    OperatorCompatibility(
        name="flux",
        display_name="Flux CD (FluxCD v2)",
        detection_labels=["app.kubernetes.io/part-of=flux"],
        detection_namespaces=["flux-system"],
        detection_deployments=["helm-controller", "kustomize-controller", "source-controller"],
        min_k8s_version="1.22",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.22", "1.34"),  # Flux v2.x generally compatible
        ],
        notes="Flux v2 generally compatible with K8s 1.22+. Check release notes for specific versions.",
        upgrade_notes="Upgrade Flux after Kubernetes upgrade if CRD changes are needed.",
        must_upgrade_before=False,
        compatibility_url="https://fluxcd.io/flux/installation/#prerequisites"
    ),
    OperatorCompatibility(
        name="crossplane",
        display_name="Crossplane",
        detection_labels=["app=crossplane", "app.kubernetes.io/name=crossplane"],
        detection_namespaces=["crossplane-system"],
        detection_deployments=["crossplane", "crossplane-rbac-manager"],
        min_k8s_version="1.22",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.22", "1.34"),  # Crossplane v1.12+
        ],
        notes="Crossplane v1.12+ supports Kubernetes 1.22+. Check provider compatibility.",
        upgrade_notes="Test Crossplane providers after upgrade. CRD schema changes may require provider updates.",
        must_upgrade_before=False,
        compatibility_url="https://docs.crossplane.io/latest/software/"
    ),
    OperatorCompatibility(
        name="istio",
        display_name="Istio Service Mesh",
        detection_labels=["app=istiod", "istio=pilot"],
        detection_namespaces=["istio-system"],
        detection_deployments=["istiod"],
        min_k8s_version="1.25",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.22", "1.26"),  # Istio 1.16.x - 1.17.x
            ("1.24", "1.28"),  # Istio 1.18.x - 1.19.x
            ("1.26", "1.30"),  # Istio 1.20.x - 1.21.x
            ("1.28", "1.32"),  # Istio 1.22.x - 1.23.x
            ("1.30", "1.34"),  # Istio 1.24.x+
        ],
        notes="Istio supports ~3 K8s minor versions per Istio minor. Check Istio-K8s compatibility matrix carefully.",
        upgrade_notes="CRITICAL: Upgrade Istio before Kubernetes upgrade if possible. Istio control plane and data plane must be compatible.",
        must_upgrade_before=True,
        compatibility_url="https://istio.io/latest/docs/releases/supported-releases/"
    ),
    OperatorCompatibility(
        name="linkerd",
        display_name="Linkerd Service Mesh",
        detection_labels=["linkerd.io/control-plane-component=controller"],
        detection_namespaces=["linkerd"],
        detection_deployments=["linkerd-controller", "linkerd-destination"],
        min_k8s_version="1.22",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.22", "1.34"),  # Linkerd 2.12+ generally compatible
        ],
        notes="Linkerd generally tracks Kubernetes support closely. Check release notes.",
        upgrade_notes="Linkerd data plane proxies restart on node upgrade. Verify proxy injection after upgrade.",
        must_upgrade_before=False,
        compatibility_url="https://linkerd.io/2.14/reference/k8s-versions/"
    ),
    OperatorCompatibility(
        name="gatekeeper",
        display_name="OPA Gatekeeper",
        detection_labels=["app=gatekeeper", "control-plane=controller-manager"],
        detection_namespaces=["gatekeeper-system"],
        detection_deployments=["gatekeeper-controller-manager", "gatekeeper-audit"],
        min_k8s_version="1.22",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.22", "1.34"),  # Gatekeeper v3.10+
        ],
        notes="Gatekeeper v3.10+ supports K8s 1.22+. Webhook failure policy is important to review.",
        upgrade_notes="Ensure Gatekeeper webhook failure policy is not set to Fail (which could block workloads if Gatekeeper is down).",
        must_upgrade_before=False,
        compatibility_url="https://open-policy-agent.github.io/gatekeeper/website/docs/install/"
    ),
    OperatorCompatibility(
        name="kyverno",
        display_name="Kyverno",
        detection_labels=["app.kubernetes.io/name=kyverno"],
        detection_namespaces=["kyverno"],
        detection_deployments=["kyverno", "kyverno-admission-controller"],
        min_k8s_version="1.22",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.22", "1.27"),  # Kyverno 1.9.x - 1.10.x
            ("1.24", "1.30"),  # Kyverno 1.11.x
            ("1.26", "1.32"),  # Kyverno 1.12.x
            ("1.28", "1.34"),  # Kyverno 1.13.x+
        ],
        notes="Kyverno version must align with K8s version. Policy admission webhooks could block workloads if incompatible.",
        upgrade_notes="Upgrade Kyverno after Kubernetes upgrade. Monitor webhook failure policies.",
        must_upgrade_before=False,
        compatibility_url="https://kyverno.io/docs/installation/#compatibility-matrix"
    ),
    OperatorCompatibility(
        name="velero",
        display_name="Velero",
        detection_labels=["app.kubernetes.io/name=velero"],
        detection_namespaces=["velero"],
        detection_deployments=["velero"],
        min_k8s_version="1.20",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.20", "1.34"),  # Velero v1.11+ broadly compatible
        ],
        notes="Velero is broadly compatible. Ensure backup provider plugins match.",
        upgrade_notes="Upgrade Velero after Kubernetes upgrade. Take a backup before upgrade.",
        must_upgrade_before=False,
        compatibility_url="https://velero.io/docs/main/basic-install/"
    ),
    OperatorCompatibility(
        name="karpenter",
        display_name="Karpenter",
        detection_labels=["app.kubernetes.io/name=karpenter"],
        detection_namespaces=["karpenter"],
        detection_deployments=["karpenter"],
        min_k8s_version="1.25",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.25", "1.29"),  # Karpenter v0.30.x - v0.35.x
            ("1.27", "1.32"),  # Karpenter v0.36.x - v1.0.x
            ("1.29", "1.34"),  # Karpenter v1.1.x+
        ],
        notes="Karpenter provisions nodes; version must be compatible with K8s control plane.",
        upgrade_notes="Upgrade Karpenter AFTER control plane upgrade. Node provisioning may be disrupted.",
        must_upgrade_before=False,
        compatibility_url="https://karpenter.sh/docs/upgrading/compatibility/"
    ),
    OperatorCompatibility(
        name="aws-load-balancer-controller",
        display_name="AWS Load Balancer Controller",
        detection_labels=["app.kubernetes.io/name=aws-load-balancer-controller"],
        detection_namespaces=["kube-system"],
        detection_deployments=["aws-load-balancer-controller"],
        min_k8s_version="1.22",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.22", "1.34"),  # AWS LBC v2.5+ broadly compatible
        ],
        notes="AWS LBC v2.5+ supports K8s 1.22+. Uses networking.k8s.io/v1 Ingress.",
        upgrade_notes="Upgrade AWS LBC to latest version before or after Kubernetes upgrade.",
        must_upgrade_before=False,
        compatibility_url="https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/"
    ),
    OperatorCompatibility(
        name="ebs-csi-driver",
        display_name="AWS EBS CSI Driver",
        detection_labels=["app.kubernetes.io/name=aws-ebs-csi-driver"],
        detection_namespaces=["kube-system"],
        detection_deployments=["ebs-csi-controller"],
        min_k8s_version="1.22",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.22", "1.34"),  # EBS CSI v1.x broadly compatible
        ],
        notes="EBS CSI driver v1.x supports K8s 1.22+. Required for EBS volumes with in-tree removal.",
        upgrade_notes="Ensure EBS CSI is installed before upgrading to K8s versions that remove in-tree provider.",
        must_upgrade_before=True,
        compatibility_url="https://github.com/kubernetes-sigs/aws-ebs-csi-driver"
    ),
    OperatorCompatibility(
        name="efs-csi-driver",
        display_name="AWS EFS CSI Driver",
        detection_labels=["app.kubernetes.io/name=aws-efs-csi-driver"],
        detection_namespaces=["kube-system"],
        detection_deployments=["efs-csi-controller"],
        min_k8s_version="1.22",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.22", "1.34"),  # EFS CSI v1.x broadly compatible
        ],
        notes="EFS CSI driver broadly compatible with K8s 1.22+.",
        upgrade_notes="Upgrade EFS CSI driver after Kubernetes upgrade if needed.",
        must_upgrade_before=False,
        compatibility_url="https://github.com/kubernetes-sigs/aws-efs-csi-driver"
    ),
    OperatorCompatibility(
        name="cilium",
        display_name="Cilium CNI",
        detection_labels=["app.kubernetes.io/name=cilium", "k8s-app=cilium"],
        detection_namespaces=["kube-system", "cilium"],
        detection_deployments=["cilium-operator"],
        min_k8s_version="1.21",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.21", "1.26"),  # Cilium 1.12.x - 1.13.x
            ("1.23", "1.28"),  # Cilium 1.14.x
            ("1.25", "1.30"),  # Cilium 1.15.x
            ("1.27", "1.32"),  # Cilium 1.16.x
            ("1.29", "1.34"),  # Cilium 1.17.x+
        ],
        notes="CRITICAL: Cilium CNI must be compatible with Kubernetes version. CNI incompatibility causes cluster-wide networking failure.",
        upgrade_notes="CRITICAL: Upgrade Cilium BEFORE Kubernetes control plane upgrade. Incompatible Cilium will break cluster networking.",
        must_upgrade_before=True,
        compatibility_url="https://docs.cilium.io/en/stable/network/kubernetes/compatibility/"
    ),
    OperatorCompatibility(
        name="calico",
        display_name="Calico CNI / Network Policy",
        detection_labels=["app.kubernetes.io/name=calico", "k8s-app=calico-node"],
        detection_namespaces=["kube-system", "calico-system"],
        detection_deployments=["calico-kube-controllers"],
        min_k8s_version="1.21",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.21", "1.34"),  # Calico v3.24+ broadly compatible
        ],
        notes="Calico generally compatible across a wide range of K8s versions. Check release notes for specific versions.",
        upgrade_notes="Calico is generally safe to upgrade after Kubernetes upgrade.",
        must_upgrade_before=False,
        compatibility_url="https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements"
    ),
    OperatorCompatibility(
        name="antrea",
        display_name="Antrea CNI",
        detection_labels=["app=antrea"],
        detection_namespaces=["kube-system"],
        detection_deployments=["antrea-controller"],
        min_k8s_version="1.21",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.21", "1.34"),  # Antrea v1.x broadly compatible
        ],
        notes="Antrea generally supports multiple K8s minor versions. Check release notes.",
        upgrade_notes="Upgrade Antrea to compatible version before or after Kubernetes upgrade.",
        must_upgrade_before=False,
        compatibility_url="https://antrea.io/docs/main/docs/support-matrix/"
    ),
    OperatorCompatibility(
        name="external-dns",
        display_name="ExternalDNS",
        detection_labels=["app.kubernetes.io/name=external-dns", "app=external-dns"],
        detection_namespaces=["external-dns", "kube-system"],
        detection_deployments=["external-dns"],
        min_k8s_version="1.21",
        max_k8s_version="1.34",
        supported_ranges=[
            ("1.21", "1.34"),  # ExternalDNS broadly compatible
        ],
        notes="ExternalDNS broadly compatible with K8s 1.21+.",
        upgrade_notes="Upgrade ExternalDNS after Kubernetes upgrade if needed.",
        must_upgrade_before=False,
        compatibility_url="https://github.com/kubernetes-sigs/external-dns"
    ),
]


# ---------------------------------------------------------------------------
# CRI Compatibility Matrix
# ---------------------------------------------------------------------------

# Map: k8s_version -> list of supported CRI runtimes
CRI_COMPATIBILITY: Dict[str, List[str]] = {
    "1.20": ["containerd 1.3+", "CRI-O 1.20", "dockershim (deprecated)"],
    "1.21": ["containerd 1.4+", "CRI-O 1.21", "dockershim (deprecated)"],
    "1.22": ["containerd 1.4+", "CRI-O 1.22", "dockershim (deprecated)"],
    "1.23": ["containerd 1.5+", "CRI-O 1.23", "dockershim (deprecated)"],
    "1.24": ["containerd 1.5+", "CRI-O 1.24"],  # dockershim REMOVED
    "1.25": ["containerd 1.6+", "CRI-O 1.25"],
    "1.26": ["containerd 1.6+", "CRI-O 1.26"],
    "1.27": ["containerd 1.6+", "CRI-O 1.27"],
    "1.28": ["containerd 1.7+", "CRI-O 1.28"],
    "1.29": ["containerd 1.7+", "CRI-O 1.29"],
    "1.30": ["containerd 1.7+", "CRI-O 1.30"],
    "1.31": ["containerd 1.7+", "CRI-O 1.31"],
    "1.32": ["containerd 2.0+", "CRI-O 1.32"],
    "1.33": ["containerd 2.0+", "CRI-O 1.33"],
    "1.34": ["containerd 2.0+", "CRI-O 1.34"],
}

# Runtimes that use Docker/dockershim (removed in 1.24)
DOCKERSHIM_RUNTIMES = {"docker", "dockershim"}

# CRI runtimes requiring upgrade for given k8s target versions
CRI_MIN_VERSIONS: Dict[str, Dict[str, str]] = {
    "containerd": {
        "1.20": "1.3", "1.21": "1.4", "1.22": "1.4",
        "1.23": "1.5", "1.24": "1.5", "1.25": "1.6",
        "1.26": "1.6", "1.27": "1.6", "1.28": "1.7",
        "1.29": "1.7", "1.30": "1.7", "1.31": "1.7",
        "1.32": "2.0", "1.33": "2.0", "1.34": "2.0",
    }
}


# ---------------------------------------------------------------------------
# Version Utility Functions
# ---------------------------------------------------------------------------

def parse_version(version_str: str) -> Tuple[int, int]:
    """Parse a K8s version string like '1.27' or 'v1.27.3' into (major, minor)."""
    v = version_str.lstrip("v")
    parts = v.split(".")
    major = int(parts[0]) if len(parts) > 0 else 1
    minor = int(parts[1]) if len(parts) > 1 else 0
    return (major, minor)


def version_gte(v1: str, v2: str) -> bool:
    """Return True if v1 >= v2."""
    return parse_version(v1) >= parse_version(v2)


def version_lte(v1: str, v2: str) -> bool:
    """Return True if v1 <= v2."""
    return parse_version(v1) <= parse_version(v2)


def version_gt(v1: str, v2: str) -> bool:
    """Return True if v1 > v2."""
    return parse_version(v1) > parse_version(v2)


def version_lt(v1: str, v2: str) -> bool:
    """Return True if v1 < v2."""
    return parse_version(v1) < parse_version(v2)


def get_intermediate_versions(source: str, target: str) -> List[str]:
    """Return all K8s minor versions between source and target (inclusive of target)."""
    src_major, src_minor = parse_version(source)
    tgt_major, tgt_minor = parse_version(target)
    versions = []
    for minor in range(src_minor + 1, tgt_minor + 1):
        versions.append(f"{src_major}.{minor}")
    return versions


def get_removed_apis_in_range(source: str, target: str) -> List[RemovedAPI]:
    """Return all APIs removed in versions > source and <= target."""
    result = []
    for api in REMOVED_APIS:
        removal = api.removal_version
        if version_gt(removal, source) and version_lte(removal, target):
            result.append(api)
    return result


def get_deprecated_apis_in_range(source: str, target: str) -> List[DeprecatedAPI]:
    """Return all APIs deprecated (planned removal within range or after)."""
    result = []
    for api in DEPRECATED_APIS:
        # Include if planned removal is within or after target (still relevant)
        if version_gt(api.planned_removal_version, source):
            result.append(api)
    return result


def get_behavioral_changes_in_range(source: str, target: str) -> List[BehavioralChange]:
    """Return all behavioral changes introduced in versions > source and <= target."""
    result = []
    for change in BEHAVIORAL_CHANGES:
        v = change.version
        if version_gt(v, source) and version_lte(v, target):
            result.append(change)
    return result


def get_operator_compatibility(operator_name: str) -> Optional[OperatorCompatibility]:
    """Return operator compatibility data for a given operator name."""
    for op in OPERATOR_COMPATIBILITY:
        if op.name == operator_name:
            return op
    return None


def is_operator_compatible(op: OperatorCompatibility, target_k8s_version: str) -> Tuple[bool, str]:
    """
    Check if operator is compatible with target K8s version.
    Returns (is_compatible, reason).
    """
    for (min_v, max_v) in op.supported_ranges:
        if version_gte(target_k8s_version, min_v) and version_lte(target_k8s_version, max_v):
            return True, f"Compatible (supported range {min_v}–{max_v})"
    return False, f"No supported range covers K8s {target_k8s_version}. {op.notes}"


# ---------------------------------------------------------------------------
# K8s Release Summary Database
# ---------------------------------------------------------------------------

K8S_RELEASE_NOTES: Dict[str, str] = {
    "1.22": "Major: All beta API removals (webhooks, RBAC, Ingress, CRDs). Ingress graduates to v1.",
    "1.23": "Dual-stack IPv4/IPv6 stable. HPA autoscaling/v2beta2 deprecated.",
    "1.24": "CRITICAL: Dockershim removed. Token request API changes. LegacyServiceAccount tokens deprecated.",
    "1.25": "CRITICAL: PSP removed. CSI migration stable. cgroup v2 support. Pod Security Admission stable.",
    "1.26": "Dynamic kubelet config removed. FlowSchema v1beta1 removed. HPA autoscaling/v2beta2 removed.",
    "1.27": "SeccompDefault GA. StatefulSet PVC deletion. CSIStorageCapacity v1beta1 removed (1.27).",
    "1.28": "Retroactive StorageClass assignment. Node lifecycle improvements. Mixed version proxy.",
    "1.29": "AppArmor GA. ReadWriteOncePod PVC GA. FlowSchema v1beta2 removed. nftables backend beta.",
    "1.30": "In-tree cloud provider removal continues. Structured authz config. AppArmor graduated.",
    "1.31": "VolumeAttributesClass beta. Persistent volume enhancements.",
    "1.32": "FlowSchema v1beta3 removed (only v1 remains). Topology aware routing improvements.",
    "1.33": "Sidecar containers GA. PodCertificateRequest API beta. Major stability improvements.",
    "1.34": "Latest features. Check official release notes.",
}
