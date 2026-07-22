"""
Kubernetes Release Database & Compatibility Knowledge Base.
Contains detailed version removal histories, deprecations, breaking changes,
and controller/operator compatibility matrices.
"""

from typing import Dict, List, Any, Optional

def parse_version(ver_str: str) -> tuple[int, int]:
    """Parse 'v1.28.2' or '1.28' into (1, 28)."""
    s = ver_str.strip().lstrip('v')
    parts = s.split('.')
    major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 1
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return (major, minor)

def format_version(ver_tuple: tuple[int, int]) -> str:
    return f"v{ver_tuple[0]}.{ver_tuple[1]}"

# Database of Removed APIs
REMOVED_APIS = [
    {
        "api_version": "policy/v1beta1",
        "kind": "PodDisruptionBudget",
        "removed_in": (1, 25),
        "replacement_api": "policy/v1",
        "impact": "Workloads with policy/v1beta1 PodDisruptionBudget manifest will fail to apply or be rejected by API server.",
        "required_action": "Migrate PodDisruptionBudget API version from policy/v1beta1 to policy/v1."
    },
    {
        "api_version": "policy/v1beta1",
        "kind": "PodSecurityPolicy",
        "removed_in": (1, 25),
        "replacement_api": "Pod Security Admission (PSA) / Gatekeeper / Kyverno",
        "impact": "PodSecurityPolicy feature gate is removed entirely. PSP resources will be deleted or unserved. Workloads relying on PSP for permission escalation will fail or be blocked.",
        "required_action": "Migrate to Pod Security Admission (PSA) namespace labels or Kyverno/Gatekeeper policies."
    },
    {
        "api_version": "batch/v1beta1",
        "kind": "CronJob",
        "removed_in": (1, 25),
        "replacement_api": "batch/v1",
        "impact": "CronJob manifests using batch/v1beta1 will fail to validate and reconcile.",
        "required_action": "Update CronJob manifest apiVersion to batch/v1."
    },
    {
        "api_version": "autoscaling/v2beta2",
        "kind": "HorizontalPodAutoscaler",
        "removed_in": (1, 26),
        "replacement_api": "autoscaling/v2",
        "impact": "HorizontalPodAutoscaler resources using v2beta2 will be rejected by API server.",
        "required_action": "Update HPA manifest apiVersion to autoscaling/v2."
    },
    {
        "api_version": "autoscaling/v2beta1",
        "kind": "HorizontalPodAutoscaler",
        "removed_in": (1, 25),
        "replacement_api": "autoscaling/v2",
        "impact": "HorizontalPodAutoscaler resources using v2beta1 will be rejected by API server.",
        "required_action": "Update HPA manifest apiVersion to autoscaling/v2."
    },
    {
        "api_version": "networking.k8s.io/v1beta1",
        "kind": "Ingress",
        "removed_in": (1, 22),
        "replacement_api": "networking.k8s.io/v1",
        "impact": "Ingress manifests using networking.k8s.io/v1beta1 will fail to reconcile.",
        "required_action": "Migrate Ingress to networking.k8s.io/v1."
    },
    {
        "api_version": "networking.k8s.io/v1beta1",
        "kind": "IngressClass",
        "removed_in": (1, 22),
        "replacement_api": "networking.k8s.io/v1",
        "impact": "IngressClass manifests using v1beta1 will fail.",
        "required_action": "Migrate IngressClass to networking.k8s.io/v1."
    },
    {
        "api_version": "admissionregistration.k8s.io/v1beta1",
        "kind": "ValidatingWebhookConfiguration",
        "removed_in": (1, 22),
        "replacement_api": "admissionregistration.k8s.io/v1",
        "impact": "ValidatingWebhookConfiguration using v1beta1 will be unserved.",
        "required_action": "Migrate webhook configuration to admissionregistration.k8s.io/v1."
    },
    {
        "api_version": "admissionregistration.k8s.io/v1beta1",
        "kind": "MutatingWebhookConfiguration",
        "removed_in": (1, 22),
        "replacement_api": "admissionregistration.k8s.io/v1",
        "impact": "MutatingWebhookConfiguration using v1beta1 will be unserved.",
        "required_action": "Migrate webhook configuration to admissionregistration.k8s.io/v1."
    },
    {
        "api_version": "storage.k8s.io/v1beta1",
        "kind": "CSINode",
        "removed_in": (1, 22),
        "replacement_api": "storage.k8s.io/v1",
        "impact": "CSINode resources using v1beta1 fail.",
        "required_action": "Migrate to storage.k8s.io/v1."
    },
    {
        "api_version": "events.k8s.io/v1beta1",
        "kind": "Event",
        "removed_in": (1, 25),
        "replacement_api": "events.k8s.io/v1",
        "impact": "Event collectors using v1beta1 will fail to retrieve events.",
        "required_action": "Migrate event clients to events.k8s.io/v1."
    },
    {
        "api_version": "discovery.k8s.io/v1beta1",
        "kind": "EndpointSlice",
        "removed_in": (1, 25),
        "replacement_api": "discovery.k8s.io/v1",
        "impact": "Custom controllers reading v1beta1 EndpointSlice will fail.",
        "required_action": "Migrate controllers to discovery.k8s.io/v1."
    },
    {
        "api_version": "flowcontrol.apiserver.k8s.io/v1beta2",
        "kind": "FlowSchema",
        "removed_in": (1, 29),
        "replacement_api": "flowcontrol.apiserver.k8s.io/v1",
        "impact": "FlowSchema resources using v1beta2 will fail to validate.",
        "required_action": "Migrate FlowSchema to flowcontrol.apiserver.k8s.io/v1."
    },
    {
        "api_version": "flowcontrol.apiserver.k8s.io/v1beta2",
        "kind": "PriorityLevelConfiguration",
        "removed_in": (1, 29),
        "replacement_api": "flowcontrol.apiserver.k8s.io/v1",
        "impact": "PriorityLevelConfiguration resources using v1beta2 will fail.",
        "required_action": "Migrate PriorityLevelConfiguration to flowcontrol.apiserver.k8s.io/v1."
    },
    {
        "api_version": "flowcontrol.apiserver.k8s.io/v1beta3",
        "kind": "FlowSchema",
        "removed_in": (1, 32),
        "replacement_api": "flowcontrol.apiserver.k8s.io/v1",
        "impact": "FlowSchema resources using v1beta3 will fail.",
        "required_action": "Migrate FlowSchema to flowcontrol.apiserver.k8s.io/v1."
    },
    {
        "api_version": "flowcontrol.apiserver.k8s.io/v1beta3",
        "kind": "PriorityLevelConfiguration",
        "removed_in": (1, 32),
        "replacement_api": "flowcontrol.apiserver.k8s.io/v1",
        "impact": "PriorityLevelConfiguration resources using v1beta3 will fail.",
        "required_action": "Migrate PriorityLevelConfiguration to flowcontrol.apiserver.k8s.io/v1."
    },
    {
        "api_version": "apiextensions.k8s.io/v1beta1",
        "kind": "CustomResourceDefinition",
        "removed_in": (1, 22),
        "replacement_api": "apiextensions.k8s.io/v1",
        "impact": "CRD manifests using v1beta1 are no longer served or accepted.",
        "required_action": "Migrate CRD manifests to apiextensions.k8s.io/v1 with structural schema."
    }
]

# Database of Deprecated APIs & Scheduled Removals
DEPRECATED_APIS = [
    {
        "api_version": "flowcontrol.apiserver.k8s.io/v1beta3",
        "kind": "FlowSchema",
        "deprecated_in": (1, 29),
        "removed_in": (1, 32),
        "replacement": "flowcontrol.apiserver.k8s.io/v1"
    },
    {
        "api_version": "resource.k8s.io/v1alpha2",
        "kind": "ResourceClaim",
        "deprecated_in": (1, 30),
        "removed_in": (1, 32),
        "replacement": "resource.k8s.io/v1beta1"
    }
]

# Major K8s Version Breaking Behavioral Changes
BREAKING_BEHAVIORAL_CHANGES = {
    (1, 24): [
        "Dockershim removed from kubelet. Containers must use containerd or CRI-O runtime.",
        "Beta topology labels (topology.kubernetes.io/zone preferred over failure-domain.beta.kubernetes.io/zone).",
        "Service Account token secrets no longer auto-generated by default."
    ],
    (1, 25): [
        "PodSecurityPolicy (PSP) completely removed. Pod Security Admission (PSA) or webhook required.",
        "CRI v1alpha2 deprecated.",
        "Kubelet cgroup v2 support promoted to GA."
    ],
    (1, 26): [
        "CRI v1alpha2 removed from kubelet. Runtimes must support CRI v1.",
        "autoscaling/v2beta2 removed.",
        "Service InternalTrafficPolicy promoted to GA."
    ],
    (1, 27): [
        "SeccompDefault feature enabled by default in kubelet.",
        "Mutable Pod Scheduling Directives promoted to GA.",
        "Node Log Query alpha feature enabled."
    ],
    (1, 28): [
        "Expanded Kubelet skew policy supported (Kubelet can be up to 3 minor versions behind control plane).",
        "Cel Validation Rules for Custom Resources promoted to GA.",
        "Automatic fallback for native sidecar containers (initContainers with restartPolicy: Always)."
    ],
    (1, 29): [
        "Legacy in-tree cloud providers deprecated/removed; external Cloud Controller Manager (CCM) required.",
        "flowcontrol.apiserver.k8s.io/v1beta2 removed.",
        "Kubelet volume limit in-tree plugins removed in favor of CSI plugins."
    ],
    (1, 30): [
        "Go 1.22 minimum version required.",
        "AppArmor field moved to pod securityContext (annotations deprecated).",
        "Structured Authorization Configuration enabled."
    ],
    (1, 31): [
        "AppArmor annotations removed in favor of securityContext.appArmorProfile.",
        "In-tree volume plugins for Cloud providers completely disabled/removed."
    ],
    (1, 32): [
        "flowcontrol.apiserver.k8s.io/v1beta3 removed.",
        "Dynamic Resource Allocation (DRA) structured parameters promoted to beta."
    ]
}

# Controller & Operator Compatibility Matrix
CONTROLLER_COMPATIBILITY_MATRIX = {
    "cert-manager": [
        {"version_prefix": "v1.8.", "min_k8s": (1, 20), "max_k8s": (1, 24)},
        {"version_prefix": "v1.11.", "min_k8s": (1, 22), "max_k8s": (1, 27)},
        {"version_prefix": "v1.12.", "min_k8s": (1, 24), "max_k8s": (1, 28)},
        {"version_prefix": "v1.14.", "min_k8s": (1, 26), "max_k8s": (1, 30)},
        {"version_prefix": "v1.15.", "min_k8s": (1, 27), "max_k8s": (1, 31)},
        {"version_prefix": "v1.16.", "min_k8s": (1, 28), "max_k8s": (1, 32)}
    ],
    "ingress-nginx": [
        {"version_prefix": "v1.1.", "min_k8s": (1, 20), "max_k8s": (1, 24)},
        {"version_prefix": "v1.3.", "min_k8s": (1, 22), "max_k8s": (1, 25)},
        {"version_prefix": "v1.7.", "min_k8s": (1, 24), "max_k8s": (1, 27)},
        {"version_prefix": "v1.9.", "min_k8s": (1, 26), "max_k8s": (1, 29)},
        {"version_prefix": "v1.10.", "min_k8s": (1, 27), "max_k8s": (1, 30)},
        {"version_prefix": "v1.11.", "min_k8s": (1, 28), "max_k8s": (1, 31)}
    ],
    "external-dns": [
        {"version_prefix": "v0.12.", "min_k8s": (1, 21), "max_k8s": (1, 25)},
        {"version_prefix": "v0.13.", "min_k8s": (1, 22), "max_k8s": (1, 27)},
        {"version_prefix": "v0.14.", "min_k8s": (1, 25), "max_k8s": (1, 30)}
    ],
    "cluster-autoscaler": [
        # Cluster autoscaler MUST match exact minor K8s version
        {"version_prefix": "1.24.", "min_k8s": (1, 24), "max_k8s": (1, 24)},
        {"version_prefix": "1.25.", "min_k8s": (1, 25), "max_k8s": (1, 25)},
        {"version_prefix": "1.26.", "min_k8s": (1, 26), "max_k8s": (1, 26)},
        {"version_prefix": "1.27.", "min_k8s": (1, 27), "max_k8s": (1, 27)},
        {"version_prefix": "1.28.", "min_k8s": (1, 28), "max_k8s": (1, 28)},
        {"version_prefix": "1.29.", "min_k8s": (1, 29), "max_k8s": (1, 29)},
        {"version_prefix": "1.30.", "min_k8s": (1, 30), "max_k8s": (1, 30)}
    ],
    "metrics-server": [
        {"version_prefix": "v0.5.", "min_k8s": (1, 19), "max_k8s": (1, 24)},
        {"version_prefix": "v0.6.", "min_k8s": (1, 21), "max_k8s": (1, 27)},
        {"version_prefix": "v0.7.", "min_k8s": (1, 25), "max_k8s": (1, 30)}
    ],
    "kube-prometheus-stack": [
        {"version_prefix": "v0.56.", "min_k8s": (1, 21), "max_k8s": (1, 24)},
        {"version_prefix": "v0.65.", "min_k8s": (1, 23), "max_k8s": (1, 27)},
        {"version_prefix": "v0.70.", "min_k8s": (1, 25), "max_k8s": (1, 29)},
        {"version_prefix": "v0.75.", "min_k8s": (1, 27), "max_k8s": (1, 31)}
    ],
    "argo-cd": [
        {"version_prefix": "v2.4.", "min_k8s": (1, 21), "max_k8s": (1, 24)},
        {"version_prefix": "v2.6.", "min_k8s": (1, 22), "max_k8s": (1, 26)},
        {"version_prefix": "v2.9.", "min_k8s": (1, 24), "max_k8s": (1, 28)},
        {"version_prefix": "v2.11.", "min_k8s": (1, 26), "max_k8s": (1, 30)}
    ],
    "aws-load-balancer-controller": [
        {"version_prefix": "v2.4.", "min_k8s": (1, 19), "max_k8s": (1, 24)},
        {"version_prefix": "v2.5.", "min_k8s": (1, 22), "max_k8s": (1, 27)},
        {"version_prefix": "v2.7.", "min_k8s": (1, 25), "max_k8s": (1, 29)},
        {"version_prefix": "v2.8.", "min_k8s": (1, 26), "max_k8s": (1, 30)}
    ],
    "aws-ebs-csi-driver": [
        {"version_prefix": "v1.12.", "min_k8s": (1, 21), "max_k8s": (1, 25)},
        {"version_prefix": "v1.20.", "min_k8s": (1, 23), "max_k8s": (1, 27)},
        {"version_prefix": "v1.28.", "min_k8s": (1, 25), "max_k8s": (1, 29)},
        {"version_prefix": "v1.32.", "min_k8s": (1, 27), "max_k8s": (1, 31)}
    ],
    "cilium": [
        {"version_prefix": "v1.12", "min_k8s": (1, 21), "max_k8s": (1, 25)},
        {"version_prefix": "v1.14", "min_k8s": (1, 24), "max_k8s": (1, 28)},
        {"version_prefix": "v1.15", "min_k8s": (1, 26), "max_k8s": (1, 30)}
    ],
    "calico": [
        {"version_prefix": "v3.25", "min_k8s": (1, 22), "max_k8s": (1, 26)},
        {"version_prefix": "v3.27", "min_k8s": (1, 25), "max_k8s": (1, 29)}
    ],
    "gatekeeper": [
        {"version_prefix": "v3.11", "min_k8s": (1, 22), "max_k8s": (1, 26)},
        {"version_prefix": "v3.15", "min_k8s": (1, 25), "max_k8s": (1, 29)}
    ],
    "kyverno": [
        {"version_prefix": "v1.9", "min_k8s": (1, 23), "max_k8s": (1, 26)},
        {"version_prefix": "v1.11", "min_k8s": (1, 26), "max_k8s": (1, 30)}
    ],
    "velero": [
        {"version_prefix": "v1.9", "min_k8s": (1, 20), "max_k8s": (1, 24)},
        {"version_prefix": "v1.11", "min_k8s": (1, 23), "max_k8s": (1, 27)},
        {"version_prefix": "v1.13", "min_k8s": (1, 25), "max_k8s": (1, 29)}
    ]
}
