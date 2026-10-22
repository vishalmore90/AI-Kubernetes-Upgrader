"""
cluster_collector.py
====================
Collects Kubernetes cluster state for upgrade assessment.

Supports two modes:
1. Live Mode: Uses subprocess kubectl calls to collect live cluster state
2. Snapshot Mode: Loads a pre-captured JSON cluster state file

Output: Normalized ClusterSnapshot dataclass used throughout the assessment engine.
"""

import json
import subprocess
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class NodeInfo:
    name: str
    role: str               # "control-plane" | "worker"
    k8s_version: str
    os_image: str
    kernel_version: str
    container_runtime: str  # e.g., "containerd://1.6.20"
    status: str             # "Ready" | "NotReady"
    cpu: str
    memory: str
    architecture: str


@dataclass
class WorkloadResource:
    namespace: str
    kind: str               # Deployment, StatefulSet, DaemonSet, etc.
    name: str
    api_version: str
    replicas: int
    ready_replicas: int
    age: str
    images: List[str]
    labels: Dict[str, str]
    annotations: Dict[str, str]


@dataclass
class CRDInfo:
    name: str
    group: str
    kind: str
    versions: List[str]          # all versions defined
    storage_version: str
    served_versions: List[str]
    scope: str                   # Namespaced | Cluster
    has_conversion_webhook: bool
    conversion_strategy: str     # None | Webhook
    has_validation_schema: bool
    established: bool


@dataclass
class WebhookInfo:
    name: str
    kind: str               # "Validating" | "Mutating"
    failure_policy: str     # "Fail" | "Ignore"
    side_effects: str       # "None" | "NoneOnDryRun" | "Unknown" | "Some"
    admission_review_versions: List[str]
    rules: List[Dict]
    timeout_seconds: int
    namespace_selector: Optional[Dict]


@dataclass
class StorageClassInfo:
    name: str
    provisioner: str
    reclaim_policy: str
    volume_binding_mode: str
    allow_volume_expansion: bool
    is_default: bool


@dataclass
class PVInfo:
    name: str
    capacity: str
    access_modes: List[str]
    reclaim_policy: str
    status: str
    storage_class: str
    claim_ref: Optional[str]


@dataclass
class PVCInfo:
    namespace: str
    name: str
    status: str
    volume: str
    capacity: str
    access_modes: List[str]
    storage_class: str


@dataclass
class NetworkPolicyInfo:
    namespace: str
    name: str
    pod_selector: Dict
    policy_types: List[str]


@dataclass(frozen=True)
class NormalizedResource:
    """Normalized representation of a single Kubernetes resource object."""
    group: str
    version: str
    kind: str
    namespace: str
    name: str
    api_version: str
    source_collection: str = "all_resources"


@dataclass
class ClusterSnapshot:
    """Complete normalized cluster state for assessment."""
    # Source of data
    source_mode: str = "snapshot"            # "live" | "snapshot" | "sample"

    # Step 1: Cluster Info
    k8s_version: str = "1.25"
    k8s_git_version: str = ""
    api_server_version: str = ""
    platform: str = "linux/amd64"            # e.g., "linux/amd64"
    cluster_name: str = "cluster"
    is_managed: bool = False                 # EKS, GKE, AKS, etc.
    managed_provider: str = "self-managed"   # "eks" | "gke" | "aks" | "self-managed"
    ha_control_plane: bool = True

    # Step 1: Nodes
    nodes: List[NodeInfo] = field(default_factory=list)
    control_plane_count: int = 0
    worker_count: int = 0

    # Step 2: Workloads
    deployments: List[WorkloadResource] = field(default_factory=list)
    statefulsets: List[WorkloadResource] = field(default_factory=list)
    daemonsets: List[WorkloadResource] = field(default_factory=list)
    jobs: List[WorkloadResource] = field(default_factory=list)
    cronjobs: List[WorkloadResource] = field(default_factory=list)
    namespaces: List[str] = field(default_factory=list)

    # Step 3: CRDs
    crds: List[CRDInfo] = field(default_factory=list)

    # Step 10: Webhooks
    validating_webhooks: List[WebhookInfo] = field(default_factory=list)
    mutating_webhooks: List[WebhookInfo] = field(default_factory=list)

    # Step 12: Storage
    storage_classes: List[StorageClassInfo] = field(default_factory=list)
    persistent_volumes: List[PVInfo] = field(default_factory=list)
    persistent_volume_claims: List[PVCInfo] = field(default_factory=list)

    # Step 11: Networking
    network_policies: List[NetworkPolicyInfo] = field(default_factory=list)
    cni_plugin: str = ""
    ingress_controller: str = ""

    # Step 13: Security
    pod_security_policies: List[str] = field(default_factory=list)  # PSP names
    has_pod_security_admission: bool = False
    privileged_workloads: List[str] = field(default_factory=list)

    # Step 15: Resource Pressure
    node_cpu_pressures: Dict[str, str] = field(default_factory=dict)
    node_memory_pressures: Dict[str, str] = field(default_factory=dict)
    node_disk_pressures: Dict[str, str] = field(default_factory=dict)

    # Detected operators
    detected_operators: Dict[str, str] = field(default_factory=dict)  # name -> version

    # Raw API resources
    api_resources: List[Dict] = field(default_factory=list)
    api_services: List[Dict] = field(default_factory=list)

    # All resource objects (flat list for API scanning)
    all_resources: List[Dict] = field(default_factory=list)
    all_resources_provided: bool = True

    # Errors during collection
    collection_errors: List[str] = field(default_factory=list)

    def get_normalized_inventory(self) -> List[NormalizedResource]:
        """Return normalized, deduplicated list of all observed cluster resources."""
        return build_resource_inventory(self)


def build_resource_inventory(snapshot: ClusterSnapshot) -> List[NormalizedResource]:
    """
    Build a deduplicated, normalized inventory of Kubernetes resources observed
    in the cluster across all supported snapshot collections:
    1. snapshot.all_resources
    2. snapshot.deployments, statefulsets, daemonsets, jobs, cronjobs
    3. snapshot.pod_security_policies
    """
    raw_resources: List[NormalizedResource] = []

    # 1. From all_resources
    for item in snapshot.all_resources:
        if not isinstance(item, dict):
            continue
        api_ver = (item.get("apiVersion") or item.get("api_version") or "").strip()
        kind = (item.get("kind") or "").strip()
        if not api_ver or not kind:
            continue

        meta = item.get("metadata")
        if isinstance(meta, dict):
            name = (meta.get("name") or item.get("name") or "").strip()
            namespace = (meta.get("namespace") or item.get("namespace") or "").strip()
        else:
            name = (item.get("name") or "").strip()
            namespace = (item.get("namespace") or "").strip()

        if "/" in api_ver:
            group, version = api_ver.split("/", 1)
        else:
            group = ""
            version = api_ver

        raw_resources.append(NormalizedResource(
            group=group.strip(),
            version=version.strip(),
            kind=kind,
            namespace=namespace,
            name=name,
            api_version=api_ver,
            source_collection="all_resources",
        ))

    # 2. From workloads
    workload_lists = [
        snapshot.deployments,
        snapshot.statefulsets,
        snapshot.daemonsets,
        snapshot.jobs,
        snapshot.cronjobs,
    ]
    for w_list in workload_lists:
        for w in w_list:
            api_ver = (getattr(w, "api_version", "") or "").strip()
            kind = (getattr(w, "kind", "") or "").strip()
            name = (getattr(w, "name", "") or "").strip()
            namespace = (getattr(w, "namespace", "") or "").strip()
            if not api_ver or not kind:
                continue

            if "/" in api_ver:
                group, version = api_ver.split("/", 1)
            else:
                group = ""
                version = api_ver

            raw_resources.append(NormalizedResource(
                group=group.strip(),
                version=version.strip(),
                kind=kind,
                namespace=namespace,
                name=name,
                api_version=api_ver,
                source_collection="workloads",
            ))

    # 3. From pod_security_policies
    for psp in snapshot.pod_security_policies:
        if isinstance(psp, str):
            psp_name = psp.strip()
        elif isinstance(psp, dict):
            psp_name = (psp.get("name") or psp.get("metadata", {}).get("name") or "").strip()
        else:
            psp_name = str(psp).strip()
        if psp_name:
            raw_resources.append(NormalizedResource(
                group="policy",
                version="v1beta1",
                kind="PodSecurityPolicy",
                namespace="",
                name=psp_name,
                api_version="policy/v1beta1",
                source_collection="pod_security_policies",
            ))

    # Deduplicate while preserving order
    seen = set()
    deduped: List[NormalizedResource] = []
    for res in raw_resources:
        key = (res.group, res.version, res.kind, res.namespace, res.name)
        if key not in seen:
            seen.add(key)
            deduped.append(res)

    return deduped


# ---------------------------------------------------------------------------
# Live Cluster Collector
# ---------------------------------------------------------------------------

class LiveClusterCollector:
    """Collects cluster state via subprocess kubectl calls."""

    def __init__(self, kubeconfig: Optional[str] = None, context: Optional[str] = None):
        self.kubeconfig = kubeconfig
        self.context = context

    def _kubectl(self, args: List[str], timeout: int = 30) -> Optional[Dict]:
        """Run a kubectl command and return JSON output."""
        cmd = ["kubectl"] + args + ["-o", "json"]
        if self.kubeconfig:
            cmd = ["kubectl", "--kubeconfig", self.kubeconfig] + args[1:] + ["-o", "json"]
        if self.context:
            cmd.insert(1, "--context")
            cmd.insert(2, self.context)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                logger.warning(f"kubectl error for {args}: {result.stderr.strip()}")
                return None
        except subprocess.TimeoutExpired:
            logger.warning(f"kubectl timeout for {args}")
            return None
        except Exception as e:
            logger.warning(f"kubectl exception for {args}: {e}")
            return None

    def _kubectl_text(self, args: List[str], timeout: int = 30) -> Optional[str]:
        """Run a kubectl command and return text output."""
        cmd = ["kubectl"] + args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception:
            return None

    def collect(self) -> ClusterSnapshot:
        snap = ClusterSnapshot(
            source_mode="live",
            k8s_version="", k8s_git_version="", api_server_version="",
            platform="", cluster_name="", is_managed=False,
            managed_provider="self-managed", ha_control_plane=False
        )

        # Version
        version_data = self._kubectl(["version"])
        if version_data:
            sv = version_data.get("serverVersion", {})
            snap.k8s_git_version = sv.get("gitVersion", "")
            snap.api_server_version = sv.get("gitVersion", "")
            minor = sv.get("minor", "0").rstrip("+")
            major = sv.get("major", "1")
            snap.k8s_version = f"{major}.{minor}"

        # Nodes
        nodes_data = self._kubectl(["get", "nodes"])
        if nodes_data:
            snap.nodes, snap.control_plane_count, snap.worker_count = self._parse_nodes(nodes_data)

        snap.ha_control_plane = snap.control_plane_count > 1

        # Namespaces
        ns_data = self._kubectl(["get", "namespaces"])
        if ns_data:
            snap.namespaces = [item["metadata"]["name"] for item in ns_data.get("items", [])]

        # Detect managed provider
        snap.managed_provider, snap.is_managed = self._detect_managed_provider(snap)

        # Workloads
        deploys = self._kubectl(["get", "deployments", "-A"])
        if deploys:
            snap.deployments = self._parse_workloads(deploys, "Deployment")

        sts = self._kubectl(["get", "statefulsets", "-A"])
        if sts:
            snap.statefulsets = self._parse_workloads(sts, "StatefulSet")

        ds = self._kubectl(["get", "daemonsets", "-A"])
        if ds:
            snap.daemonsets = self._parse_workloads(ds, "DaemonSet")

        jobs = self._kubectl(["get", "jobs", "-A"])
        if jobs:
            snap.jobs = self._parse_workloads(jobs, "Job")

        cjobs = self._kubectl(["get", "cronjobs", "-A"])
        if cjobs:
            snap.cronjobs = self._parse_workloads(cjobs, "CronJob")

        # CRDs
        crds = self._kubectl(["get", "crds"])
        if crds:
            snap.crds = self._parse_crds(crds)

        # Webhooks
        vwc = self._kubectl(["get", "validatingwebhookconfigurations"])
        if vwc:
            snap.validating_webhooks = self._parse_webhooks(vwc, "Validating")

        mwc = self._kubectl(["get", "mutatingwebhookconfigurations"])
        if mwc:
            snap.mutating_webhooks = self._parse_webhooks(mwc, "Mutating")

        # Storage
        sc = self._kubectl(["get", "storageclasses"])
        if sc:
            snap.storage_classes = self._parse_storage_classes(sc)

        pvs = self._kubectl(["get", "persistentvolumes"])
        if pvs:
            snap.persistent_volumes = self._parse_pvs(pvs)

        pvcs = self._kubectl(["get", "persistentvolumeclaims", "-A"])
        if pvcs:
            snap.persistent_volume_claims = self._parse_pvcs(pvcs)

        # Network Policies
        np = self._kubectl(["get", "networkpolicies", "-A"])
        if np:
            snap.network_policies = self._parse_network_policies(np)

        # PSP
        psp = self._kubectl(["get", "podsecuritypolicies"])
        if psp:
            snap.pod_security_policies = [item["metadata"]["name"] for item in psp.get("items", [])]

        # Build all_resources list for API scanning
        snap.all_resources = self._collect_all_resources()

        # Detect operators
        snap.detected_operators = self._detect_operators(snap)

        return snap

    def _parse_nodes(self, data: Dict) -> tuple:
        nodes = []
        cp_count = 0
        worker_count = 0
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            status = item.get("status", {})
            labels = meta.get("labels", {})
            ni = item.get("status", {}).get("nodeInfo", {})

            role = "worker"
            if "node-role.kubernetes.io/control-plane" in labels or "node-role.kubernetes.io/master" in labels:
                role = "control-plane"
                cp_count += 1
            else:
                worker_count += 1

            node_status = "Ready"
            for cond in status.get("conditions", []):
                if cond.get("type") == "Ready" and cond.get("status") == "False":
                    node_status = "NotReady"

            capacity = status.get("capacity", {})
            nodes.append(NodeInfo(
                name=meta.get("name", ""),
                role=role,
                k8s_version=ni.get("kubeletVersion", ""),
                os_image=ni.get("osImage", ""),
                kernel_version=ni.get("kernelVersion", ""),
                container_runtime=ni.get("containerRuntimeVersion", ""),
                status=node_status,
                cpu=capacity.get("cpu", ""),
                memory=capacity.get("memory", ""),
                architecture=ni.get("architecture", "amd64"),
            ))
        return nodes, cp_count, worker_count

    def _parse_workloads(self, data: Dict, kind: str) -> List[WorkloadResource]:
        resources = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            status_d = item.get("status", {})
            api_version = item.get("apiVersion", "")

            images = []
            containers = spec.get("template", {}).get("spec", {}).get("containers", [])
            for c in containers:
                images.append(c.get("image", ""))

            resources.append(WorkloadResource(
                namespace=meta.get("namespace", ""),
                kind=kind,
                name=meta.get("name", ""),
                api_version=api_version,
                replicas=spec.get("replicas", 1),
                ready_replicas=status_d.get("readyReplicas", 0),
                age=meta.get("creationTimestamp", ""),
                images=images,
                labels=meta.get("labels", {}),
                annotations=meta.get("annotations", {}),
            ))
        return resources

    def _parse_crds(self, data: Dict) -> List[CRDInfo]:
        crds = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            status_d = item.get("status", {})

            versions_list = spec.get("versions", [])
            all_versions = [v["name"] for v in versions_list]
            storage_version = next((v["name"] for v in versions_list if v.get("storage", False)), "")
            served_versions = [v["name"] for v in versions_list if v.get("served", False)]

            conversion = spec.get("conversion", {})
            has_webhook = conversion.get("strategy", "None") == "Webhook"
            has_schema = any(v.get("schema") for v in versions_list)

            established = any(
                c.get("type") == "Established" and c.get("status") == "True"
                for c in status_d.get("conditions", [])
            )

            crds.append(CRDInfo(
                name=meta.get("name", ""),
                group=spec.get("group", ""),
                kind=spec.get("names", {}).get("kind", ""),
                versions=all_versions,
                storage_version=storage_version,
                served_versions=served_versions,
                scope=spec.get("scope", ""),
                has_conversion_webhook=has_webhook,
                conversion_strategy=conversion.get("strategy", "None"),
                has_validation_schema=has_schema,
                established=established,
            ))
        return crds

    def _parse_webhooks(self, data: Dict, kind: str) -> List[WebhookInfo]:
        webhooks = []
        key = "webhooks" if kind == "Validating" else "webhooks"
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            for wh in item.get("webhooks", []):
                webhooks.append(WebhookInfo(
                    name=meta.get("name", ""),
                    kind=kind,
                    failure_policy=wh.get("failurePolicy", "Fail"),
                    side_effects=wh.get("sideEffects", "Unknown"),
                    admission_review_versions=wh.get("admissionReviewVersions", []),
                    rules=wh.get("rules", []),
                    timeout_seconds=wh.get("timeoutSeconds", 10),
                    namespace_selector=wh.get("namespaceSelector"),
                ))
        return webhooks

    def _parse_storage_classes(self, data: Dict) -> List[StorageClassInfo]:
        scs = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            annotations = meta.get("annotations", {})
            is_default = annotations.get("storageclass.kubernetes.io/is-default-class") == "true"
            scs.append(StorageClassInfo(
                name=meta.get("name", ""),
                provisioner=item.get("provisioner", ""),
                reclaim_policy=item.get("reclaimPolicy", "Delete"),
                volume_binding_mode=item.get("volumeBindingMode", "Immediate"),
                allow_volume_expansion=item.get("allowVolumeExpansion", False),
                is_default=is_default,
            ))
        return scs

    def _parse_pvs(self, data: Dict) -> List[PVInfo]:
        pvs = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            status_d = item.get("status", {})
            claim_ref = spec.get("claimRef", {})
            claim = f"{claim_ref.get('namespace', '')}/{claim_ref.get('name', '')}" if claim_ref else None
            cap = spec.get("capacity", {})
            pvs.append(PVInfo(
                name=meta.get("name", ""),
                capacity=cap.get("storage", ""),
                access_modes=spec.get("accessModes", []),
                reclaim_policy=spec.get("persistentVolumeReclaimPolicy", ""),
                status=status_d.get("phase", ""),
                storage_class=spec.get("storageClassName", ""),
                claim_ref=claim,
            ))
        return pvs

    def _parse_pvcs(self, data: Dict) -> List[PVCInfo]:
        pvcs = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            status_d = item.get("status", {})
            cap = status_d.get("capacity", {})
            pvcs.append(PVCInfo(
                namespace=meta.get("namespace", ""),
                name=meta.get("name", ""),
                status=status_d.get("phase", ""),
                volume=spec.get("volumeName", ""),
                capacity=cap.get("storage", ""),
                access_modes=spec.get("accessModes", []),
                storage_class=spec.get("storageClassName", ""),
            ))
        return pvcs

    def _parse_network_policies(self, data: Dict) -> List[NetworkPolicyInfo]:
        nps = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            nps.append(NetworkPolicyInfo(
                namespace=meta.get("namespace", ""),
                name=meta.get("name", ""),
                pod_selector=spec.get("podSelector", {}),
                policy_types=spec.get("policyTypes", []),
            ))
        return nps

    def _detect_managed_provider(self, snap: ClusterSnapshot) -> tuple:
        """Detect cloud provider based on node labels and annotations."""
        for node in snap.nodes:
            if "eks.amazonaws.com" in node.os_image.lower():
                return "eks", True
            if "gke" in node.os_image.lower():
                return "gke", True
            if "aks" in node.os_image.lower():
                return "aks", True
        return "self-managed", False

    def _collect_all_resources(self) -> List[Dict]:
        """
        Collect resources across key API groups for API version scanning.

        Live Collection Limitation:
        `kubectl get <resource> -o json` queries the live API server, which serves
        resources translated into the API server's current preferred/storage version.
        Live collection cannot reliably detect whether a resource was originally applied
        using a deprecated or removed API version in source manifests/Helm charts.
        For reliable manifest-level deprecation detection, snapshots generated from
        manifest trees, Helm release secrets, or Kubernetes audit logs should be used.
        """
        resources = []
        # Sample key resource types
        resource_types = [
            "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs",
            "ingresses", "networkpolicies", "horizontalpodautoscalers",
            "poddisruptionbudgets", "storageclasses", "clusterroles",
            "clusterrolebindings", "roles", "rolebindings",
        ]
        for rt in resource_types:
            data = self._kubectl(["get", rt, "-A"])
            if data:
                for item in data.get("items", []):
                    resources.append({
                        "apiVersion": item.get("apiVersion", ""),
                        "kind": item.get("kind", ""),
                        "namespace": item.get("metadata", {}).get("namespace", ""),
                        "name": item.get("metadata", {}).get("name", ""),
                    })
        return resources

    def _detect_operators(self, snap: ClusterSnapshot) -> Dict[str, str]:
        """Detect installed operators by checking deployments and labels."""
        from ai_k8s_upgrader.k8s_database import OPERATOR_COMPATIBILITY
        detected = {}
        all_deployments = snap.deployments + snap.daemonsets

        for op in OPERATOR_COMPATIBILITY:
            for deploy_name in op.detection_deployments:
                for workload in all_deployments:
                    if deploy_name.lower() in workload.name.lower():
                        # Try to extract version from image
                        version = "unknown"
                        for img in workload.images:
                            if ":" in img:
                                version = img.split(":")[-1]
                                break
                        detected[op.name] = version
                        break

        return detected


# ---------------------------------------------------------------------------
# Snapshot Loader
# ---------------------------------------------------------------------------

class SnapshotClusterCollector:
    """Loads cluster state from a pre-captured JSON snapshot file."""

    def __init__(self, snapshot_path: str):
        self.snapshot_path = snapshot_path

    def collect(self) -> ClusterSnapshot:
        with open(self.snapshot_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        snap = ClusterSnapshot(source_mode="snapshot", **self._parse_snapshot(data))
        return snap

    def _parse_snapshot(self, data: Dict) -> Dict:
        """Parse snapshot JSON into ClusterSnapshot fields."""
        nodes = []
        for n in data.get("nodes", []):
            if isinstance(n, NodeInfo):
                nodes.append(n)
            elif isinstance(n, dict):
                norm_node = {
                    "name": n.get("name", "node"),
                    "role": n.get("role", "worker"),
                    "k8s_version": n.get("k8s_version") or n.get("version") or n.get("kubelet_version") or data.get("k8s_version", ""),
                    "os_image": n.get("os_image") or n.get("os") or "linux",
                    "kernel_version": n.get("kernel_version", ""),
                    "container_runtime": n.get("container_runtime") or n.get("runtime") or "containerd://1.6.0",
                    "status": n.get("status", "Ready"),
                    "cpu": str(n.get("cpu", "4")),
                    "memory": str(n.get("memory", "16Gi")),
                    "architecture": n.get("architecture", "amd64"),
                }
                nodes.append(NodeInfo(**norm_node))

        deployments = [WorkloadResource(**d) for d in data.get("deployments", [])]
        statefulsets = [WorkloadResource(**d) for d in data.get("statefulsets", [])]
        daemonsets = [WorkloadResource(**d) for d in data.get("daemonsets", [])]
        jobs = [WorkloadResource(**d) for d in data.get("jobs", [])]
        cronjobs = [WorkloadResource(**d) for d in data.get("cronjobs", [])]
        crds = [CRDInfo(**c) for c in data.get("crds", [])]
        validating_webhooks = [WebhookInfo(**w) for w in data.get("validating_webhooks", [])]
        mutating_webhooks = [WebhookInfo(**w) for w in data.get("mutating_webhooks", [])]
        storage_classes = [StorageClassInfo(**s) for s in data.get("storage_classes", [])]
        persistent_volumes = [PVInfo(**p) for p in data.get("persistent_volumes", [])]
        persistent_volume_claims = [PVCInfo(**p) for p in data.get("persistent_volume_claims", [])]
        network_policies = [NetworkPolicyInfo(**n) for n in data.get("network_policies", [])]

        cp_count = sum(1 for n in nodes if n.role == "control-plane")
        worker_count = sum(1 for n in nodes if n.role == "worker")

        has_all_res = ("all_resources" in data and data["all_resources"] is not None)
        all_res = data.get("all_resources", []) if has_all_res else []
        if all_res is None:
            all_res = []
            has_all_res = False

        return dict(
            k8s_version=data.get("k8s_version", ""),
            k8s_git_version=data.get("k8s_git_version", ""),
            api_server_version=data.get("api_server_version", ""),
            platform=data.get("platform", "linux/amd64"),
            cluster_name=data.get("cluster_name", ""),
            is_managed=data.get("is_managed", False),
            managed_provider=data.get("managed_provider", "self-managed"),
            ha_control_plane=data.get("ha_control_plane", False),
            nodes=nodes,
            control_plane_count=cp_count,
            worker_count=worker_count,
            deployments=deployments,
            statefulsets=statefulsets,
            daemonsets=daemonsets,
            jobs=jobs,
            cronjobs=cronjobs,
            namespaces=data.get("namespaces", []),
            crds=crds,
            validating_webhooks=validating_webhooks,
            mutating_webhooks=mutating_webhooks,
            storage_classes=storage_classes,
            persistent_volumes=persistent_volumes,
            persistent_volume_claims=persistent_volume_claims,
            network_policies=network_policies,
            cni_plugin=data.get("cni_plugin", ""),
            ingress_controller=data.get("ingress_controller", ""),
            pod_security_policies=data.get("pod_security_policies", []),
            has_pod_security_admission=data.get("has_pod_security_admission", False),
            privileged_workloads=data.get("privileged_workloads", []),
            node_cpu_pressures=data.get("node_cpu_pressures", {}),
            node_memory_pressures=data.get("node_memory_pressures", {}),
            node_disk_pressures=data.get("node_disk_pressures", {}),
            detected_operators=data.get("detected_operators", {}),
            api_resources=data.get("api_resources", []),
            api_services=data.get("api_services", []),
            all_resources=all_res,
            all_resources_provided=has_all_res,
            collection_errors=data.get("collection_errors", []),
        )


# ---------------------------------------------------------------------------
# Factory Function
# ---------------------------------------------------------------------------

def collect_cluster_state(
    mode: str = "snapshot",
    snapshot_path: Optional[str] = None,
    kubeconfig: Optional[str] = None,
    context: Optional[str] = None,
) -> ClusterSnapshot:
    """
    Factory function to collect cluster state.

    Args:
        mode: "live" | "snapshot"
        snapshot_path: Path to JSON snapshot file (for snapshot mode)
        kubeconfig: Optional kubeconfig path (for live mode)
        context: Optional kubectl context (for live mode)
    """
    if mode == "live":
        collector = LiveClusterCollector(kubeconfig=kubeconfig, context=context)
        return collector.collect()
    elif mode == "snapshot" and snapshot_path:
        collector = SnapshotClusterCollector(snapshot_path=snapshot_path)
        return collector.collect()
    else:
        raise ValueError(f"Invalid mode '{mode}' or missing snapshot_path")
