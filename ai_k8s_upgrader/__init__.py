"""
AI-Kubernetes-Upgrader
======================
Enterprise-grade Kubernetes Upgrade Feasibility, Compatibility, and Risk Assessment Engine.

Implements all 17 assessment steps to determine whether a Kubernetes cluster
can be safely upgraded from a source version to a target version.
"""

from ai_k8s_upgrader.assessment_engine import (
    AssessmentEngine,
    AssessmentResult,
    Status,
    Severity,
    IssueCategory,
)
from ai_k8s_upgrader.cluster_collector import (
    ClusterSnapshot,
    NodeInfo,
    NormalizedResource,
    WorkloadResource,
    SnapshotClusterCollector,
    build_resource_inventory,
    collect_cluster_state,
)
from ai_k8s_upgrader.scoring_matrix import (
    ScoringEngine,
    ScoringResult,
    RiskMatrixEntry,
)
from ai_k8s_upgrader.reporter import (
    generate_markdown_report,
    generate_json_report,
)
from ai_k8s_upgrader.sample_generator import (
    generate_sample_cluster,
    save_sample_cluster,
)

__version__ = "1.0.0"
__author__ = "AI-Kubernetes-Upgrader"

__all__ = [
    "__version__",
    "__author__",
    # Assessment
    "AssessmentEngine",
    "AssessmentResult",
    "Status",
    "Severity",
    "IssueCategory",
    # Cluster Collector
    "ClusterSnapshot",
    "NodeInfo",
    "NormalizedResource",
    "WorkloadResource",
    "SnapshotClusterCollector",
    "build_resource_inventory",
    "collect_cluster_state",
    # Scoring
    "ScoringEngine",
    "ScoringResult",
    "RiskMatrixEntry",
    # Reporting
    "generate_markdown_report",
    "generate_json_report",
    # Sample generator
    "generate_sample_cluster",
    "save_sample_cluster",
]
