"""
conftest.py
===========
Shared pytest fixtures for the AI-Kubernetes-Upgrader test suite.
"""

import json
import os
import sys
import tempfile
import pytest

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_k8s_upgrader.cluster_collector import (
    ClusterSnapshot,
    NodeInfo,
    SnapshotClusterCollector,
)
from ai_k8s_upgrader.sample_generator import generate_sample_cluster
from ai_k8s_upgrader.web_dashboard import app, rate_limiter


@pytest.fixture
def sample_cluster_dict():
    """Returns a realistic sample cluster dictionary (v1.27 -> v1.30)."""
    return generate_sample_cluster(source_version="1.27", target_version="1.30")


@pytest.fixture
def sample_snapshot(sample_cluster_dict):
    """Returns a parsed ClusterSnapshot instance from sample cluster data."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(sample_cluster_dict, f)
        tmp_path = f.name
    try:
        collector = SnapshotClusterCollector(tmp_path)
        snapshot = collector.collect()
        snapshot.source_mode = "sample"
        return snapshot
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


@pytest.fixture
def test_client():
    """Provides a fresh Flask test client with rate limiter reset before and after."""
    app.config["TESTING"] = True
    app.config["ALLOW_LIVE_CLUSTER"] = False
    rate_limiter.reset()
    with app.test_client() as client:
        yield client
    rate_limiter.reset()


@pytest.fixture
def default_node_info():
    """Provides a default healthy NodeInfo fixture."""
    return NodeInfo(
        name="test-worker-1",
        role="worker",
        k8s_version="1.27.0",
        os_image="Ubuntu 22.04 LTS",
        kernel_version="5.15.0-generic",
        container_runtime="containerd://1.6.20",
        status="Ready",
        cpu="4",
        memory="16Gi",
        architecture="amd64",
    )
