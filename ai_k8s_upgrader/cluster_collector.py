"""
Cluster Collector Module.
Gathers cluster info, workloads, CRDs, webhooks, controllers, nodes, storage, and networking
either from live kubectl commands or from an offline snapshot file.
"""

import json
import subprocess
import os
from typing import Dict, Any, Optional, List

class ClusterCollector:
    def __init__(self, kubeconfig: Optional[str] = None, snapshot_file: Optional[str] = None):
        self.kubeconfig = kubeconfig
        self.snapshot_file = snapshot_file

    def collect(self) -> Dict[str, Any]:
        if self.snapshot_file and os.path.exists(self.snapshot_file):
            return self._load_snapshot(self.snapshot_file)
        
        # Attempt live collection via kubectl
        return self._collect_live()

    def _load_snapshot(self, path: str) -> Dict[str, Any]:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def _run_kubectl(self, args: List[str]) -> Optional[Dict[str, Any]]:
        cmd = ["kubectl"] + args
        if self.kubeconfig:
            cmd += ["--kubeconfig", self.kubeconfig]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if res.returncode == 0:
                try:
                    return json.loads(res.stdout)
                except json.JSONDecodeError:
                    return {"raw_text": res.stdout}
        except Exception:
            pass
        return None

    def _collect_live(self) -> Dict[str, Any]:
        # Step 1: Cluster Info
        ver_data = self._run_kubectl(["version", "-o", "json"]) or {}
        nodes_data = self._run_kubectl(["get", "nodes", "-o", "json"]) or {"items": []}
        ns_data = self._run_kubectl(["get", "ns", "-o", "json"]) or {"items": []}
        
        # Step 2: Workloads
        deploy_data = self._run_kubectl(["get", "deployments", "-A", "-o", "json"]) or {"items": []}
        sts_data = self._run_kubectl(["get", "statefulsets", "-A", "-o", "json"]) or {"items": []}
        ds_data = self._run_kubectl(["get", "daemonsets", "-A", "-o", "json"]) or {"items": []}
        jobs_data = self._run_kubectl(["get", "jobs", "-A", "-o", "json"]) or {"items": []}
        cronjobs_data = self._run_kubectl(["get", "cronjobs", "-A", "-o", "json"]) or {"items": []}
        pods_data = self._run_kubectl(["get", "pods", "-A", "-o", "json"]) or {"items": []}

        # Step 3: CRDs
        crd_data = self._run_kubectl(["get", "crd", "-o", "json"]) or {"items": []}

        # Webhooks
        val_webhooks = self._run_kubectl(["get", "validatingwebhookconfigurations", "-o", "json"]) or {"items": []}
        mut_webhooks = self._run_kubectl(["get", "mutatingwebhookconfigurations", "-o", "json"]) or {"items": []}

        # Storage
        sc_data = self._run_kubectl(["get", "storageclasses", "-o", "json"]) or {"items": []}
        pv_data = self._run_kubectl(["get", "pv", "-o", "json"]) or {"items": []}
        pvc_data = self._run_kubectl(["get", "pvc", "-A", "-o", "json"]) or {"items": []}

        return {
            "cluster_info": {
                "server_version": ver_data.get("serverVersion", {}).get("gitVersion", "v1.25.0"),
                "nodes": nodes_data.get("items", []),
                "namespaces": ns_data.get("items", []),
                "is_live": True
            },
            "workloads": {
                "deployments": deploy_data.get("items", []),
                "statefulsets": sts_data.get("items", []),
                "daemonsets": ds_data.get("items", []),
                "jobs": jobs_data.get("items", []),
                "cronjobs": cronjobs_data.get("items", []),
                "pods": pods_data.get("items", [])
            },
            "crds": crd_data.get("items", []),
            "webhooks": {
                "validating": val_webhooks.get("items", []),
                "mutating": mut_webhooks.get("items", [])
            },
            "storage": {
                "storage_classes": sc_data.get("items", []),
                "pvs": pv_data.get("items", []),
                "pvcs": pvc_data.get("items", [])
            }
        }
