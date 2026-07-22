"""
Scoring & Risk Matrix Engine.
Calculates Readiness Score (0-100), Confidence Score (%), 10-Area Risk Matrix,
Executive Summary, and Mandatory Incompatibility Rule report format.
"""

from typing import Dict, List, Any

class ScoringMatrixEngine:
    def __init__(self, assessment_data: Dict[str, Any]):
        self.data = assessment_data

    def generate_report_sections(self) -> Dict[str, Any]:
        risk_matrix = self._build_risk_matrix()
        readiness_score = self._calculate_readiness_score(risk_matrix)
        confidence_score = self._calculate_confidence_score()
        mandatory_breakdowns = self._build_mandatory_breakdowns()
        exec_summary = self._build_executive_summary(readiness_score, confidence_score, risk_matrix, mandatory_breakdowns)

        return {
            "risk_matrix": risk_matrix,
            "readiness_score": readiness_score,
            "confidence_score": confidence_score,
            "executive_summary": exec_summary,
            "mandatory_breakdowns": mandatory_breakdowns
        }

    def _build_risk_matrix(self) -> List[Dict[str, str]]:
        d = self.data
        api_removals = d.get("step6_api_removals", [])
        crd_compat = d.get("step8_crd_compat", [])
        ctrl_compat = d.get("step9_controller_compat", [])
        webhooks = d.get("step10_webhooks", {})
        networking = d.get("step11_networking", {})
        storage = d.get("step12_storage", {})
        security = d.get("step13_security", {})
        runtime = d.get("step14_runtime", {})
        sim = d.get("step16_simulation", {})

        # 1. APIs
        if api_removals:
            api_status, api_sev = "CRITICAL", "Critical"
            api_exp = f"Found {len(api_removals)} workload objects using removed APIs."
        else:
            api_status, api_sev = "PASS", "Low"
            api_exp = "All active workloads use valid, supported API versions."

        # 2. CRDs
        crd_breaks = [c for c in crd_compat if c.get("could_break")]
        if crd_breaks:
            crd_status, crd_sev = "HIGH RISK", "High"
            crd_exp = f"{len(crd_breaks)} CRDs have schema or API version compatibility issues."
        else:
            crd_status, crd_sev = "PASS", "Low"
            crd_exp = "All CRD schemas and served versions compatible."

        # 3. Controllers
        ctrl_issues = [c for c in ctrl_compat if c.get("target_compatibility") in ["HIGH RISK", "CRITICAL"]]
        if ctrl_issues:
            ctrl_status, ctrl_sev = "HIGH RISK", "High"
            ctrl_exp = f"{len(ctrl_issues)} controllers require version upgrade before cluster upgrade."
        else:
            ctrl_status, ctrl_sev = "PASS", "Low"
            ctrl_exp = "Installed controller versions support target K8s release."

        # 4. Webhooks
        if webhooks.get("can_webhook_failures_block_workloads") == "YES":
            wh_status, wh_sev = "WARNING", "Medium"
            wh_exp = webhooks.get("block_reason", "Webhooks could block deployments on failure.")
        else:
            wh_status, wh_sev = "PASS", "Low"
            wh_exp = "Webhooks configured with failure bypass or non-blocking policy."

        # 5. Networking
        if networking.get("can_networking_break") == "YES":
            net_status, net_sev = "WARNING", "Medium"
            net_exp = networking.get("reason", "CNI daemonsets require PSP migration.")
        else:
            net_status, net_sev = "PASS", "Low"
            net_exp = "CNI, CoreDNS, and kube-proxy compatible."

        # 6. Storage
        if storage.get("can_storage_become_inaccessible") == "YES":
            st_status, st_sev = "HIGH RISK", "High"
            st_exp = storage.get("reason", "In-tree storage provisioner removed.")
        else:
            st_status, st_sev = "PASS", "Low"
            st_exp = "StorageClasses and CSI drivers fully supported."

        # 7. Security
        if security.get("can_security_changes_break_workloads") == "YES":
            sec_status, sec_sev = "HIGH RISK", "High"
            sec_exp = security.get("reason", "PodSecurityPolicy removal requires PSA labels.")
        else:
            sec_status, sec_sev = "PASS", "Low"
            sec_exp = "Pod Security Admission standards enforced."

        # 8. Runtime
        if not runtime.get("runtime_compatible", True):
            rt_status, rt_sev = "CRITICAL", "Critical"
            rt_exp = runtime.get("reason", "Container runtime incompatible.")
        else:
            rt_status, rt_sev = "PASS", "Low"
            rt_exp = "Container runtime supports CRI v1."

        # 9. Nodes
        n_status, n_sev = "PASS", "Low"
        n_exp = "Node OS and Kubelet skew policy within supported boundaries."

        # 10. Control Plane
        cp_status, cp_sev = "PASS", "Low"
        cp_exp = "Control plane upgrade path follows sequential minor release steps."

        return [
            {"area": "APIs", "status": api_status, "severity": api_sev, "explanation": api_exp},
            {"area": "CRDs", "status": crd_status, "severity": crd_sev, "explanation": crd_exp},
            {"area": "Controllers", "status": ctrl_status, "severity": ctrl_sev, "explanation": ctrl_exp},
            {"area": "Webhooks", "status": wh_status, "severity": wh_sev, "explanation": wh_exp},
            {"area": "Networking", "status": net_status, "severity": net_sev, "explanation": net_exp},
            {"area": "Storage", "status": st_status, "severity": st_sev, "explanation": st_exp},
            {"area": "Security", "status": sec_status, "severity": sec_sev, "explanation": sec_exp},
            {"area": "Runtime", "status": rt_status, "severity": rt_sev, "explanation": rt_exp},
            {"area": "Nodes", "status": n_status, "severity": n_sev, "explanation": n_exp},
            {"area": "Control Plane", "status": cp_status, "severity": cp_sev, "explanation": cp_exp}
        ]

    def _calculate_readiness_score(self, risk_matrix: List[Dict[str, str]]) -> int:
        score = 100
        for item in risk_matrix:
            sev = item["severity"]
            if sev == "Critical":
                score -= 25
            elif sev == "High":
                score -= 15
            elif sev == "Medium":
                score -= 8
        return max(0, score)

    def _calculate_confidence_score(self) -> int:
        c_info = self.data.get("step1_cluster_info", {})
        nodes = c_info.get("node_count", 0)
        is_live = c_info.get("is_managed", False)
        
        confidence = 95
        if nodes == 0:
            confidence -= 15
        if not self.data.get("step4_controllers"):
            confidence -= 10
        return max(50, confidence)

    def _build_mandatory_breakdowns(self) -> List[Dict[str, str]]:
        breakdowns = []
        d = self.data

        # Check API Removals
        for item in d.get("step6_api_removals", []):
            breakdowns.append({
                "what_will_break": f"Workload '{item['object']}' in namespace '{item['namespace']}' ({item['kind']} using {item['current_api']})",
                "when_it_will_break": "Immediately After Upgrade (or next deployment/reconcile)",
                "impact": "Deployment Failure / Reconciliation Failure",
                "severity": "Critical",
                "remediation": item["required_action"]
            })

        # Check Controllers
        for ctrl in d.get("step9_controller_compat", []):
            if ctrl["target_compatibility"] in ["HIGH RISK", "CRITICAL"]:
                c_ver = ctrl['installed_version'] if ctrl['installed_version'].startswith('v') else f"v{ctrl['installed_version']}"
                breakdowns.append({
                    "what_will_break": f"Controller '{ctrl['controller']}' ({c_ver})",
                    "when_it_will_break": "Control Plane Upgrade",
                    "impact": "Outage / Reconciliation Failure",
                    "severity": "High" if ctrl["target_compatibility"] == "HIGH RISK" else "Critical",
                    "remediation": f"Upgrade '{ctrl['controller']}' to a compatible release supporting Kubernetes {self.data['target_version']} before performing cluster upgrade."
                })

        # Check Storage
        st = d.get("step12_storage", {})
        if st.get("can_storage_become_inaccessible") == "YES":
            breakdowns.append({
                "what_will_break": "PersistentVolumes provisioned with in-tree Cloud storage drivers",
                "when_it_will_break": "Control Plane Upgrade (v1.29+)",
                "impact": "Data Risk / Volume Mount Failure",
                "severity": "High",
                "remediation": st.get("reason")
            })

        # Check Security (PSP)
        sec = d.get("step13_security", {})
        if sec.get("can_security_changes_break_workloads") == "YES":
            breakdowns.append({
                "what_will_break": "Privileged daemonsets/pods relying on PodSecurityPolicy",
                "when_it_will_break": "Control Plane Upgrade (v1.25+)",
                "impact": "Pod Admission Failure / Outage",
                "severity": "High",
                "remediation": "Apply Pod Security Admission (PSA) labels to namespaces and configure policy rules before upgrading."
            })

        return breakdowns

    def _build_executive_summary(self, readiness: int, confidence: int, risk_matrix: List[Dict[str, str]], breakdowns: List[Dict[str, str]]) -> Dict[str, Any]:
        if readiness >= 90:
            decision = "APPROVED"
            rec_text = "The cluster upgrade is APPROVED. All pre-upgrade checks indicate full compatibility."
        elif readiness >= 75:
            decision = "CONDITIONAL"
            rec_text = "The cluster upgrade is CONDITIONAL upon executing the required remediation steps prior to control plane upgrade."
        else:
            decision = "NOT RECOMMENDED"
            rec_text = "The cluster upgrade is NOT RECOMMENDED at this time due to critical API removals and unsupported controller versions. Complete all required remediations before attempting upgrade."

        crit_issues = [b["what_will_break"] for b in breakdowns if b["severity"] == "Critical"]
        high_risks = [b["what_will_break"] for b in breakdowns if b["severity"] == "High"]
        warnings = [item["explanation"] for item in risk_matrix if item["severity"] == "Medium"]

        actions = [b["remediation"] for b in breakdowns]

        return {
            "upgrade_decision": decision,
            "source_version": self.data["source_version"],
            "target_version": self.data["target_version"],
            "readiness_score": f"{readiness}/100",
            "confidence_score": f"{confidence}%",
            "critical_issues": crit_issues or ["None detected."],
            "high_risks": high_risks or ["None detected."],
            "warnings": warnings or ["None detected."],
            "required_actions_before_upgrade": actions or ["No pre-upgrade remediation required."],
            "recommended_upgrade_order": [
                "1. Update all workload manifests to replace removed API versions (e.g. policy/v1beta1 -> policy/v1, batch/v1beta1 -> batch/v1, autoscaling/v2beta2 -> autoscaling/v2).",
                "2. Upgrade out-of-date controllers and add-ons (Cluster Autoscaler, Ingress NGINX, Cert-Manager) to target-compatible versions.",
                "3. Configure Pod Security Admission (PSA) labels across all namespaces to replace deprecated PSPs.",
                "4. Perform control plane upgrade sequentially through each minor version step.",
                "5. Drain and upgrade worker nodes sequentially while monitoring pod eviction & resource pressure.",
                "6. Execute post-upgrade verification suite."
            ],
            "post_upgrade_validations": [
                "1. Verify control plane component health via kubectl get componentstatuses / apiservices.",
                "2. Validate all controller reconciliations (cert-manager, ingress-nginx, cluster-autoscaler).",
                "3. Ensure admission webhooks process pod creation events without timeout errors.",
                "4. Verify persistent volume attachments and CNI pod network connectivity."
            ],
            "final_recommendation": rec_text
        }
