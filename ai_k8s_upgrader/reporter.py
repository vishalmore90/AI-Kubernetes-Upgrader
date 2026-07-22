"""
Markdown & Text Report Generation Module.
Formats assessment engine output into publication-ready Markdown adhering strictly to prompt specs.
"""

from typing import Dict, Any

class ReportGenerator:
    def __init__(self, assessment_result: Dict[str, Any], scoring_result: Dict[str, Any]):
        self.a = assessment_result
        self.s = scoring_result

    def generate_markdown(self) -> str:
        a = self.a
        s = self.s
        exec_s = s["executive_summary"]
        risk_m = s["risk_matrix"]
        breakdowns = s["mandatory_breakdowns"]

        md = []

        md.append("# Kubernetes Upgrade Feasibility, Compatibility, and Risk Assessment Report\n")
        md.append(f"**SOURCE_VERSION**=`{a['source_version']}`\n**TARGET_VERSION**=`{a['target_version']}`\n")
        md.append("---\n")

        # Executive Summary
        md.append("# Executive Summary\n")
        md.append("```text")
        md.append(f"UPGRADE DECISION:\n{exec_s['upgrade_decision']}\n")
        md.append(f"SOURCE VERSION:\n{exec_s['source_version']}\n")
        md.append(f"TARGET VERSION:\n{exec_s['target_version']}\n")
        md.append(f"READINESS SCORE:\n{exec_s['readiness_score']}\n")
        md.append(f"CONFIDENCE:\n{exec_s['confidence_score']}\n")
        md.append("CRITICAL ISSUES:")
        for item in exec_s["critical_issues"]:
            md.append(f"- {item}")
        md.append("\nHIGH RISKS:")
        for item in exec_s["high_risks"]:
            md.append(f"- {item}")
        md.append("\nWARNINGS:")
        for item in exec_s["warnings"]:
            md.append(f"- {item}")
        md.append("\nREQUIRED ACTIONS BEFORE UPGRADE:")
        for idx, act in enumerate(exec_s["required_actions_before_upgrade"], 1):
            md.append(f"{idx}. {act}")
        md.append("\nRECOMMENDED UPGRADE ORDER:")
        for order in exec_s["recommended_upgrade_order"]:
            md.append(f"{order}")
        md.append("\nPOST-UPGRADE VALIDATIONS:")
        for val in exec_s["post_upgrade_validations"]:
            md.append(f"{val}")
        md.append("\nFINAL RECOMMENDATION:")
        md.append(exec_s["final_recommendation"])
        md.append("```\n")

        # Mandatory Rule / Incompatibilities
        if breakdowns:
            md.append("# Mandatory Incompatibility Breakdowns\n")
            for b in breakdowns:
                md.append("```text")
                md.append(f"WHAT WILL BREAK:\n{b['what_will_break']}\n")
                md.append(f"WHEN IT WILL BREAK:\n{b['when_it_will_break']}\n")
                md.append(f"IMPACT:\n{b['impact']}\n")
                md.append(f"SEVERITY:\n{b['severity']}\n")
                md.append(f"REMEDIATION:\n{b['remediation']}")
                md.append("```\n")

        # Risk Matrix
        md.append("# Risk Matrix\n")
        md.append("| Area | Status | Severity | Explanation |")
        md.append("| --- | --- | --- | --- |")
        for row in risk_m:
            md.append(f"| {row['area']} | {row['status']} | {row['severity']} | {row['explanation']} |")
        md.append("\n")

        # Readiness & Confidence
        md.append("# Readiness Score\n")
        md.append(f"```text\nReadiness Score: {exec_s['readiness_score']}\n```")
        md.append("Scoring:\n- 90-100 = Ready\n- 75-89 = Ready with remediation\n- 50-74 = Significant risk\n- 0-49 = Not recommended\n")

        md.append("# Confidence Score\n")
        md.append(f"```text\nConfidence Score: {exec_s['confidence_score']}\n```\n")

        # Step 1
        s1 = a["step1_cluster_info"]
        md.append("# Step 1 - Cluster Information\n")
        md.append(f"- **Kubernetes Version**: {s1['k8s_version']}")
        md.append(f"- **API Server Version**: {s1['api_server_version']}")
        md.append(f"- **Node Count**: {s1['node_count']}")
        md.append(f"- **Kubelet Versions**: {', '.join(s1['kubelet_versions'])}")
        md.append(f"- **OS Versions**: {', '.join(s1['os_versions'])}")
        md.append(f"- **Container Runtimes**: {', '.join(s1['container_runtimes'])}")
        md.append(f"- **Cluster Managed/Provider**: {s1['provider']}")
        md.append(f"- **HA Topology**: {s1['ha_topology']}\n")

        # Step 2
        s2 = a["step2_inventory"]
        md.append("# Step 2 - Resource Inventory\n")
        md.append(f"Total Workloads Analyzed: {len(s2)}\n")
        md.append("| Namespace | Kind | Name | API Version | Criticality | Restarts |")
        md.append("| --- | --- | --- | --- | --- | --- |")
        for w in s2[:25]:
            md.append(f"| {w['namespace']} | {w['kind']} | {w['name']} | {w['api_version']} | {w['criticality']} | {w['restarts']} |")
        if len(s2) > 25:
            md.append(f"*... and {len(s2) - 25} additional workloads.*")
        md.append("\n")

        # Step 3
        s3 = a["step3_crds"]
        md.append("# Step 3 - Installed CRDs\n")
        md.append(f"Total CRDs Found: {len(s3)}\n")
        md.append("| CRD Name | Group | Kind | Served Versions | Storage Version | Conversion |")
        md.append("| --- | --- | --- | --- | --- | --- |")
        for crd in s3[:20]:
            md.append(f"| {crd['name']} | {crd['group']} | {crd['kind']} | {', '.join(crd['served_versions'])} | {crd['storage_version']} | {crd['conversion_strategy']} |")
        md.append("\n")

        # Step 4
        s4 = a["step4_controllers"]
        md.append("# Step 4 - Identified Controllers and Operators\n")
        md.append("| Controller Key | Name | Namespace | Installed Version |")
        md.append("| --- | --- | --- | --- |")
        for c in s4:
            md.append(f"| {c['key']} | {c['name']} | {c['namespace']} | {c['installed_version']} |")
        md.append("\n")

        # Step 5
        s5 = a["step5_release_notes"]
        md.append("# Step 5 - Kubernetes Release Notes Analysis\n")
        for note in s5["notes"]:
            md.append(f"### Upgrade Step: {note['step']}")
            for change in note["breaking_changes"]:
                md.append(f"- {change}")
        md.append("\n")

        # Step 6
        s6 = a["step6_api_removals"]
        md.append("# Step 6 - API Removal Analysis\n")
        if not s6:
            md.append("No workloads using removed APIs detected.\n")
        else:
            for rem in s6:
                md.append("```text")
                md.append(f"Namespace:\n{rem['namespace']}\n")
                md.append(f"Object:\n{rem['object']}\n")
                md.append(f"Kind:\n{rem['kind']}\n")
                md.append(f"Current API:\n{rem['current_api']}\n")
                md.append(f"Removal Version:\n{rem['removal_version']}\n")
                md.append(f"Impact:\n{rem['impact']}\n")
                md.append(f"Required Action:\n{rem['required_action']}\n")
                md.append("Classify as:\nCRITICAL")
                md.append("```\n")

        # Step 7
        s7 = a["step7_deprecated_apis"]
        md.append("# Step 7 - Deprecated API Analysis\n")
        if not s7:
            md.append("No workloads using deprecated APIs detected.\n")
        else:
            md.append("| Namespace | Object | API Version | Risk Level | Migration Required |")
            md.append("| --- | --- | --- | --- | --- |")
            for dep in s7:
                md.append(f"| {dep['namespace']} | {dep['object']} | {dep['api_version']} | {dep['risk_level']} | {dep['migration_required']} |")
            md.append("\n")

        # Step 8
        s8 = a["step8_crd_compat"]
        md.append("# Step 8 - CRD Compatibility Analysis\n")
        for crd in s8[:15]:
            md.append(f"### CRD: `{crd['crd_name']}`")
            break_str = "YES" if crd['could_break'] else "NO"
            md.append("```text")
            md.append(f"Could this CRD break after upgrade?\n{break_str}\n")
            md.append(f"Reason:\n{'; '.join(crd['break_reasons'])}")
            md.append("```\n")

        # Step 9
        s9 = a["step9_controller_compat"]
        md.append("# Step 9 - Controller and Operator Compatibility\n")
        for ctrl in s9:
            md.append("```text")
            md.append(f"Installed Version:\n{ctrl['installed_version']}")
            md.append(f"Supported Kubernetes Versions:\n{ctrl['supported_k8s_versions']}")
            md.append(f"Target Compatibility:\n{ctrl['target_compatibility']}")
            md.append(f"Upgrade Required:\n{ctrl['upgrade_timing_required']}")
            md.append("```\n")

        # Step 10
        s10 = a["step10_webhooks"]
        md.append("# Step 10 - Admission Webhook Analysis\n")
        md.append("```text")
        md.append(f"Can webhook failures block workloads?\n{s10['can_webhook_failures_block_workloads']}\n")
        md.append(f"Can webhook fail after upgrade?\n{s10['can_webhook_fail_after_upgrade']}\n")
        md.append(f"Reason:\n{s10['block_reason']} {s10['fail_reason']}")
        md.append("```\n")

        # Step 11
        s11 = a["step11_networking"]
        md.append("# Step 11 - Networking Compatibility Analysis\n")
        md.append("```text")
        md.append(f"Can networking break after upgrade?\n{s11['can_networking_break']}\n")
        md.append(f"Why?\n{s11['reason']}")
        md.append("```\n")

        # Step 12
        s12 = a["step12_storage"]
        md.append("# Step 12 - Storage Compatibility Analysis\n")
        md.append("```text")
        md.append(f"Can storage become inaccessible?\n{s12['can_storage_become_inaccessible']}\n")
        md.append(f"Why?\n{s12['reason']}")
        md.append("```\n")

        # Step 13
        s13 = a["step13_security"]
        md.append("# Step 13 - Security Compatibility Analysis\n")
        md.append("```text")
        md.append(f"Can security changes break workloads?\n{s13['can_security_changes_break_workloads']}\n")
        md.append(f"Why?\n{s13['reason']}")
        md.append("```\n")

        # Step 14
        s14 = a["step14_runtime"]
        md.append("# Step 14 - Runtime Compatibility Analysis\n")
        md.append(f"- **Runtimes Detected**: {', '.join(s14['runtimes_detected'])}")
        md.append(f"- **Runtime Compatible**: {'YES' if s14['runtime_compatible'] else 'NO'}")
        md.append(f"- **Details**: {s14['reason']}\n")

        # Step 15
        s15 = a["step15_resource_pressure"]
        md.append("# Step 15 - Resource Pressure Analysis\n")
        md.append(f"- **CPU Pressure Risk**: {s15['cpu_pressure_risk']}")
        md.append(f"- **Memory Pressure Risk**: {s15['memory_pressure_risk']}")
        md.append(f"- **Eviction Risk**: {s15['eviction_risk']}")
        md.append(f"- **Recommendation**: {s15['recommendation']}\n")

        # Step 16
        s16 = a["step16_simulation"]
        md.append("# Step 16 - Upgrade Simulation\n")
        for area, data in s16.items():
            md.append(f"## {area.replace('_', ' ').title()}\n")
            md.append(f"Status:\n```text\n{data['status']}\n```\n")
            md.append(f"Reason:\n{data['reason']}\n")

        # Step 17
        s17 = a["step17_failure_scenarios"]
        md.append("# Step 17 - Failure Scenario Analysis\n")
        for question_key, data in s17.items():
            title_q = question_key.replace('_', ' ').capitalize() + "?"
            md.append(f"## Could {title_q.lower()}\n")
            md.append(f"```text\n{data['answer']}\n```\n")
            md.append(f"Reason:\n{data['reason']}\n")

        return "\n".join(md)
