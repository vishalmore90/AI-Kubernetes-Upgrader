"""
reporter.py
===========
Generates comprehensive Markdown and JSON reports from assessment results.

Produces:
- Full 17-section Markdown report
- Executive summary
- Risk Matrix table
- Failure scenario analysis
- JSON structured output
"""

import json
from datetime import datetime, timezone
from typing import List

from ai_k8s_upgrader.assessment_engine import (
    AssessmentResult, Status, Severity, IssueCategory
)
from ai_k8s_upgrader.scoring_matrix import ScoringResult, RiskMatrixEntry


# Status Emoji mapping
STATUS_EMOJI = {
    Status.PASS: "✅",
    Status.GOOD: "🟢",
    Status.WARNING: "⚠️",
    Status.HIGH_RISK: "🔴",
    Status.CRITICAL: "🚨",
}

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🚨",
    Severity.HIGH: "🔴",
    Severity.MEDIUM: "⚠️",
    Severity.LOW: "ℹ️",
}


def generate_markdown_report(
    result: AssessmentResult,
    scoring: ScoringResult,
) -> str:
    """Generate the full markdown assessment report."""
    lines = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Header
    lines += [
        "# Kubernetes Upgrade Assessment Report",
        "",
        f"> Generated: {now}",
        f"> Assessment Engine: AI-Kubernetes-Upgrader v1.0.0",
        "",
        "---",
        "",
    ]

    # Executive Summary
    lines += _generate_executive_summary(result, scoring)

    # Step 1: Cluster Info
    lines += _generate_step1(result)

    # Step 2: Workload Inventory
    lines += _generate_step2(result)

    # Step 3: CRD Inventory
    lines += _generate_step3(result)

    # Step 4: Controllers
    lines += _generate_step4(result)

    # Step 5: Release Notes
    lines += _generate_step5(result)

    # Step 6: API Removal Analysis
    lines += _generate_step6(result)

    # Step 7: Deprecated API Analysis
    lines += _generate_step7(result)

    # Step 8: CRD Compatibility
    lines += _generate_step8(result)

    # Step 9: Controller Compatibility
    lines += _generate_step9(result)

    # Step 10: Webhook Analysis
    lines += _generate_step10(result)

    # Step 11: Networking
    lines += _generate_step11(result)

    # Step 12: Storage
    lines += _generate_step12(result)

    # Step 13: Security
    lines += _generate_step13(result)

    # Step 14: Runtime
    lines += _generate_step14(result)

    # Step 15: Resource Pressure
    lines += _generate_step15(result)

    # Step 16: Upgrade Simulation
    lines += _generate_step16(result)

    # Step 17: Failure Scenarios
    lines += _generate_step17(result)

    # Risk Matrix
    lines += _generate_risk_matrix(scoring)

    # Readiness Score
    lines += _generate_readiness_score(scoring)

    # Confidence Score
    lines += _generate_confidence_score(scoring)

    # Mandatory Incompatibility Reports
    if result.incompatibility_reports:
        lines += _generate_incompatibility_reports(result)

    return "\n".join(lines)


def _generate_executive_summary(result: AssessmentResult, scoring: ScoringResult) -> List[str]:
    decision_emoji = {
        "APPROVED": "✅",
        "CONDITIONAL": "⚠️",
        "NOT RECOMMENDED": "🚨",
    }.get(scoring.upgrade_decision, "❓")

    lines = [
        "## Executive Summary",
        "",
        "```",
        f"UPGRADE DECISION: {scoring.upgrade_decision} {decision_emoji}",
        "",
        f"SOURCE VERSION: {result.source_version}",
        f"TARGET VERSION: {result.target_version}",
        f"INTERMEDIATE VERSIONS: {' -> '.join(result.intermediate_versions) if result.intermediate_versions else 'Direct upgrade'}",
        "",
        f"READINESS SCORE: {scoring.readiness_score}/100 ({scoring.readiness_label})",
        f"CONFIDENCE:      {scoring.confidence_score}%",
        "",
    ]

    lines.append("CRITICAL ISSUES:")
    if scoring.critical_issues:
        for issue in scoring.critical_issues:
            lines.append(f"  - {issue}")
    else:
        lines.append("  - None detected")
    lines.append("")

    lines.append("HIGH RISKS:")
    if scoring.high_risks:
        for risk in scoring.high_risks[:5]:
            lines.append(f"  - {risk}")
    else:
        lines.append("  - None detected")
    lines.append("")

    lines.append("WARNINGS:")
    if scoring.warnings:
        for w in scoring.warnings[:5]:
            lines.append(f"  - {w}")
    else:
        lines.append("  - None detected")
    lines.append("")

    lines.append("REQUIRED ACTIONS BEFORE UPGRADE:")
    for action in scoring.required_actions_before:
        lines.append(f"  {action}")
    lines.append("")

    lines.append("RECOMMENDED UPGRADE ORDER:")
    for i, step in enumerate(scoring.recommended_upgrade_order, 1):
        lines.append(f"  {i}. {step}")
    lines.append("")

    lines.append("POST-UPGRADE VALIDATIONS:")
    for v in scoring.post_upgrade_validations[:5]:
        lines.append(f"  {v}")
    lines.append("")

    lines.append(f"FINAL RECOMMENDATION:")
    lines.append(f"  {scoring.final_recommendation}")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")

    return lines


def _generate_step1(result: AssessmentResult) -> List[str]:
    ci = result.cluster_info
    snap = result.snapshot
    lines = [
        "## Step 1 — Cluster Information",
        "",
        f"| Property | Value |",
        f"|---|---|",
        f"| Kubernetes Version | `{ci.get('kubernetes_version', 'N/A')}` |",
        f"| Git Version | `{ci.get('git_version', 'N/A')}` |",
        f"| API Server Version | `{ci.get('api_server_version', 'N/A')}` |",
        f"| Platform | `{ci.get('platform', 'N/A')}` |",
        f"| Cluster Provider | `{ci.get('managed_provider', 'N/A')}` |",
        f"| Managed Cluster | `{ci.get('is_managed', False)}` |",
        f"| HA Control Plane | `{ci.get('ha_control_plane', False)}` |",
        f"| Control Plane Nodes | `{ci.get('control_plane_nodes', 0)}` |",
        f"| Worker Nodes | `{ci.get('worker_nodes', 0)}` |",
        f"| Total Nodes | `{ci.get('total_nodes', 0)}` |",
        f"| Namespaces | `{ci.get('namespaces', 0)}` |",
        f"| Source Version | `{result.source_version}` |",
        f"| Target Version | `{result.target_version}` |",
        f"| Resource Inventory Coverage | `{getattr(result, 'inventory_status', 'N/A')}` |",
        "",
    ]

    # Node details
    node_details = ci.get("node_details", [])
    if node_details:
        lines += [
            "### Node Details",
            "",
            "| Node | Role | K8s Version | OS | Runtime | Status |",
            "|---|---|---|---|---|---|",
        ]
        for n in node_details:
            lines.append(
                f"| `{n['name']}` | {n['role']} | `{n['version']}` | "
                f"{n['os'][:40]} | {n['runtime'][:30]} | {n['status']} |"
            )
        lines.append("")

    lines += ["---", ""]
    return lines


def _generate_step2(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 2 — Workload Inventory",
        "",
        f"| Kind | Count |",
        f"|---|---|",
        f"| Deployments | {len(result.snapshot.deployments)} |",
        f"| StatefulSets | {len(result.snapshot.statefulsets)} |",
        f"| DaemonSets | {len(result.snapshot.daemonsets)} |",
        f"| Jobs | {len(result.snapshot.jobs)} |",
        f"| CronJobs | {len(result.snapshot.cronjobs)} |",
        f"| **Total Workloads** | **{len(result.workload_inventory)}** |",
        "",
    ]

    if result.workload_inventory:
        lines += [
            "### Workload Details (first 20)",
            "",
            "| Namespace | Kind | Name | API Version | Replicas |",
            "|---|---|---|---|---|",
        ]
        for w in result.workload_inventory[:20]:
            lines.append(
                f"| `{w['namespace']}` | {w['kind']} | `{w['name']}` | "
                f"`{w['api_version']}` | {w['replicas']} |"
            )
        if len(result.workload_inventory) > 20:
            lines.append(f"| ... | ... | ... (and {len(result.workload_inventory) - 20} more) | ... | ... |")
        lines.append("")

    lines += ["---", ""]
    return lines


def _generate_step3(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 3 — CRD Inventory",
        "",
        f"**Total CRDs:** {len(result.snapshot.crds)}",
        "",
    ]

    if result.crd_inventory:
        lines += [
            "| CRD Name | Group | Kind | Versions | Storage Version | Has Webhook |",
            "|---|---|---|---|---|---|",
        ]
        for c in result.crd_inventory[:30]:
            lines.append(
                f"| `{c['name'][:50]}` | `{c['group']}` | {c['kind']} | "
                f"`{', '.join(c['versions'])}` | `{c['storage_version']}` | "
                f"{'Yes ⚠️' if c['has_conversion_webhook'] else 'No'} |"
            )
        if len(result.crd_inventory) > 30:
            lines.append(f"| *...and {len(result.crd_inventory) - 30} more CRDs* | | | | | |")
        lines.append("")
    else:
        lines.append("*No CRDs installed.*\n")

    lines += ["---", ""]
    return lines


def _generate_step4(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 4 — Detected Controllers and Operators",
        "",
    ]

    if result.detected_controllers:
        lines += [
            "| Controller | Detected Version |",
            "|---|---|",
        ]
        for name, version in result.detected_controllers.items():
            lines.append(f"| {name} | `{version}` |")
        lines.append("")
    else:
        lines.append("*No known controllers/operators detected automatically.*\n")

    lines += ["---", ""]
    return lines


def _generate_step5(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 5 — Release Note Analysis",
        "",
        f"**Versions reviewed:** {result.source_version} → {result.target_version}",
        f"**Intermediate versions:** {', '.join(result.intermediate_versions) if result.intermediate_versions else 'None (direct upgrade)'}",
        "",
        "### Release Notes Summary",
        "",
    ]

    for note in result.release_notes:
        lines.append(f"- **{note}**")
    lines.append("")

    if result.behavioral_changes:
        lines += [
            "### Breaking Behavioral Changes",
            "",
            "| Version | Category | Severity | Title |",
            "|---|---|---|---|",
        ]
        for change in result.behavioral_changes:
            sev_e = SEVERITY_EMOJI.get(change.severity, "")
            lines.append(
                f"| v{change.version} | {change.category} | {sev_e} {change.severity} | {change.title} |"
            )
        lines.append("")

        for change in result.behavioral_changes:
            sev_e = SEVERITY_EMOJI.get(change.severity, "")
            lines += [
                f"#### {sev_e} v{change.version}: {change.title}",
                "",
                f"**Category:** {change.category}  ",
                f"**Severity:** {change.severity}  ",
                "",
                f"**Description:** {change.description}",
                "",
                f"**Impact:** {change.impact}",
                "",
                f"**Mitigation:** {change.mitigation}",
                "",
            ]

    lines += ["---", ""]
    return lines


def _generate_step6(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 6 — API Removal Analysis",
        "",
    ]

    if not result.api_removal_findings:
        lines += [
            "✅ **No removed APIs detected in active use within the upgrade range.**",
            "",
            "---",
            "",
        ]
        return lines

    lines += [
        f"🚨 **{len(result.api_removal_findings)} removed API(s) detected that affect this upgrade.**",
        "",
    ]

    for f in result.api_removal_findings:
        lines += [
            f"### 🚨 CRITICAL: {f.kind}",
            "",
            "```",
            f"Namespace:        {f.namespace}",
            f"Object:           {f.object_name}",
            f"Kind:             {f.kind}",
            f"Current API:      {f.current_api}",
            f"Removal Version:  Kubernetes {f.removal_version}",
            f"Impact:           {f.impact}",
            f"Required Action:  {f.required_action}",
            f"Confidence:       {f.category}",
            "```",
            "",
        ]

    lines += ["---", ""]
    return lines


def _generate_step7(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 7 — Deprecated API Analysis",
        "",
    ]

    if not result.deprecated_api_findings:
        lines += [
            "✅ **No deprecated APIs requiring immediate action detected in observed resources.**",
            "",
        ]
    else:
        lines += [
            "| Namespace | Object | API Version | Risk Level | Planned Removal | Migration Required |",
            "|---|---|---|---|---|---|",
        ]

        for f in result.deprecated_api_findings:
            risk_e = "🔴" if f.risk_level == "HIGH" else "⚠️"
            lines.append(
                f"| {f.namespace} | {f.object_name} | `{f.api_version}` | "
                f"{risk_e} {f.risk_level} | v{f.planned_removal_version} | {f.migration_required[:80]} |"
            )
        lines.append("")

    upcoming = getattr(result, "upcoming_release_changes", [])
    if upcoming:
        lines += [
            "### Upcoming / Informational Deprecations (Beyond Target Version)",
            "",
            "> Note: These APIs are documented in release deprecation schedules but are not observed as immediate blockers for your target upgrade.",
            "",
            "| Object / Kind | Deprecated API | Planned Removal | Replacement |",
            "|---|---|---|---|",
        ]
        for f in upcoming:
            k = f.get("kind", "") if isinstance(f, dict) else getattr(f, "kind", "")
            av = f.get("api_version", "") if isinstance(f, dict) else getattr(f, "api_version", "")
            pr = f.get("planned_removal", "") if isinstance(f, dict) else getattr(f, "planned_removal", "")
            rep = f.get("replacement", "") if isinstance(f, dict) else getattr(f, "replacement", "")
            lines.append(
                f"| {k} | `{av}` | v{pr} | {rep[:80]} |"
            )
        lines.append("")

    lines += ["---", ""]
    return lines


def _generate_step8(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 8 — CRD Compatibility Analysis",
        "",
    ]

    if not result.crd_compatibility_findings:
        lines += [
            f"✅ **All {len(result.snapshot.crds)} CRD(s) appear compatible with the target version.**",
            "",
            "---",
            "",
        ]
        return lines

    breaking = [f for f in result.crd_compatibility_findings if f.will_break]
    warned = [f for f in result.crd_compatibility_findings if not f.will_break]

    if breaking:
        lines.append(f"🔴 **{len(breaking)} CRD(s) may break after upgrade:**\n")
        for f in breaking:
            lines += [
                f"#### ⚠️ {f.crd_name}",
                "",
                f"**Could this CRD break after upgrade? YES**  ",
                f"**Group:** `{f.group}`  ",
                f"**Kind:** {f.kind}  ",
                f"**Severity:** {f.severity}  ",
                f"**Reason:** {f.reason}",
                "",
            ]

    if warned:
        lines.append(f"⚠️ **{len(warned)} CRD(s) with warnings (no confirmed break):**\n")
        lines += [
            "| CRD | Issue | Severity |",
            "|---|---|---|",
        ]
        for f in warned:
            lines.append(f"| `{f.crd_name}` | {f.issue[:80]} | {f.severity} |")
        lines.append("")

    lines += ["---", ""]
    return lines


def _generate_step9(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 9 — Controller and Operator Compatibility",
        "",
    ]

    if not result.controller_compatibility_findings:
        lines += [
            "⚠️ **No controllers detected. Manual verification recommended.**",
            "",
            "---",
            "",
        ]
        return lines

    lines += [
        "| Controller | Installed Version | Supported K8s | K8s Target | Status | Upgrade Timing |",
        "|---|---|---|---|---|---|",
    ]

    for f in result.controller_compatibility_findings:
        status_e = STATUS_EMOJI.get(f.status, "❓")
        lines.append(
            f"| {f.controller_name} | `{f.installed_version}` | {f.supported_k8s_versions[:40]} | "
            f"{f.target_compatibility[:40]} | {status_e} {f.status} | {f.upgrade_timing} |"
        )

    lines.append("")

    # Detailed notes for incompatible
    incompatible = [f for f in result.controller_compatibility_findings
                    if f.status in [Status.CRITICAL, Status.HIGH_RISK]]
    if incompatible:
        lines.append("### Incompatible Controllers - Detailed Notes\n")
        for f in incompatible:
            lines += [
                f"#### {STATUS_EMOJI.get(f.status, '')} {f.controller_name}",
                "",
                f"**Status:** {f.status}  ",
                f"**Installed Version:** `{f.installed_version}`  ",
                f"**Upgrade Timing:** {f.upgrade_timing}  ",
                f"**Notes:** {f.notes}",
                "",
            ]

    lines += ["---", ""]
    return lines


def _generate_step10(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 10 — Admission Webhook Analysis",
        "",
        f"**Validating Webhooks:** {len(result.snapshot.validating_webhooks)}  ",
        f"**Mutating Webhooks:** {len(result.snapshot.mutating_webhooks)}",
        "",
    ]

    if not result.webhook_findings:
        lines += [
            "✅ **No critical webhook issues detected.**",
            "",
            "---",
            "",
        ]
        return lines

    for f in result.webhook_findings:
        sev_e = SEVERITY_EMOJI.get(f.severity, "")
        lines += [
            f"### {sev_e} {f.name} ({f.kind} Webhook)",
            "",
            f"**Failure Policy:** {f.failure_policy}  ",
            f"**Side Effects:** {f.side_effects}  ",
            f"**Can block workloads?** {'YES ⚠️' if f.can_block_workloads else 'NO'}  ",
            f"**Can fail after upgrade?** {'YES 🔴' if f.can_fail_after_upgrade else 'NO'}  ",
            f"**Reason:** {f.reason}  ",
            f"**Confidence:** {f.category}",
            "",
        ]

    lines += ["---", ""]
    return lines


def _generate_step11(result: AssessmentResult) -> List[str]:
    status_e = STATUS_EMOJI.get(result.networking_status, "❓")
    lines = [
        "## Step 11 — Networking Compatibility Analysis",
        "",
        f"**Status:** {status_e} {result.networking_status}  ",
        f"**CNI Plugin:** `{result.snapshot.cni_plugin or 'unknown'}`  ",
        f"**Ingress Controller:** `{result.snapshot.ingress_controller or 'unknown'}`  ",
        f"**Network Policies:** {len(result.snapshot.network_policies)}",
        "",
        f"**Can networking break after upgrade?** {'YES 🔴' if result.networking_can_break else 'NO ✅'}",
        "",
        f"**Why?** {result.networking_reason}",
        "",
    ]

    if result.networking_issues:
        lines.append("### Networking Issues\n")
        for issue in result.networking_issues:
            prefix = "🚨" if "CRITICAL" in issue else "⚠️"
            lines.append(f"- {prefix} {issue}")
        lines.append("")

    lines += ["---", ""]
    return lines


def _generate_step12(result: AssessmentResult) -> List[str]:
    status_e = STATUS_EMOJI.get(result.storage_status, "❓")
    lines = [
        "## Step 12 — Storage Compatibility Analysis",
        "",
        f"**Status:** {status_e} {result.storage_status}  ",
        f"**StorageClasses:** {len(result.snapshot.storage_classes)}  ",
        f"**PersistentVolumes:** {len(result.snapshot.persistent_volumes)}  ",
        f"**PersistentVolumeClaims:** {len(result.snapshot.persistent_volume_claims)}",
        "",
        f"**Can storage become inaccessible?** {'YES 🔴' if result.storage_can_break else 'NO ✅'}",
        "",
        f"**Why?** {result.storage_reason}",
        "",
    ]

    if result.snapshot.storage_classes:
        lines += [
            "### StorageClasses",
            "",
            "| Name | Provisioner | Reclaim Policy | Default |",
            "|---|---|---|---|",
        ]
        for sc in result.snapshot.storage_classes:
            lines.append(
                f"| `{sc.name}` | `{sc.provisioner}` | {sc.reclaim_policy} | "
                f"{'✅ Yes' if sc.is_default else 'No'} |"
            )
        lines.append("")

    if result.storage_issues:
        lines.append("### Storage Issues\n")
        for issue in result.storage_issues:
            prefix = "🚨" if "CRITICAL" in issue else "⚠️"
            lines.append(f"- {prefix} {issue}")
        lines.append("")

    lines += ["---", ""]
    return lines


def _generate_step13(result: AssessmentResult) -> List[str]:
    status_e = STATUS_EMOJI.get(result.security_status, "❓")
    lines = [
        "## Step 13 — Security Compatibility Analysis",
        "",
        f"**Status:** {status_e} {result.security_status}  ",
        f"**PodSecurityPolicies:** {len(result.snapshot.pod_security_policies)}  ",
        f"**Pod Security Admission:** {'Enabled' if result.snapshot.has_pod_security_admission else 'Not detected'}  ",
        f"**Privileged Workloads:** {len(result.snapshot.privileged_workloads)}",
        "",
        f"**Can security changes break workloads?** {'YES 🔴' if result.security_can_break else 'NO ✅'}",
        "",
        f"**Why?** {result.security_reason}",
        "",
    ]

    if result.snapshot.pod_security_policies:
        lines += [
            "### ⚠️ Pod Security Policies Detected",
            "",
            "| PSP Name |",
            "|---|",
        ]
        for psp in result.snapshot.pod_security_policies:
            lines.append(f"| `{psp}` |")
        lines.append("")

    if result.security_issues:
        lines.append("### Security Issues\n")
        for issue in result.security_issues:
            prefix = "🚨" if "CRITICAL" in issue else "⚠️"
            lines.append(f"- {prefix} {issue}")
        lines.append("")

    lines += ["---", ""]
    return lines


def _generate_step14(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 14 — Runtime Compatibility Analysis",
        "",
    ]

    if result.snapshot.nodes:
        lines += [
            "| Node | Runtime | Target Compatible |",
            "|---|---|---|",
        ]
        for node in result.snapshot.nodes:
            runtime = node.container_runtime
            is_docker = "docker" in runtime.lower() and "containerd" not in runtime.lower()
            compat = "🚨 Docker removed in 1.24" if is_docker else "✅"
            lines.append(f"| `{node.name}` | `{runtime}` | {compat} |")
        lines.append("")

    if result.runtime_issues:
        lines.append("### Runtime Issues\n")
        for issue in result.runtime_issues:
            prefix = "🚨" if "CRITICAL" in issue else "⚠️"
            lines.append(f"- {prefix} {issue}")
        lines.append("")
    else:
        lines.append("✅ **No runtime compatibility issues detected.**\n")

    lines += ["---", ""]
    return lines


def _generate_step15(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 15 — Resource Pressure Analysis",
        "",
    ]

    if result.resource_pressure_issues:
        for issue in result.resource_pressure_issues:
            prefix = "🚨" if "CRITICAL" in issue else "⚠️" if "WARNING" in issue else "ℹ️"
            lines.append(f"- {prefix} {issue}")
        lines.append("")
    else:
        lines.append("✅ **No resource pressure issues detected.**\n")

    lines += ["---", ""]
    return lines


def _generate_step16(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 16 — Upgrade Simulation",
        "",
    ]

    for sub in result.simulation_results:
        status_e = STATUS_EMOJI.get(sub.status, "❓")
        lines += [
            f"### {status_e} {sub.name}",
            "",
            f"**Status:** {sub.status}  ",
            f"**Severity:** {sub.severity}  ",
            f"**Reason:** {sub.explanation}",
            "",
        ]

    lines += ["---", ""]
    return lines


def _generate_step17(result: AssessmentResult) -> List[str]:
    lines = [
        "## Step 17 — Failure Scenario Analysis",
        "",
    ]

    for scenario in result.failure_scenarios:
        answer_e = {
            "YES": "🔴 YES",
            "NO": "✅ NO",
            "POSSIBLE": "⚠️ POSSIBLE",
        }.get(scenario.answer, scenario.answer)

        sev_e = SEVERITY_EMOJI.get(scenario.severity, "")

        lines += [
            f"### {scenario.scenario}",
            "",
            f"**Answer:** {answer_e}  ",
            f"**Severity:** {sev_e} {scenario.severity}  ",
            f"**Reason:** {scenario.reason}  ",
            f"**Confidence:** {scenario.category}",
            "",
        ]

    lines += ["---", ""]
    return lines


def _generate_risk_matrix(scoring: ScoringResult) -> List[str]:
    lines = [
        "## Risk Matrix",
        "",
        "| Area | Status | Severity | Explanation |",
        "|---|---|---|---|",
    ]

    for entry in scoring.risk_matrix:
        status_e = STATUS_EMOJI.get(entry.status, "❓")
        sev_e = SEVERITY_EMOJI.get(entry.severity, "")
        explanation = entry.explanation[:100].replace("|", "\\|")
        lines.append(
            f"| **{entry.area}** | {status_e} {entry.status} | {sev_e} {entry.severity} | {explanation} |"
        )

    lines += ["", "---", ""]
    return lines


def _generate_readiness_score(scoring: ScoringResult) -> List[str]:
    score = scoring.readiness_score
    bar_filled = int(score / 5)
    bar_empty = 20 - bar_filled
    bar = "█" * bar_filled + "░" * bar_empty

    label_e = {
        "Ready": "✅",
        "Ready with remediation": "⚠️",
        "Significant risk": "🔴",
        "Not recommended": "🚨",
    }.get(scoring.readiness_label, "❓")

    lines = [
        "## Readiness Score",
        "",
        f"```",
        f"Readiness Score: {score}/100",
        f"",
        f"[{bar}] {score}%",
        f"",
        f"Rating: {scoring.readiness_label}",
        f"",
        f"90-100 = Ready",
        f"75-89  = Ready with remediation",
        f"50-74  = Significant risk",
        f"0-49   = Not recommended",
        f"```",
        "",
        f"**{label_e} {scoring.readiness_label}**",
        "",
        "---",
        "",
    ]
    return lines


def _generate_confidence_score(scoring: ScoringResult) -> List[str]:
    score = scoring.confidence_score
    lines = [
        "## Confidence Score",
        "",
        f"```",
        f"Confidence Score: {score}%",
        "",
        "Confidence Factors:",
    ]

    for factor in scoring.confidence_factors:
        lines.append(f"  {factor}")

    lines += [
        f"```",
        "",
        "---",
        "",
    ]
    return lines


def _generate_incompatibility_reports(result: AssessmentResult) -> List[str]:
    lines = [
        "## Mandatory Incompatibility Reports",
        "",
        "> All confirmed, probable, or possible incompatibilities are documented below.",
        "",
    ]

    for i, report in enumerate(result.incompatibility_reports, 1):
        sev_e = SEVERITY_EMOJI.get(report.severity, "")
        lines += [
            f"### {sev_e} Incompatibility #{i} ({report.category})",
            "",
            "```",
            f"WHAT WILL BREAK:  {report.what_will_break}",
            f"WHEN IT WILL BREAK: {report.when_it_will_break}",
            f"IMPACT:           {report.impact}",
            f"SEVERITY:         {report.severity}",
            f"REMEDIATION:      {report.remediation}",
            "```",
            "",
        ]

    return lines


def generate_json_report(result: AssessmentResult, scoring: ScoringResult) -> str:
    """Generate JSON-structured report for programmatic use."""
    data = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source_version": result.source_version,
            "target_version": result.target_version,
            "intermediate_versions": result.intermediate_versions,
            "inventory_status": getattr(result, "inventory_status", "UNKNOWN"),
        },
        "executive_summary": {
            "upgrade_decision": scoring.upgrade_decision,
            "readiness_score": scoring.readiness_score,
            "readiness_label": scoring.readiness_label,
            "confidence_score": scoring.confidence_score,
            "critical_issues": scoring.critical_issues,
            "high_risks": scoring.high_risks,
            "warnings": scoring.warnings,
            "required_actions_before": scoring.required_actions_before,
            "recommended_upgrade_order": scoring.recommended_upgrade_order,
            "post_upgrade_validations": scoring.post_upgrade_validations,
            "final_recommendation": scoring.final_recommendation,
        },
        "risk_matrix": [
            {
                "area": e.area,
                "status": e.status,
                "severity": e.severity,
                "explanation": e.explanation,
            }
            for e in scoring.risk_matrix
        ],
        "api_removals": [
            {
                "kind": f.kind,
                "current_api": f.current_api,
                "removal_version": f.removal_version,
                "replacement_api": f.replacement_api,
                "severity": f.severity,
                "category": f.category,
            }
            for f in result.api_removal_findings
        ],
        "deprecated_apis": [
            {
                "kind": f.object_name,
                "api_version": f.api_version,
                "risk_level": f.risk_level,
                "planned_removal": f.planned_removal_version,
            }
            for f in result.deprecated_api_findings
        ],
        "upcoming_release_changes": [
            {
                "kind": f.get("kind", "") if isinstance(f, dict) else getattr(f, "kind", ""),
                "api_version": f.get("api_version", "") if isinstance(f, dict) else getattr(f, "api_version", ""),
                "planned_removal": f.get("planned_removal", "") if isinstance(f, dict) else getattr(f, "planned_removal", ""),
                "replacement": f.get("replacement", "") if isinstance(f, dict) else getattr(f, "replacement", ""),
            }
            for f in getattr(result, "upcoming_release_changes", [])
        ],
        "controller_compatibility": [
            {
                "name": f.controller_name,
                "installed_version": f.installed_version,
                "status": f.status,
                "upgrade_timing": f.upgrade_timing,
            }
            for f in result.controller_compatibility_findings
        ],
        "webhook_findings": [
            {
                "name": f.name,
                "kind": f.kind,
                "failure_policy": f.failure_policy,
                "can_block": f.can_block_workloads,
                "can_fail": f.can_fail_after_upgrade,
                "severity": f.severity,
            }
            for f in result.webhook_findings
        ],
        "failure_scenarios": [
            {
                "scenario": f.scenario,
                "answer": f.answer,
                "reason": f.reason,
                "severity": f.severity,
            }
            for f in result.failure_scenarios
        ],
        "simulation_results": [
            {
                "subsystem": s.name,
                "status": s.status,
                "severity": s.severity,
                "explanation": s.explanation,
            }
            for s in result.simulation_results
        ],
        "incompatibility_reports": [
            {
                "what_will_break": r.what_will_break,
                "when": r.when_it_will_break,
                "impact": r.impact,
                "severity": r.severity,
                "remediation": r.remediation,
                "category": r.category,
            }
            for r in result.incompatibility_reports
        ],
    }
    return json.dumps(data, indent=2)
