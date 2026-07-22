"""
CLI Interface for AI-Kubernetes-Upgrader.
"""

import argparse
import json
import sys
import os

from .cluster_collector import ClusterCollector
from .assessment_engine import AssessmentEngine
from .scoring_matrix import ScoringMatrixEngine
from .reporter import ReportGenerator
from .sample_generator import generate_sample_cluster_data

def main():
    parser = argparse.ArgumentParser(description="AI-Kubernetes-Upgrader: Kubernetes Upgrade Feasibility & Risk Assessment Engine")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: analyze
    analyze_parser = subparsers.add_parser("analyze", help="Run upgrade feasibility and risk assessment")
    analyze_parser.add_argument("--source", required=True, help="Source Kubernetes version (e.g., v1.25.0)")
    analyze_parser.add_argument("--target", required=True, help="Target Kubernetes version (e.g., v1.29.0)")
    analyze_parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    analyze_parser.add_argument("--snapshot", help="Path to offline cluster snapshot JSON file")
    analyze_parser.add_argument("--output-file", default="reports/upgrade_assessment_report.md", help="Output file path")
    analyze_parser.add_argument("--output-format", choices=["markdown", "json"], default="markdown", help="Report format")

    # Command: generate-snapshot
    gen_parser = subparsers.add_parser("generate-snapshot", help="Generate sample production cluster JSON snapshot")
    gen_parser.add_argument("--output", default="samples/sample_cluster.json", help="Output JSON path")

    # Command: serve
    serve_parser = subparsers.add_parser("serve", help="Launch interactive Web Dashboard for report visualization")
    serve_parser.add_argument("--port", type=int, default=8080, help="Port to run web dashboard")
    serve_parser.add_argument("--report", default="reports/upgrade_assessment_report.md", help="Report file path")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "generate-snapshot":
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        data = generate_sample_cluster_data()
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Sample cluster snapshot generated successfully at: {args.output}")
        return

    if args.command == "analyze":
        snapshot_path = args.snapshot
        if not snapshot_path and not os.path.exists(os.path.expanduser("~/.kube/config")) and not args.kubeconfig:
            print("[!] No live cluster or kubeconfig found. Automatically generating sample cluster snapshot...")
            snapshot_path = "samples/sample_cluster.json"
            if not os.path.exists(snapshot_path):
                os.makedirs("samples", exist_ok=True)
                sample_data = generate_sample_cluster_data()
                with open(snapshot_path, "w", encoding="utf-8") as f:
                    json.dump(sample_data, f, indent=2)

        collector = ClusterCollector(kubeconfig=args.kubeconfig, snapshot_file=snapshot_path)
        cluster_data = collector.collect()

        print(f"[*] Running assessment from {args.source} to {args.target}...")
        engine = AssessmentEngine(cluster_data, args.source, args.target)
        assessment_res = engine.run_assessment()

        scoring = ScoringMatrixEngine(assessment_res)
        scoring_res = scoring.generate_report_sections()

        os.makedirs(os.path.dirname(args.output_file), exist_ok=True)

        if args.output_format == "json":
            combined = {"assessment": assessment_res, "scoring": scoring_res}
            with open(args.output_file, "w", encoding="utf-8") as f:
                json.dump(combined, f, indent=2)
        else:
            reporter = ReportGenerator(assessment_res, scoring_res)
            md_content = reporter.generate_markdown()
            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(md_content)

        print(f"[+] Upgrade assessment completed successfully!")
        print(f"[+] Readiness Score: {scoring_res['executive_summary']['readiness_score']}")
        print(f"[+] Upgrade Decision: {scoring_res['executive_summary']['upgrade_decision']}")
        print(f"[+] Assessment report saved to: {args.output_file}")

    if args.command == "serve":
        from .web_dashboard import start_web_dashboard
        start_web_dashboard(args.report, args.port)

if __name__ == "__main__":
    main()
