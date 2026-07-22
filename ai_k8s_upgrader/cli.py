"""
cli.py
======
Command-line interface for the AI-Kubernetes-Upgrader tool.

Usage:
    k8s-upgrade-assess --source 1.27 --target 1.30 --sample
    k8s-upgrade-assess --source 1.27 --target 1.30 --snapshot cluster.json
    k8s-upgrade-assess --source 1.27 --target 1.30 --live
    k8s-upgrade-assess --source 1.27 --target 1.30 --sample --output report.md
    k8s-upgrade-assess --serve
    k8s-upgrade-assess --serve --port 8080
"""

import json
import os
import sys
import tempfile
import click

from ai_k8s_upgrader.assessment_engine import AssessmentEngine
from ai_k8s_upgrader.scoring_matrix import ScoringEngine
from ai_k8s_upgrader.reporter import generate_markdown_report, generate_json_report
from ai_k8s_upgrader.sample_generator import save_sample_cluster, generate_sample_cluster

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def _print(msg: str, style: str = ""):
    if RICH_AVAILABLE and console:
        console.print(msg)
    else:
        # Strip rich markup
        import re
        clean = re.sub(r'\[/?[^\]]*\]', '', msg)
        print(clean)


def _banner():
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║        AI-Kubernetes-Upgrader  ·  v1.0.0 Enterprise Edition      ║
║   Kubernetes Upgrade Feasibility, Compatibility & Risk Assessor   ║
╚═══════════════════════════════════════════════════════════════════╝
"""
    _print(f"[bold cyan]{banner}[/]" if RICH_AVAILABLE else banner)


def _run_assessment(source: str, target: str, mode: str,
                    snapshot_path: str = None,
                    kubeconfig: str = None,
                    context: str = None,
                    output_format: str = "markdown",
                    output_file: str = None,
                    quiet: bool = False):
    """Core assessment logic."""
    from ai_k8s_upgrader.cluster_collector import collect_cluster_state, SnapshotClusterCollector

    if not quiet:
        _print(f"\n[bold]🎯 Assessment:[/] K8s [cyan]{source}[/] → [green]{target}[/]")
        _print(f"[bold]📊 Mode:[/] {mode}\n")

    # Step 1: Collect cluster state
    if not quiet:
        _print("[dim]Collecting cluster state...[/]")

    if mode == "sample":
        cluster_data = generate_sample_cluster(source_version=source, target_version=target)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(cluster_data, f)
            tmp_path = f.name
        collector = SnapshotClusterCollector(tmp_path)
        snapshot = collector.collect()
        snapshot.source_mode = "sample"
        os.unlink(tmp_path)
    elif mode == "snapshot":
        if not snapshot_path or not os.path.exists(snapshot_path):
            _print(f"[red]❌ Snapshot file not found: {snapshot_path}[/]")
            sys.exit(1)
        collector = SnapshotClusterCollector(snapshot_path)
        snapshot = collector.collect()
    elif mode == "live":
        snapshot = collect_cluster_state(mode="live", kubeconfig=kubeconfig, context=context)
    else:
        _print(f"[red]❌ Unknown mode: {mode}[/]")
        sys.exit(1)

    if not quiet:
        _print(f"[dim]✓ Cluster state collected ({len(snapshot.nodes)} nodes, "
               f"{len(snapshot.deployments)} deployments, {len(snapshot.crds)} CRDs)[/]")

    # Step 2: Run assessment
    if not quiet:
        _print("[dim]Running 17-step assessment engine...[/]")

    engine = AssessmentEngine(source, target, snapshot)
    result = engine.run_all()

    # Step 3: Score
    scorer = ScoringEngine(result)
    scoring = scorer.calculate()

    if not quiet:
        _print("[dim]✓ Assessment complete.[/]\n")
        _print_summary(result, scoring)

    # Step 4: Generate report
    if output_format == "json":
        report_content = generate_json_report(result, scoring)
        ext = ".json"
    else:
        report_content = generate_markdown_report(result, scoring)
        ext = ".md"

    # Write report
    if output_file:
        out_path = output_file
    else:
        out_path = f"reports/upgrade_assessment_{source}_to_{target}{ext}"

    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    if not quiet:
        _print(f"\n[bold green]✅ Report saved:[/] [cyan]{out_path}[/]")
        _print(f"\n[dim]To launch the web dashboard, run:[/] [bold]k8s-upgrade-assess --serve[/]\n")

    return result, scoring


def _print_summary(result, scoring):
    """Print a concise summary to the terminal."""
    decision_color = {
        "APPROVED": "green",
        "CONDITIONAL": "yellow",
        "NOT RECOMMENDED": "red",
    }.get(scoring.upgrade_decision, "white")

    decision_emoji = {
        "APPROVED": "✅",
        "CONDITIONAL": "⚠️",
        "NOT RECOMMENDED": "🚨",
    }.get(scoring.upgrade_decision, "❓")

    if RICH_AVAILABLE:
        # Decision panel
        console.rule()
        console.print(f"\n  UPGRADE DECISION: [{decision_color} bold]{decision_emoji} {scoring.upgrade_decision}[/]")
        console.print(f"  Readiness Score: [bold]{scoring.readiness_score}/100[/] ({scoring.readiness_label})")
        console.print(f"  Confidence:      [bold]{scoring.confidence_score}%[/]")
        console.rule()

        # Risk matrix table
        table = Table(title="Risk Matrix", show_header=True, header_style="bold cyan")
        table.add_column("Area", width=14)
        table.add_column("Status", width=14)
        table.add_column("Severity", width=10)
        table.add_column("Explanation")

        status_styles = {
            "PASS": "green", "GOOD": "green",
            "WARNING": "yellow", "HIGH RISK": "red", "CRITICAL": "bold red"
        }

        for entry in scoring.risk_matrix:
            style = status_styles.get(entry.status, "white")
            table.add_row(
                f"[bold]{entry.area}[/]",
                f"[{style}]{entry.status}[/]",
                entry.severity,
                entry.explanation[:80] + "..." if len(entry.explanation) > 80 else entry.explanation,
            )
        console.print(table)

        # Critical issues
        if scoring.critical_issues:
            console.print("\n[bold red]🚨 CRITICAL ISSUES:[/]")
            for issue in scoring.critical_issues:
                console.print(f"  • {issue}")

        if scoring.high_risks:
            console.print("\n[bold yellow]🔴 HIGH RISKS:[/]")
            for risk in scoring.high_risks[:5]:
                console.print(f"  • {risk}")

        # Required actions
        if scoring.required_actions_before:
            console.print("\n[bold]📋 REQUIRED ACTIONS BEFORE UPGRADE:[/]")
            for action in scoring.required_actions_before:
                console.print(f"  {action}")

    else:
        # Plain text summary
        print(f"\n{'='*70}")
        print(f"  UPGRADE DECISION: {decision_emoji} {scoring.upgrade_decision}")
        print(f"  Readiness Score:  {scoring.readiness_score}/100 ({scoring.readiness_label})")
        print(f"  Confidence:       {scoring.confidence_score}%")
        print(f"{'='*70}")
        print("\nRISK MATRIX:")
        for entry in scoring.risk_matrix:
            print(f"  {entry.area:14} | {entry.status:10} | {entry.severity:8} | {entry.explanation[:60]}")
        if scoring.critical_issues:
            print("\nCRITICAL ISSUES:")
            for issue in scoring.critical_issues:
                print(f"  * {issue}")
        print()


# ---------------------------------------------------------------------------
# CLI Commands
# ---------------------------------------------------------------------------

@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx):
    """AI-Kubernetes-Upgrader: Kubernetes Upgrade Feasibility, Compatibility, and Risk Assessment Engine."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
@click.option("--source", "-s", required=True, help="Source Kubernetes version (e.g. 1.27)")
@click.option("--target", "-t", required=True, help="Target Kubernetes version (e.g. 1.30)")
@click.option("--snapshot", "snapshot_path", default=None, help="Path to cluster snapshot JSON file")
@click.option("--live", "use_live", is_flag=True, default=False, help="Use live cluster via kubectl")
@click.option("--sample", "use_sample", is_flag=True, default=False, help="Use generated sample cluster data")
@click.option("--kubeconfig", default=None, help="Path to kubeconfig file (for live mode)")
@click.option("--context", "kube_context", default=None, help="kubectl context to use (for live mode)")
@click.option("--output", "-o", default=None, help="Output file path for report")
@click.option("--format", "fmt", default="markdown", type=click.Choice(["markdown", "json"]), help="Output format")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress progress output")
def assess(source, target, snapshot_path, use_live, use_sample, kubeconfig, kube_context, output, fmt, quiet):
    """Run a comprehensive Kubernetes upgrade assessment (all 17 steps)."""
    if not quiet:
        _banner()

    # Determine mode
    if use_sample:
        mode = "sample"
    elif use_live:
        mode = "live"
    elif snapshot_path:
        mode = "snapshot"
    else:
        # Default to sample if nothing specified
        _print("[yellow]No mode specified. Using --sample mode. Use --help for options.[/]")
        mode = "sample"

    _run_assessment(
        source=source.lstrip("v"),
        target=target.lstrip("v"),
        mode=mode,
        snapshot_path=snapshot_path,
        kubeconfig=kubeconfig,
        context=kube_context,
        output_format=fmt,
        output_file=output,
        quiet=quiet,
    )


@main.command()
@click.option("--source", "-s", default="1.27", help="Source K8s version for sample")
@click.option("--target", "-t", default="1.30", help="Target K8s version for sample")
@click.option("--output", "-o", default="samples/sample_cluster.json", help="Output path for sample JSON")
def generate_sample(source, target, output):
    """Generate a sample cluster JSON snapshot for testing."""
    _banner()
    os.makedirs(os.path.dirname(output) if os.path.dirname(output) else ".", exist_ok=True)
    save_sample_cluster(output, source_version=source, target_version=target)
    _print(f"[green]✅ Sample cluster snapshot saved to:[/] [cyan]{output}[/]")
    _print(f"\nTo run assessment with this sample:")
    _print(f"  k8s-upgrade-assess assess --source {source} --target {target} --snapshot {output}")


@main.command()
@click.option("--host", default="0.0.0.0", help="Host to bind dashboard")
@click.option("--port", default=5000, help="Port for web dashboard")
@click.option("--debug", is_flag=True, default=False, help="Enable Flask debug mode")
def serve(host, port, debug):
    """Launch the interactive web dashboard."""
    _banner()
    from ai_k8s_upgrader.web_dashboard import run_dashboard
    run_dashboard(host=host, port=port, debug=debug)


@main.command()
def version():
    """Show the version."""
    _print("[cyan]AI-Kubernetes-Upgrader[/] v1.0.0")
    _print("Enterprise-grade Kubernetes Upgrade Assessment Engine")


if __name__ == "__main__":
    main()
