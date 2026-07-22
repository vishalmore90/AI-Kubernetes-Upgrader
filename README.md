# AI-Kubernetes-Upgrader

AI-Kubernetes-Upgrader is a comprehensive, automated, evidence-based Kubernetes upgrade feasibility, compatibility, and risk assessment engine. It systematically analyzes cluster resources, API deprecations/removals, CRDs, controllers, webhooks, networking, storage, and security before upgrading cluster versions.

## Features

This tool performs a 17-step assessment process to generate detailed risk and readiness reports:

*   **Cluster Information:** Gathers details about cluster version, nodes, and control plane topology.
*   **Workload & CRD Inventory:** Catalogs all workloads and Custom Resource Definitions.
*   **API Deprecation & Removal Analysis:** Identifies APIs in use that will be deprecated or removed in the target Kubernetes version (e.g., PodSecurityPolicy, Dockershim, FlowSchema).
*   **Controller/Operator Compatibility:** Verifies if installed controllers (e.g., cert-manager, ingress-nginx, cluster-autoscaler) are compatible with the target Kubernetes version.
*   **Admission Webhook Analysis:** Evaluates validating and mutating webhooks for potential failure policies that could block upgrades.
*   **Networking, Storage & Security:** Assesses CNI plugins, storage provisioners (detects deprecated in-tree provisioners), and security policies (e.g., PSP removals).
*   **Runtime & Resource Pressure:** Checks container runtime compatibility and node resource pressures.
*   **Upgrade Simulation & Failure Scenarios:** Models failure scenarios to predict what might break during or after the upgrade.
*   **Scoring & Reporting:** Generates a 10-area Risk Matrix, a Readiness Score (0-100), and a Confidence Score, along with a final upgrade decision (APPROVED, CONDITIONAL, NOT RECOMMENDED).

## Components

*   **CLI Interface (`k8s-upgrade-assess`):** Run assessments directly from your terminal.
*   **Interactive Web Dashboard:** A premium, dark-themed Flask dashboard to visualize the risk matrix, score gauges, and detailed assessment results.
*   **Sample Generator:** Generates realistic cluster snapshots (with various configurable risk factors) for testing and demonstration.
*   **Markdown & JSON Reports:** Export comprehensive reports for documentation or programmatic use.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/vishalmore90/AI-Kubernetes-Upgrader.git
    cd AI-Kubernetes-Upgrader
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  (Optional) Install as a package:
    ```bash
    pip install -e .
    ```

## Quick Start

```bash
# Launch dashboard
python -m ai_k8s_upgrader.cli serve --port 5000

# CLI one-shot assessment (using generated sample)
python -m ai_k8s_upgrader.cli assess --source 1.27 --target 1.30 --sample

# Assess your own cluster from a snapshot
python -m ai_k8s_upgrader.cli assess --source 1.27 --target 1.30 --snapshot cluster.json
```

## Usage

### Command Line Interface (CLI)

You can run the assessment in three modes:

1.  **Sample Mode:** Uses a generated realistic sample cluster snapshot.
    ```bash
    k8s-upgrade-assess --source 1.27 --target 1.30 --sample
    ```

2.  **Snapshot Mode:** Uses a JSON snapshot of your cluster.
    ```bash
    # Generate snapshot (example using kubectl)
    kubectl get all,crds,nodes,storageclasses,webhookconfigurations,psp -A -o json > cluster.json
    
    # Run assessment
    k8s-upgrade-assess --source 1.27 --target 1.30 --snapshot cluster.json
    ```

3.  **Live Mode:** Connects to your live cluster via `kubectl`.
    ```bash
    k8s-upgrade-assess --source 1.27 --target 1.30 --live
    ```

Other useful CLI commands:

*   **Generate a sample cluster snapshot:**
    ```bash
    k8s-upgrade-assess generate-sample --source 1.27 --target 1.30 --output my_sample.json
    ```

*   **Launch the Web Dashboard:**
    ```bash
    k8s-upgrade-assess serve --port 5000
    ```

### Web Dashboard

1.  Start the dashboard server:
    ```bash
    k8s-upgrade-assess serve --port 5000
    ```
2.  Open your browser and navigate to `http://localhost:5000`.
3.  Configure your assessment (Source Version, Target Version, and Mode).
4.  Run the assessment and view the interactive results, Risk Matrix, and export options.

## Testing

The project includes a comprehensive suite of unit tests (55+ tests) covering all modules (Database, Collector, Engine, Scoring, and Reporter).

Run the tests using `pytest`:
```bash
python -m pytest tests/test_engine.py -v
```

## Architecture

*   **`k8s_database.py`**: Contains Kubernetes release history, API deprecation/removal timelines, behavioral changes, and a compatibility matrix for popular operators.
*   **`cluster_collector.py`**: Responsible for ingesting cluster state either from a live cluster via `kubectl` or from a static JSON snapshot.
*   **`assessment_engine.py`**: The core engine that executes the 17-step assessment process.
*   **`scoring_matrix.py`**: Calculates the Readiness Score, Confidence Score, and builds the 10-area Risk Matrix based on the assessment results.
*   **`reporter.py`**: Generates structured Markdown and JSON reports.
*   **`web_dashboard.py`**: The Flask-based interactive web interface.

## License

This project is licensed under the Apache 2.0 License.
