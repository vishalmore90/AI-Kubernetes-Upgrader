# ⚙️ AI-Kubernetes-Upgrader

> A comprehensive, automated, evidence-based Kubernetes **upgrade feasibility, compatibility, and risk assessment engine**.  
> Systematically analyses cluster resources, API deprecations, CRDs, controllers, webhooks, networking, storage, and security before you upgrade.

---

## 🧩 What Problem Does This Solve?

Upgrading a Kubernetes cluster is risky. A single deprecated API, an incompatible admission webhook, or an in-tree storage provisioner can break production workloads silently — sometimes only discovered after the upgrade is already applied.

**AI-Kubernetes-Upgrader eliminates that risk.** Before you run a single upgrade command, the tool performs a **17-step assessment** of your cluster and generates a clear, evidence-backed verdict:

- ✅ **APPROVED** — Safe to proceed
- ⚠️ **CONDITIONAL** — Proceed with specific remediations
- ❌ **NOT RECOMMENDED** — High-risk issues must be resolved first

---

## ✨ Features

| Assessment Area | What It Checks |
|---|---|
| **Cluster Info** | Version, node topology, control plane health |
| **Workload & CRD Inventory** | All workloads and Custom Resource Definitions |
| **API Deprecation Analysis** | APIs being removed in the target version (PSP, Dockershim, FlowSchema, etc.) |
| **Controller/Operator Compatibility** | cert-manager, ingress-nginx, cluster-autoscaler vs target version |
| **Admission Webhook Analysis** | Validating & mutating webhooks with failure policies that could block upgrades |
| **CNI & Networking** | Network plugin compatibility |
| **Storage Provisioners** | Detects deprecated in-tree provisioners |
| **Security Policies** | PSP removals and security posture |
| **Runtime Compatibility** | Container runtime version checks |
| **Node Resource Pressure** | CPU, memory, disk pressure across nodes |
| **Upgrade Simulation** | Models failure scenarios to predict post-upgrade breakage |
| **Scoring & Reporting** | 10-area Risk Matrix, Readiness Score (0–100), Confidence Score |

---

## 🏗️ Architecture

```
CLI / Web Dashboard
        │
        ▼
Assessment Engine (17-step pipeline)
        │
        ├── Cluster Collector  ──►  live kubectl  /  JSON snapshot
        │
        ├── K8s Database       ──►  API deprecation timelines
        │                           behavioral changes per version
        │                           operator compatibility matrix
        │
        ├── Scoring Matrix     ──►  Readiness Score (0–100)
        │                           Confidence Score
        │                           10-area Risk Matrix
        │
        └── Reporter           ──►  Markdown report
                                    JSON report
                                    Web Dashboard (Flask)
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| **Core Engine** | Python 3.x |
| **Web Dashboard** | Flask (dark-themed, interactive) |
| **CLI** | `k8s-upgrade-assess` (argparse) |
| **Cluster Integration** | `kubectl` (live mode) / JSON snapshots |
| **Testing** | pytest (55+ unit tests) |
| **Reporting** | Markdown + JSON |

---

## ⚡ Quick Start

### Installation

```bash
git clone https://github.com/vishalmore90/AI-Kubernetes-Upgrader.git
cd AI-Kubernetes-Upgrader
pip install -r requirements.txt

# Optional: install as a CLI tool
pip install -e .
```

### Run Modes

**Sample Mode** — uses a generated realistic cluster snapshot:
```bash
k8s-upgrade-assess --source 1.27 --target 1.30 --sample
```

**Snapshot Mode** — uses a JSON export of your cluster:
```bash
# Export your cluster state
kubectl get all,crds,nodes,storageclasses,webhookconfigurations,psp -A -o json > cluster.json

# Run assessment
k8s-upgrade-assess --source 1.27 --target 1.30 --snapshot cluster.json
```

**Live Mode** — connects directly to your running cluster:
```bash
k8s-upgrade-assess --source 1.27 --target 1.30 --live
```

### Launch the Web Dashboard

```bash
k8s-upgrade-assess serve --port 5000
```

Open `http://localhost:5000` to visualise the Risk Matrix, score gauges, and full assessment results interactively.

---

## 📊 Sample Output

```
══════════════════════════════════════════════════════
  KUBERNETES UPGRADE ASSESSMENT REPORT
  1.27 → 1.30
══════════════════════════════════════════════════════

  Readiness Score   : 72 / 100
  Confidence Score  : 88%
  Verdict           : ⚠️  CONDITIONAL

  Risk Matrix (10 areas):
  ┌─────────────────────────────┬────────┐
  │ API Deprecations            │ HIGH   │
  │ Controller Compatibility    │ MEDIUM │
  │ Admission Webhooks          │ LOW    │
  │ Storage Provisioners        │ MEDIUM │
  │ Security Policies           │ HIGH   │
  │ Networking                  │ LOW    │
  │ Runtime Compatibility       │ LOW    │
  │ Node Resource Pressure      │ LOW    │
  │ Workload Health             │ LOW    │
  │ CRD Compatibility           │ LOW    │
  └─────────────────────────────┴────────┘

  Action Required Before Upgrade:
  1. Migrate PodSecurityPolicy → Pod Security Admission
  2. Update ingress-nginx to v1.9.0+
  3. Replace in-tree AWS EBS provisioner with EBS CSI driver
══════════════════════════════════════════════════════
```

---

## 🧪 Testing

The project includes **55+ unit tests** covering all modules:

```bash
# Run all tests
pytest

# Run a specific module
python -m pytest tests/test_engine.py -v
```

Test coverage spans: Database, Cluster Collector, Assessment Engine, Scoring Matrix, and Reporter.

---

## 📁 Project Structure

```
AI-Kubernetes-Upgrader/
├── ai_k8s_upgrader/
│   ├── k8s_database.py        # K8s release history, API deprecation timelines
│   ├── cluster_collector.py   # Ingests live cluster or JSON snapshot
│   ├── assessment_engine.py   # 17-step assessment pipeline
│   ├── scoring_matrix.py      # Readiness Score, Risk Matrix
│   ├── reporter.py            # Markdown + JSON report generation
│   ├── web_dashboard.py       # Flask interactive dashboard
│   └── cli.py                 # CLI entry point
├── tests/
│   └── test_engine.py
├── requirements.txt
├── setup.py
└── README.md
```

---

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE) for details.
