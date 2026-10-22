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

## 📋 Snapshot Formats & Ingestion

AI-Kubernetes-Upgrader accepts JSON snapshots generated from Kubernetes clusters or CI/CD pipelines.

### Supported Snapshot Schemas

1. **Manifest-Level Resource Inventory (`all_resources`)**:
   ```json
   {
     "k8s_version": "1.21",
     "all_resources": [
       {
         "apiVersion": "networking.k8s.io/v1beta1",
         "kind": "Ingress",
         "namespace": "production",
         "name": "legacy-public-ingress"
       }
     ]
   }
   ```
2. **Workload Collections**:
   Supports `deployments`, `statefulsets`, `daemonsets`, `jobs`, `cronjobs`, `crds`, `storage_classes`, and `nodes`. Both Kubernetes-style (`apiVersion`, `kind`, `metadata.name`) and Python dataclass-style keys (`api_version`, `kind`, `name`) are automatically normalized and deduplicated.

### Observed Incompatibilities vs. Release Advisories

To eliminate false positives, the engine strictly separates findings:
- **Observed Incompatibilities (Verified Blockers)**: The cluster snapshot contains actual resource evidence matching a removed API or breaking change in the requested source-to-target version range.
- **Observed Deprecated APIs (Warning)**: Matching resource evidence exists, but the API is deprecated and not yet removed at the target release.
- **Upcoming Release Advisories (Informational)**: General Kubernetes release changes scheduled for future versions beyond your target release. Never presented as cluster blockers.
- **Data Completeness & Confidence Score**:
  - `VERIFIED_EMPTY`: Explicit clean inventory provided (`all_resources: []`). Confidence score: 80–100%.
  - `MISSING`: No inventory provided. Confidence is penalized (-20%) and an advisory is raised.
  - `COLLECTION_ERRORS`: Collector encountered permission or connectivity failures. Logged in assessment errors.

---

## 🔍 Live-Cluster Collection Capabilities & Limitations

- **What Live Collection CAN Prove**:
  - Node topology, kubelet versions, and container runtimes (e.g. Dockershim presence).
  - Controller and operator versions running in the cluster.
  - In-tree storage provisioners and admission webhooks with failure policies.
  - Resource usage pressures (CPU/Memory/Disk).
- **What Live Collection CANNOT Prove**:
  - Original YAML manifest versions: `kubectl get` returns resources converted into the API server's preferred or storage version. If a client deployed an object using a deprecated API version, the live API server may serve it under a newer version.
  - Recommendation: For 100% manifest fidelity, scan YAML manifests directly from your GitOps/CI repositories using snapshot format alongside cluster assessment.

---

## 🧪 Testing & Regression Verification

The project includes **93 automated tests** covering unit behavior and 10 end-to-end regression scenarios:

```bash
# Run all unit and regression tests
pytest -v

# Run the 10 Phase 4 regression scenarios specifically
pytest tests/test_regression.py -v
```

### Reproducing Regression Scenarios

The suite in `tests/test_regression.py` tests:
1. `test_scenario_1_single_legacy_ingress`: Single legacy Ingress (v1beta1) in 1.21→1.22. Verifies exactly 1 finding, migration to `networking.k8s.io/v1`, and 0 manufactured webhook/CRD errors.
2. `test_scenario_2_clean_api_inventory`: Clean cluster in 1.21→1.22. Verifies 0 false API removal findings.
3. `test_scenario_3_modern_ingress_api`: Ingress using `networking.k8s.io/v1`. Verifies no false removal.
4. `test_scenario_4_docker_runtime_compatibility`: 1.23→1.24 with Docker and containerd nodes. Verifies dockershim removal flag on Docker node only and CRI remediation.
5. `test_scenario_5_hpa_api_removal`: 1.25→1.26 with `autoscaling/v2beta2` HPA. Verifies detection, recommendation of `autoscaling/v2`, and no duplicate critical blockers.
6. `test_scenario_6_psp_removal`: 1.24→1.25 comparison between PSP present vs PSP absent.
7. `test_scenario_7_flowschema_removal`: 1.28→1.29 FlowSchema/PriorityLevelConfiguration v1beta2 removal distinguished from 1.32 v1beta3 removal.
8. `test_scenario_8_missing_versus_empty_inventory`: Verified clean vs missing inventory vs collection errors.
9. `test_scenario_9_web_dashboard_upload`: Web route `/api/assess` multipart upload, valid/invalid handling, and export streaming.
10. `test_scenario_10_report_and_score_consistency`: Deterministic scoring, non-duplication in Markdown and JSON.

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
│   ├── web_dashboard.py       # Flask interactive dashboard (Render-ready WSGI)
│   └── cli.py                 # CLI entry point
├── tests/
│   ├── test_engine.py         # Engine, database, and scoring tests
│   └── test_web_dashboard.py  # Web dashboard, security, and validation tests
├── requirements.txt
├── setup.py
└── README.md
```

---

## 🚀 Deploying to Render (Free Public Demo)

The web dashboard is production-ready for deployment on Render's free tier as a Python Web Service.

### Render Configuration

| Setting | Value |
|---|---|
| **Environment** | `Python` (3.12 recommended) |
| **Region** | Any (e.g., Oregon, Frankfurt) |
| **Branch** | `main` |
| **Build Command** | `pip install -r requirements.txt && pip install -e .` |
| **Start Command** | `gunicorn --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120 ai_k8s_upgrader.web_dashboard:app` |

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `ALLOW_LIVE_CLUSTER` | `false` | Disables live `kubectl` access for public security. Sample mode and snapshot JSON uploads remain fully functional. |
| `RATE_LIMIT_REQUESTS` | `30` | Maximum assessment requests per client IP per window. |
| `RATE_LIMIT_WINDOW` | `60` | Rate limit window in seconds (default: 60s). |
| `MAX_UPLOAD_SIZE` | `5242880` | Maximum upload size in bytes (5 MB). |

### Public Demo Security Architecture

- **No Cluster Credentials**: The demo operates in zero-credential mode. No kubeconfig or cluster secrets are embedded or required.
- **Safe Sample Mode**: Evaluates realistic pre-computed cluster topologies without outbound cluster connections.
- **Snapshot Validation**: Uploaded snapshots are validated for JSON integrity, schema structure, and size limits (5 MB max) before parsing.
- **Leak-Free Resource Cleanup**: Temporary files are guaranteed to be unlinked even upon parsing failures; exported reports are streamed directly in-memory via `io.BytesIO`.
- **Stack Trace Protection**: Public visitors receive clean, generic error messages. Diagnostic stack traces are logged server-side only.
- **Rate Limiting**: Thread-safe in-memory sliding-window limiter prevents request floods on free tier compute instances.

---

## 📄 License

Apache 2.0 — see [LICENSE](LICENSE) for details.
