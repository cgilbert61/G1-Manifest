<p align="center">
  <img src="assets/g1_logo.jpg" alt="G1 Logo" width="110" />
</p>

# G1-Manifest — by G1163RT Security Labs

[![CI](https://github.com/cgilbert61/G1-Manifest/actions/workflows/ci.yml/badge.svg)](https://github.com/cgilbert61/G1-Manifest/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-informational.svg)](pyproject.toml)
[![Schema](https://img.shields.io/badge/DSSEv1-Ed25519%20v1.0-blue.svg)](schemas/dsse-envelope.v1.0.schema.json)
[![Latency](https://img.shields.io/badge/verify%20p99-%3C%205.0%20ms-success.svg)](docs/benchmarks-sizing.md)
[![GovReady-Q](https://img.shields.io/badge/NIST%20SP%20800--53-Assessed-success.svg)](docs/govready_compliance_assessment_report.md)
[![Federal DevSecOps](https://img.shields.io/badge/Federal%20DevSecOps-Verified-success.svg)](reports/devsecops_scan_report.md)
[![Community Profile](https://img.shields.io/badge/community%20standards-100%25%20green-success.svg)](CONTRIBUTING.md)

**Learned, signed, expiring dependency graphs for an estate — evidence over declaration (`v0.1.0`) — G1163RT Security Labs.**

Every containment and shielding system lives or dies on one question: *what does this service actually depend on?* Lists written by people rot — the forgotten 2 a.m. license server or partner endpoint gets cut as faithfully as an attacker's callback during an incident. **G1-Manifest** is a standalone evidence-driven dependency graph producer and verifier that composes with **G1-Docket** and **G1-Warrant** strictly through signed, expiring artifacts:

1. **Telemetry Observation (`estate_graph/sources/`)** — Read-only ingest of AWS VPC Flow Logs, Cilium Hubble JSONL, Warrant-shaped declared estate models, OpenLineage derivations, Windows Uninstall Registry, `pip` metadata, and live loaded process modules.
2. **Deterministic Aggregation (`estate_graph/aggregate.py`)** — Merges observations into a canonical dependency graph where every edge carries empirical evidence (`flow_count`, `first_seen`, `last_seen`, `sources`). Rare flows are kept and flagged `low_frequency`, never averaged away.
3. **Reconciliation (`estate_graph/reconcile.py`, `host_reconcile.py`)** — Diffs observed evidence against declared claims into three buckets (`confirmed`, `observed_undeclared`, `declared_unobserved`). Nothing observed ever auto-promotes: observation proposes, a human signature disposes.
4. **DSSEv1 Ed25519 Signing & Fail-Closed Verification (`estate_graph/sign.py`, `verify.py`)** — Emits expiring DSSE envelopes (`application/vnd.g1163rt.estate-graph+json`, default TTL 24h). Consumers fail closed on bad signatures, unsupported schema versions, or expiry, and gate surgical shields via `arming_gate()`.
5. **Offline Witness Renderer & Workstation Dashboard (`estate_graph/render.py`, `serve.py`)** — Renders deterministic, offline-safe HTML witness pages with static evidence tables and layered SVG graphs, plus a lightweight HTTP viewer with 1-click Windows (`.cmd`) and macOS (`.command`) workstation scanners.

---

## Visual Demonstration & Console Walkthrough

### 1. G1-Manifest Dashboard & 1-Click Workstation Scanners (`:8088`)
> Upload telemetry files to run estate scans, verify/render existing graphs or DSSE envelopes, manage Ed25519 signing keys, or download 1-click Windows/macOS workstation scanners that automatically ingest and open signed witness graphs in the browser.

### 2. Standalone HTML Witness Page (`/demo_view.html`)
> Every witness page displays its cryptographic proof state on its face (**VERIFIED**, **EXPIRED**, or **UNSIGNED**), highlights undeclared findings in red, renders deterministic left-to-right layered SVG topology, and embeds full static evidence tables that require no JavaScript.

---

## Repository Layout

- `estate_graph/` — Core Python package (`model.py`, `aggregate.py`, `reconcile.py`, `host_reconcile.py`, `sign.py`, `verify.py`, `render.py`, `serve.py`, `cli.py`, `sources/`, `assets/`)
- `schemas/` — JSON Schemas (Draft 2020-12) for `DependencyGraph` and DSSEv1 envelopes + `CHANGELOG.md`
- `conformance/` — Consumer Conformance Test Suite (`test_conformance.py`)
- `tests/` — Deterministic unit, integration, rendering, host-scanning, and hardening test suites
- `benchmarks/` — Empirical latency & throughput benchmark (`bench_graph.py`)
- `examples/` — Bundled synthetic estate (`demo_estate/`), `run_demo.py`, `consumer_sketch.py`, `pc_self_graph.py`, and `verify_docker_stack.py`
- `docs/` — Architecture, CLI Reference, Python SDK Guide, Benchmarks & Sizing, GovReady-Q & Federal DevSecOps reports
- `deploy/` & `charts/` & `k8s/` — Production Helm charts and Kubernetes manifests (Namespace, ConfigMap, Deployment, Service, HPA, NetworkPolicy)
- `terraform/` — Multi-cloud IaC foundation modules (`aws/`, `azure/`, `gcp/`) for KMS signing keys and WORM artifact storage
- `reports/` — Empirical verification scorecards (`verification_scorecard.json`) and compliance harness output (`compliance_report.json`)
- `scripts/` — Verification runner (`run_all_verifications.py`), Compliance Harness (`compliance_harness.py`), Mode Checker (`check_mode.py`), Interactive Operator Menu (`interactive_menu.py`)
- `.github/` — GitHub Actions CI/CD workflow (`ci.yml`), Issue Templates, and Pull Request Template
- **Community Standards & Policies** — [Contributing Guidelines](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), [Security Policy](SECURITY.md), and [Apache-2.0 License](LICENSE)

---

## Core Domain Schema (`DependencyGraph` & DSSE Envelope)

| Field | Type | Layer / Scope | Description |
| :--- | :--- | :--- | :--- |
| `graph_id` | `string` | Graph | Stable identifier (e.g. `estate-graph`, `host-graph:<hostname>`) |
| `version` | `string` | Graph | Schema version (`"1.0"`); consumers fail closed on unknown versions |
| `issued_at` / `expires_at` | `int` (UTC epoch) | Graph | Validity window; expired means expired |
| `nodes[]` | `ServiceNode[]` | Graph | `id`, `kind` (`service`, `external`, `dataset`, `package`, `process`, `library`, `system-library`), `substrate`, `labels` |
| `edges[]` | `Edge[]` | `network` \| `lineage` \| `package` \| `observed-load` | Directed edge with `port`, `protocol`, `low_frequency`, and `evidence` (`flow_count`, `first_seen`, `last_seen`, `sources`) |
| `payloadType` | `string` | DSSE Envelope | `application/vnd.g1163rt.estate-graph+json` |
| `signatures[]` | `Signature[]` | DSSE Envelope | Ed25519 signature over DSSEv1 PAE with 16-char SHA-256 `keyid` |

---

## Quickstart (Local Evaluation, Standalone CLI/SDK & Demo)

### 0. Install Dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[host]" pytest
```

### Standalone CLI & Consumer SDK (`g1-manifest` / `estate-graph`)

> [!IMPORTANT]
> **Minimal Dependencies**: Runtime verification and signing require only `cryptography>=42` (everything else is Python stdlib; `psutil>=5.9` is optional for live host module observation).

```bash
g1-manifest --help
g1-manifest --check-mode
```

### 1. Run the Reproducible End-to-End Demo

```bash
python -m examples.run_demo
```

### 2. Run the Full Test & Conformance Suite

```bash
pytest -v
pytest -v conformance/
```

### 3. Exercise the Operator CLI

```bash
g1-manifest keygen --out-dir keys/
g1-manifest build --declared examples/demo_estate/declared_model.json \
  --flowlogs examples/demo_estate/vpc_flow_logs.txt \
  --hubble examples/demo_estate/hubble.jsonl \
  --lineage examples/demo_estate/lineage.json \
  --out graph.json
g1-manifest sign --graph graph.json --key keys/private.pem --ttl 86400 --out envelope.json
g1-manifest verify --envelope envelope.json --pub keys/public.pem
g1-manifest render --envelope envelope.json --pub keys/public.pem \
  --declared examples/demo_estate/declared_model.json --out view.html
```

### 4. Interactive Operator & Auditor Control Menu

```bash
python scripts/interactive_menu.py
```

---

## One-Click Automated Docker Installers

- **Windows**: `install.bat`
- **Linux / macOS**: `chmod +x install.sh && ./install.sh`

Or directly with Docker Compose:

```bash
docker compose up -d --build
```

---

## Troubleshooting & Automated Health Polling (PowerShell)

```powershell
1..30 | ForEach-Object {
  try {
    $r = Invoke-WebRequest -Uri http://127.0.0.1:8088/health -UseBasicParsing -TimeoutSec 2
    if ($r.StatusCode -eq 200) { Write-Host "Healthy: $($r.Content)"; break }
  } catch { Start-Sleep -Seconds 1 }
}
```

---

## Service Architecture & HTTP Endpoints

| Port | Service Component | UI / Endpoint | Key Role & Scope |
| :--- | :--- | :--- | :--- |
| `8088` (host) -> `8080` (container) | `G1-Manifest` Witness Server | `http://127.0.0.1:8088/` | Interactive dashboard, estate scan upload, 1-click Windows/macOS scanners, and standalone HTML witness views |

```text
G1-Manifest HTTP Surface (:8080)
├── GET  /                           Dashboard & Available Witness Pages
├── GET  /health                     Container health check ({"status":"ok","views":N})
├── GET  /<view>.html                Standalone offline-safe HTML witness page
├── GET  /api/views                  JSON metadata list of rendered witness pages
├── GET  /api/keys/public.pem        Download active Ed25519 verification public key
├── GET  /api/agent/windows.cmd      1-click Windows workstation scanner (no Python)
├── GET  /api/agent/macos.command    1-click macOS workstation scanner
├── POST /api/scan/estate            Ingest telemetry, reconcile, sign, and render
├── POST /api/scan/host              Run container host scan
├── POST /api/scan/demo              Re-run bundled demo estate scan
├── POST /api/ingest/host            Ingest Windows/macOS workstation snapshot
├── POST /api/render                 Verify & render uploaded graph.json or envelope.json
└── POST /api/keys/rotate            Rotate server Ed25519 keypair
```

---

## Ecosystem Integrations & Third-Party Open Source Software

G1-Manifest integrates with **G1-Docket** and **G1-Warrant** exclusively through verified DSSEv1 artifacts (`application/vnd.g1163rt.estate-graph+json`).

| Package / Project | Version | Upstream License | Project URL / Source | Primary Role |
| :--- | :--- | :--- | :--- | :--- |
| `cryptography` | `>=42` | Apache-2.0 / BSD-3-Clause | https://github.com/pyca/cryptography | Ed25519 key generation, DSSE signing & verification |
| `psutil` (optional) | `>=5.9` | BSD-3-Clause | https://github.com/giampaolo/psutil | Live process loaded-module observation (`scan-host`) |
| `pytest` (dev) | `>=8` | MIT | https://github.com/pytest-dev/pytest | Unit, conformance, and hardening test runner |

---

## Observability, Security Scans & Verification

- **Health Probe:** `GET /health` (`200 OK` JSON) wired into `Dockerfile` `HEALTHCHECK` and `k8s/deployment.yaml` liveness/readiness probes.
- **Empirical Verification Scorecard:** Run `python scripts/run_all_verifications.py` to execute unit/integration tests, consumer conformance, demo, compliance harness, and latency benchmarks into [`reports/verification_scorecard.json`](reports/verification_scorecard.json).
- **Latest Empirical DevSecOps Scan ([Full Report](reports/devsecops_scan_report.md)):**

| Scanner | Scope | Status | Empirical Result |
| :--- | :--- | :--- | :--- |
| **Gitleaks** | Git history & repository secrets | `EXECUTED` | **0 leaks** |
| **Semgrep** | Python SAST (`.semgrep.yml` + `p/python`, 154 rules) | `EXECUTED` | **0 findings** |
| **Checkov** | Dockerfile, Helm, Kubernetes, Terraform | `EXECUTED` | **188 passed, 0 failed** (`70/70` Dockerfile, `91/91` K8s, `25/25` Terraform, `2/2` Helm) |
| **Trivy Image** | `g1-manifest:latest` (Alpine 3.24) OS + Python CVEs & secrets | `EXECUTED` | **0 CRITICAL / 0 HIGH**, **0 Python CVEs**, **0 secrets** (5 MEDIUM, 1 LOW) |
| **Trivy FS** | Repository IaC misconfigurations, vulns & secrets | `EXECUTED` | **0 CRITICAL / 0 HIGH**, **0 vulns**, **0 secrets** (3 MEDIUM) |
| **oss-scanner** | Standalone OSS/license scanner | `SKIPPED` | Not installed locally |

---

## Community & Security Standards

- **[Contributing Guidelines](CONTRIBUTING.md)**
- **[Code of Conduct](CODE_OF_CONDUCT.md)**
- **[Security Policy](SECURITY.md)**
- **[Issue Templates](.github/ISSUE_TEMPLATE/)**
- **[Pull Request Template](.github/pull_request_template.md)**
- **[Apache-2.0 License](LICENSE)**
