# G1-Manifest — Current Empirical DevSecOps & Verification Report

- **Repository:** [`cgilbert61/G1-Manifest`](https://github.com/cgilbert61/G1-Manifest)
- **Container Image:** `g1-manifest:latest` (Alpine 3.24.4, `sha256:b52e7bb8b37369dc8067d69254c14124bb4ef3479de32af19d21240a3309d195`)
- **Generated:** `2026-11-26T17:11:37Z`
- **GitHub Actions CI:** `PASS` (Run `45865683156` — Python 3.11 / 3.12 / 3.13 matrix, conformance, wheel check, Docker build)

---

## 1. Security Scanner Results

| Scanner | Scope | Status | Empirical Result |
| :--- | :--- | :--- | :--- |
| **Gitleaks** (`zricethezav/gitleaks:latest`) | Git history & repository secrets (4 commits, 2.74 MB) | `EXECUTED` | **0 leaks** |
| **Semgrep** (`returntocorp/semgrep:latest`) | Python SAST (`.semgrep.yml` + `p/python`, 154 rules across 29 files) | `EXECUTED` | **0 findings** |
| **Checkov** (`bridgecrew/checkov:latest`) | Dockerfile, Kubernetes, Terraform, Helm | `EXECUTED` | **188 passed, 0 failed** (`70/70` Dockerfile, `91/91` K8s, `25/25` Terraform, `2/2` Helm) |
| **Trivy Image** (`aquasec/trivy:latest`) | `g1-manifest:latest` OS + Python CVEs & secrets | `EXECUTED` | **0 CRITICAL, 0 HIGH**, 5 MEDIUM, 1 LOW; **0 Python CVEs**; **0 secrets** |
| **Trivy FS** (`aquasec/trivy:latest`) | Repository IaC misconfigurations, vulns & secrets | `EXECUTED` | **0 CRITICAL, 0 HIGH, 0 LOW**, 3 MEDIUM; **0 vulns**; **0 secrets** |
| **oss-scanner** | Standalone OSS/license scanner | `SKIPPED` | Not installed locally on PATH or as a standalone image |

### High & Critical Findings
- **Container CVEs (HIGH / CRITICAL):** `0`
- **IaC Misconfigurations — Trivy (HIGH / CRITICAL):** `0`
- **Checkov Failed IaC Checks:** `0`

---

## 2. Functional & Conformance Verification

| Suite | Status | Empirical Result |
| :--- | :--- | :--- |
| **Unit & Integration Tests** (`pytest tests/`) | `PASS` | `63 passed, 1 skipped` (Windows-only non-Windows skip) |
| **Consumer Conformance Suite** (`pytest conformance/`) | `PASS` | `5 passed` (DSSE round-trip, expiry, tamper, schema version, arming gate) |
| **End-to-End Demo** (`python -m examples.run_demo`) | `PASS` | `checkout-api: DENY` (undeclared egress), `payments-api: ALLOW` |
| **Compliance Harness** (`scripts/compliance_harness.py`) | `PASS` | `3/3 executed checks PASS` (`G1M-CRYPTO-01`, `G1M-CONT-01`, `G1M-SCHEMA-01`) |
| **Live Docker Stack** (`examples/verify_docker_stack.py`) | `PASS` | `http://127.0.0.1:8088` healthy (`views=3`, branded index, verified demo, public key) |

---

## 3. Empirical Latency Benchmarks (`25` iterations)

| Operation | Samples | p50 (ms) | p95 (ms) | p99 (ms) |
| :--- | ---: | ---: | ---: | ---: |
| `build` (parse + aggregate) | 25 | 1.060 | 1.190 | 1.210 |
| `reconcile` (learned vs declared) | 25 | 0.026 | 0.031 | 0.038 |
| `sign` (Ed25519 DSSEv1) | 25 | 0.248 | 0.347 | 0.435 |
| `verify` (Ed25519 DSSEv1 fail-closed) | 25 | 0.283 | 0.329 | 0.349 |
| `render` (deterministic layered HTML) | 25 | 0.757 | 1.120 | 8.128 |
