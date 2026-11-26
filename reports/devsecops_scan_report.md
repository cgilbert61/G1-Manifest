# G1-Manifest Empirical DevSecOps Security Scan Report

- **Generated:** `2026-11-26T17:11:37Z`
- **Repository:** `D:\Manifest\g1-estate-graph-prototype\g1-estate-graph`
- **Docker Image:** `g1-manifest:latest`

## Scanner Execution Matrix

| Scanner | Scope | Status | Summary |
| :--- | :--- | :--- | :--- |
| **Gitleaks** (`zricethezav/gitleaks:latest`) | Git history & repo secrets | `EXECUTED` | 0 leaks found |
| **Semgrep** (`returntocorp/semgrep:latest`) | Python SAST (`.semgrep.yml` + `p/python`, 154 rules) | `EXECUTED` | 0 findings |
| **Checkov** (`bridgecrew/checkov:latest`) | Dockerfile, Kubernetes, Helm, Terraform | `EXECUTED` | 0 failed checks across 4 frameworks (Dockerfile: 0 failed) |
| **Trivy Image** (`aquasec/trivy:latest`) | `g1-manifest:latest` OS + Python CVEs & secrets | `EXECUTED` | CRITICAL=0, HIGH=0, MEDIUM=5, LOW=1; secrets=0 |
| **Trivy FS** (`aquasec/trivy:latest`) | Repo IaC misconfigs, vulns & secrets | `EXECUTED` | CRITICAL=0, HIGH=0, MEDIUM=3, LOW=0; secrets=0 |
| **oss-scanner** | License/OSS scanner | `SKIPPED` | Not installed locally on PATH or as a standalone image |

## High & Critical Container CVEs (0)

None.

## High & Critical IaC Misconfigurations — Trivy (0)

None.

## Checkov Failed IaC Checks (0)

None.
