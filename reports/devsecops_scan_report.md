# G1-Manifest Empirical DevSecOps Security Scan Report

- **Generated:** `2026-11-26T16:42:41Z`
- **Repository:** `D:\Manifest\g1-estate-graph-prototype\g1-estate-graph`
- **Docker Image:** `g1-manifest:latest`

## Scanner Execution Matrix

| Scanner | Scope | Status | Summary |
| :--- | :--- | :--- | :--- |
| **Gitleaks** (`zricethezav/gitleaks:latest`) | Git history & repo secrets | `EXECUTED` | 0 leaks found |
| **Semgrep** (`returntocorp/semgrep:latest`) | Python SAST (`.semgrep.yml` + `p/python`, 154 rules) | `EXECUTED` | 0 findings |
| **Checkov** (`bridgecrew/checkov:latest`) | Dockerfile, Kubernetes, Helm, Terraform | `EXECUTED` | 5 failed checks across 4 frameworks (Dockerfile: 0 failed) |
| **Trivy Image** (`aquasec/trivy:latest`) | `g1-manifest:latest` OS + Python CVEs & secrets | `EXECUTED` | CRITICAL=0, HIGH=53, MEDIUM=84, LOW=78; secrets=0 |
| **Trivy FS** (`aquasec/trivy:latest`) | Repo IaC misconfigs, vulns & secrets | `EXECUTED` | CRITICAL=0, HIGH=0, MEDIUM=3, LOW=2; secrets=0 |
| **oss-scanner** | License/OSS scanner | `SKIPPED` | Not installed locally on PATH or as a standalone image |

## High & Critical Container CVEs (53)

| Severity | CVE | Package | Installed | Fixed | Target |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `HIGH` | CVE-2026-76642 | `bsdutils` | `1:2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78408 | `bsdutils` | `1:2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78409 | `bsdutils` | `1:2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78410 | `bsdutils` | `1:2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-54369 | `libacl1` | `2.3.2-2+b1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-76642 | `libblkid1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78408 | `libblkid1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78409 | `libblkid1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78410 | `libblkid1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-76642 | `liblastlog2-2` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78408 | `liblastlog2-2` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78409 | `liblastlog2-2` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78410 | `liblastlog2-2` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-76642 | `libmount1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78408 | `libmount1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78409 | `libmount1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78410 | `libmount1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2025-69720 | `libncursesw6` | `6.5+20250216-2` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-76642 | `libsmartcols1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78408 | `libsmartcols1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78409 | `libsmartcols1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78410 | `libsmartcols1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-119373 | `libsqlite3-0` | `3.46.1-7+deb13u2` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-119374 | `libsqlite3-0` | `3.46.1-7+deb13u2` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-119379 | `libsqlite3-0` | `3.46.1-7+deb13u2` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-107494 | `libssl3t64` | `3.5.9-1~deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-124709 | `libssl3t64` | `3.5.9-1~deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-16742 | `libsystemd0` | `257.13-1~deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2025-69720 | `libtinfo6` | `6.5+20250216-2` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-16742 | `libudev1` | `257.13-1~deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-76642 | `libuuid1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78408 | `libuuid1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78409 | `libuuid1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78410 | `libuuid1` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-76642 | `login` | `1:4.16.0-2+really2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78408 | `login` | `1:4.16.0-2+really2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78409 | `login` | `1:4.16.0-2+really2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78410 | `login` | `1:4.16.0-2+really2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-76642 | `mount` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78408 | `mount` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78409 | `mount` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78410 | `mount` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2025-69720 | `ncurses-base` | `6.5+20250216-2` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2025-69720 | `ncurses-bin` | `6.5+20250216-2` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-107494 | `openssl` | `3.5.9-1~deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-124709 | `openssl` | `3.5.9-1~deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-107494 | `openssl-provider-legacy` | `3.5.9-1~deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-124709 | `openssl-provider-legacy` | `3.5.9-1~deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-9538 | `perl-base` | `5.40.1-6+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-76642 | `util-linux` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78408 | `util-linux` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78409 | `util-linux` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |
| `HIGH` | CVE-2026-78410 | `util-linux` | `2.41.5-0+deb13u1` | `unfixed` | `g1-manifest:latest (debian 13.8)` |

## High & Critical IaC Misconfigurations — Trivy (0)

None.

## Checkov Failed IaC Checks (5)

| Framework | Check ID | File | Check Name |
| :--- | :--- | :--- | :--- |
| `kubernetes` | `CKV_K8S_43` | `/k8s/deployment.yaml` | Image should use digest |
| `terraform` | `CKV_GCP_62` | `/terraform/gcp/main.tf` | Bucket should log access |
| `terraform` | `CKV_AWS_144` | `/terraform/aws/main.tf` | Ensure that S3 bucket has cross-region replication enabled |
| `terraform` | `CKV2_AWS_62` | `/terraform/aws/main.tf` | Ensure S3 buckets should have event notifications enabled |
| `terraform` | `CKV_AWS_18` | `/terraform/aws/main.tf` | Ensure the S3 bucket has access logging enabled |
