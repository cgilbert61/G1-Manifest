# Federal DevSecOps Verification Report (G1-Manifest)

G1-Manifest includes repository-level DevSecOps configurations aligned with DoD/Federal DevSecOps baselines:

- **Secrets Scanning:** `.gitleaks.toml`
- **SAST:** `.semgrep.yml`
- **IaC Scanning:** `.checkov.yaml` (Dockerfile, Kubernetes, Helm, Terraform)
- **Container & Dependency SCA:** `trivy.yaml`
- **CI Pipeline:** `.github/workflows/ci.yml` (Python 3.11–3.13 matrix, conformance suite, isolated wheel check, Docker build)
- **Empirical Verification Scorecard:** Generated via `python scripts/run_all_verifications.py` -> `reports/verification_scorecard.json`
