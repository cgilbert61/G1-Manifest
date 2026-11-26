# NIST SP 800-53 / GovReady-Q Alignment Report (G1-Manifest)

This document distinguishes **empirically executed automated checks** (run via `python scripts/compliance_harness.py` -> `reports/compliance_report.json`) from **narrative control mappings** that require organizational SSP review.

| Control | Category | Status | Evidence |
| :--- | :--- | :--- | :--- |
| `SC-12 / SC-13` | Cryptographic Key & DSSE Ed25519 Signing | Executed (`scripts/compliance_harness.py`) | `G1M-CRYPTO-01` |
| `CM-6 / AC-6` | Non-Root Container & Least Privilege | Executed (`scripts/compliance_harness.py`) | `G1M-CONT-01` |
| `SI-10` | JSON Schema Draft 2020-12 Input Validation | Executed (`scripts/compliance_harness.py`) | `G1M-SCHEMA-01` |
| `CM-8` | System Component Inventory | Narrative Mapping (`UNVERIFIED` pending live SSP) | Estate + Host inventory layers |
| `AU-9` | Protection of Audit Artifacts | Narrative Mapping (`UNVERIFIED` pending cloud deploy) | `terraform/` WORM storage modules |
