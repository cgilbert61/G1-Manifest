# G1-Manifest Downstream Export Run Receipts (`docs/EXPORT-RUNS.md`)

Empirical receipts for all 13 downstream destinations implemented on the single shared export path (`estate_graph/destinations/core.py`). Every row carries its honest evidence tier: **`live-tested`** (real HTTP socket receiver or live database), **`fixture-tested`** (documented vendor payload format verified against fake/recorded HTTP endpoint), or **`not built`**.

**Test Run Command:** `python -m pytest -v tests/test_destinations.py` (Python 3.13.9, 2026-11-27)

---

## Per-Destination Export Matrix

| Group | Downstream System | Adapter ID | Send Modes | Evidence Tier | Verification Test |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CMDB / ITSM** | ServiceNow CMDB (IRE / CSDM) | `servicenow` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[servicenow]` |
| **CMDB / ITSM** | BMC Helix CMDB | `bmc-helix` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[bmc-helix]` |
| **CMDB / ITSM** | Jira Service Management Assets | `jsm-assets` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[jsm-assets]` |
| **CMDB / ITSM** | Ivanti Neurons for ITSM | `ivanti-itsm` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[ivanti-itsm]` |
| **CMDB / ITSM** | Device42 | `device42` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[device42]` |
| **CMDB / ITSM** | Freshservice | `freshservice` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[freshservice]` |
| **Network & Observability** | Cisco Catalyst Center | `cisco-catalyst` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[cisco-catalyst]` |
| **Network & Observability** | Datadog | `datadog` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[datadog]` |
| **Network & Observability** | Dynatrace | `dynatrace` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[dynatrace]` |
| **Network & Observability** | SolarWinds NPM | `solarwinds-npm` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[solarwinds-npm]` |
| **Graph & Catalog** | Neo4j (Cypher HTTP) | `neo4j` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[neo4j]` |
| **Graph & Catalog** | Backstage Service Catalog | `backstage` | `full`, `delta`, `findings_only` | `fixture-tested` | `test_all_13_downstream_adapters_preserve_envelope_id_and_expiry[backstage]` |
| **Graph & Catalog** | Generic REST / Webhook | `webhook` | `full`, `delta`, `findings_only` | `live-tested` (loopback HTTP) | `test_ui_end_to_end_destination_config_send_and_audit_log` |

---

## Proof Run Receipts (Item 4)

1. **Negative Proof — Expired & Tampered Graphs Refused (`test_negative_proof_expired_and_tampered_graphs_never_export`):**
   - Attempting to export an expired envelope (`now = issued_at + ttl`) raises `ExpiredGraph` with **0 outbound HTTP calls**.
   - Attempting to export a tampered envelope raises `BadSignature` with **0 outbound HTTP calls**.
2. **Delta & Findings-Only Proof (`test_export_modes_full_delta_and_findings_only`):**
   - First `delta` send delivers all 9 demo edges; second `delta` send delivers `0` unchanged nodes/edges/findings; adding `new-svc` + 1 edge and bumping `sequence=2` delivers strictly `[new-svc]` + 1 new edge.
   - `findings_only` delivers reconciliation findings with `0` nodes and `0` edges.
3. **Failure Isolation & Credential Reference Proof (`test_per_destination_failure_isolation_and_credential_ref_enforcement`):**
   - A failing destination (`ConnectionError`) records `ok=False` while a healthy destination in the same run completes with `ok=True`.
   - Raw secret fields (`password`, `api_key`, `token`, `secret`) are rejected by `DestinationConfigStore` — only `credential_ref` (environment variable name) is accepted.
4. **UI End-to-End Proof (`test_ui_end_to_end_destination_config_send_and_audit_log`):**
   - Configured `live-webhook-1` through `POST /api/destinations`, triggered `POST /api/destinations/send`, verified the real loopback HTTP receiver received the signed graph carrying `envelope_id` and `expires_at`, and verified the `create` configuration record in `GET /api/destinations/audit`.
