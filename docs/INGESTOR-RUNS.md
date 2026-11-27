# G1-Manifest Ingestor Run Receipts (`docs/INGESTOR-RUNS.md`)

Empirical receipts for every ingestor implemented in Items 1–6. Every row is labeled honestly: **`live-local`** (real loopback UDP/HTTP socket run on this host), **`fixture-only`** (deterministic fixture + fake/recorded endpoint test), or **`live-estate`** (real external cloud/vendor tenant — none claimed until executed against a live tenant).

**Test Run Command:** `python -m pytest -v tests/test_ingestors.py` (`10 passed` on Python 3.13.9, 2026-11-27)

---

## Per-Ingestor Receipts

| Ingestor (`ORIGIN`) | Mode | Exact Verification Test / Command | Records In | Observations Out | Dropped (Reasons) | Status |
| :--- | :--- | :--- | ---: | ---: | :--- | :--- |
| **Skeleton** (`skeleton-example`) | `fixture-only` | `pytest tests/test_ingestors.py -k test_checkpoint_store_roundtrip_and_skeleton` | 4 | 1 | 3 (`non_accepted_action`, `self_traffic`, `non_dict_record`) | `PASS` |
| **NetFlow v9 / IPFIX** (`netflow-v9`, `ipfix`) | `live-local` + `fixture-only` | `pytest tests/test_ingestors.py -k "netflow or live_continuous"` (real loopback UDP socket) | 6 | 3 | 3 (`dropped_forwarding_status`, `truncated_header`, `unsupported_version`) | `PASS` |
| **sFlow v5** (`sflow`) | `live-local` + `fixture-only` | `pytest tests/test_ingestors.py -k "sflow or live_continuous"` (real loopback UDP socket; `sampling_rate` preserved) | 3 | 1 | 1 (`truncated_sflow_header`) | `PASS` |
| **AWS VPC S3** (`aws-vpc-s3`) | `fixture-only` | `pytest tests/test_ingestors.py -k test_aws_s3_and_cloudwatch` (gzipped log + re-pull dedupe) | 2 | 1 | 1 (`already_checkpointed` on re-pull) | `PASS` |
| **AWS VPC CloudWatch** (`aws-vpc-cwlogs`) | `fixture-only` | `pytest tests/test_ingestors.py -k test_aws_s3_and_cloudwatch` (`eventId` dedupe) | 1 | 1 | 1 (`duplicate_event_id` on re-pull) | `PASS` |
| **Azure NSG Flow v2** (`azure-nsg-flow`) | `fixture-only` | `pytest tests/test_ingestors.py -k test_azure_nsg_and_gcp_vpc` (Allowed vs. Denied + blob checkpoint) | 2 | 1 | 1 (`denied_flow`) | `PASS` |
| **GCP VPC Flow** (`gcp-vpc-flow`) | `fixture-only` | `pytest tests/test_ingestors.py -k test_azure_nsg_and_gcp_vpc` (GCS generation checkpoint) | 1 | 1 | 0 (1 `already_checkpointed` on re-pull) | `PASS` |
| **Hubble Live Stream** (`hubble`) | `fixture-only` | `pytest tests/test_ingestors.py -k test_azure_nsg_and_gcp_vpc` (reuses `parse_hubble` app-label/pod-base identity) | 1 | 1 | 0 | `PASS` |
| **OpenLineage HTTP** (`openlineage`) | `live-local` | `pytest tests/test_ingestors.py -k test_live_continuous_runner_multi_source_end_to_end` (real loopback HTTP `POST /api/v1/lineage`) | 1 | 1 lineage edge | 0 | `PASS` |
| **Cisco Catalyst + SNA** (`cisco-catalyst`, `cisco-sna`) | `fixture-only` | `pytest tests/test_ingestors.py -k test_cisco_catalyst_inventory_and_sna_flows` (REST JSON; NetFlow/IPFIX already covers Cisco hardware flows) | 2 | 1 | 1 (`denied_flow`) | `PASS` |
| **ServiceNow CMDB** (`servicenow-cmdb`) | `fixture-only` | `pytest tests/test_ingestors.py -k test_servicenow_cmdb_declared_model_and_reconcile` (read-only Table API -> `DeclaredModel` with `servicenow_sys_id`) | 2 CIs, 1 rel | 1 declared pair | 0 | `PASS` |

---

## End-to-End Continuous Runner Proof (Acceptance #3)

- **Test:** `test_live_continuous_runner_multi_source_end_to_end`
- **Live Local Sources:** `NetFlowUDPCollector` (loopback UDP) + `SFlowUDPCollector` (loopback UDP) + `OpenLineageHTTPCollector` (loopback HTTP `POST /api/v1/lineage`).
- **Observed Result:**
  - **Cycle 1 (`sequence=1`):** Emitted signed DSSEv1 Ed25519 envelope with 2 network edges (IPFIX + sFlow with `sampling_rate=512`) and 1 lineage edge (`layer="lineage"`). Verified fail-closed by unmodified `verify_envelope()`.
  - **Cycle 2 (`sequence=2`):** Ingested additional live IPFIX flow, bumped `sequence` to `2`, re-issued signed envelope. Verified fail-closed by unmodified `verify_envelope()`.
  - **Negative Proofs:** Expired clock raised `ExpiredGraph`; tampered payload raised `BadSignature`.
  - **Failure Isolation Proof (`test_runner_enforces_reissue_shorter_than_ttl_and_isolates_failures`):** Dead collector (`ConnectionError`) and garbage-returning collector were quarantined loudly in `failed_sources` while the healthy collector still issued a valid `sequence=1` signed envelope.
