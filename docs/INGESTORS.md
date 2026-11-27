# G1-Manifest Ingestor Contract & Adapter Kit

This document specifies how to build a new telemetry ingestor for **G1-Manifest** without reading the rest of the codebase. The contract is the integration — not a pile of one-off adapters.

---

## 1. Two-Layer Separation (Mandatory)

Every ingestor MUST split cleanly into two independent layers:

| Layer | Location | Responsibilities | Prohibitions |
| :--- | :--- | :--- | :--- |
| **Pure Parser** | `estate_graph/sources/<format>.py` | Parse raw bytes/text/dicts into `list[FlowObservation]` (or `(edges, nodes)` for lineage / `DeclaredModel` for CMDB). Deterministic output. | No network, no wall clock, no filesystem I/O, no credentials. |
| **Live Collector** | `estate_graph/ingestors/<name>.py` | Talk to external endpoints (UDP socket, HTTP listener, cloud API, streaming RPC), manage read-only credentials, retries, checkpointing, and deduplication. | Never writes to the monitored estate, never modifies `aggregate.py` / `sign.py` / `verify.py`. |

---

## 2. Core Data Contract (`FlowObservation`)

```python
@dataclass
class FlowObservation:
    source: str        # service id or "ip:<addr>"
    target: str        # service id or "ip:<addr>"
    port: int | None   # destination port (None for ICMP / portless)
    protocol: str | None  # "TCP" | "UDP" | "ICMP" | ...
    count: int         # >= 1 completed flows observed
    first_seen: int    # UTC epoch seconds
    last_seen: int     # UTC epoch seconds
    origin: str        # lowercase kebab-case source identifier (ORIGIN)
    labels: dict       # optional metadata, e.g. {"sampling_rate": 1000}
```

### `ORIGIN` Naming Convention
Use lowercase kebab-case naming the telemetry protocol or system:
- Standards: `netflow-v9`, `ipfix`, `sflow`, `openlineage`
- Cloud / K8s: `vpc-flow-logs`, `aws-vpc-s3`, `aws-vpc-cwlogs`, `azure-nsg-flow`, `gcp-vpc-flow`, `hubble`
- Vendor / CMDB: `cisco-catalyst`, `cisco-sna`, `servicenow-cmdb`

### Identity Rule
Resolve IPs to service names **only** through `IdentityResolver` populated from named mapping sources (`declared`, `dns`, `aws-tags`, `k8s-api`, `cisco-catalyst`, `servicenow-cmdb`). Never guess a service name. Any unmapped IP keeps its honest identity `ip:<addr>`.

### Evidence Rule
Only **completed / accepted** traffic becomes a `FlowObservation` (`ACCEPT`/`OK` in VPC logs, `FORWARDED` in Hubble, non-zero forwarded flow in NetFlow/IPFIX/sFlow). Rejected, dropped, or denied records are attempts — count them via `stats.record_drop("rejected_action")`, never turn them into edges.

---

## 3. Collector Configuration Shape

Live runners read one JSON config file plus environment variables for secrets (never hard-coded credentials):

```json
{
  "graph_id": "estate-graph",
  "ttl_seconds": 86400,
  "reissue_interval_seconds": 3600,
  "checkpoint_path": "state/checkpoints.json",
  "output_envelope": "out/estate.envelope.json",
  "private_key_env": "G1_MANIFEST_PRIVATE_KEY_PATH",
  "sources": [
    {
      "id": "dc-netflow",
      "type": "netflow",
      "host": "0.0.0.0",
      "port": 2055
    },
    {
      "id": "aws-prod-s3",
      "type": "aws-s3",
      "bucket": "prod-vpc-flow-logs",
      "prefix": "AWSLogs/"
    }
  ]
}
```

---

## 4. Worked Example (Annotated VPC Flow Log Parser)

See `estate_graph/sources/flowlog.py` and the copyable template at `estate_graph/ingestors/skeleton.py`:

1. **Skip non-evidence rows:** blank lines, headers (`parts[0] == "version"`), `action != "ACCEPT"`, `log_status != "OK"`, or missing `-` fields.
2. **Resolve identity honestly:** `src = ip_to_service.get(srcaddr, f"ip:{srcaddr}")`; drop self-traffic (`src == dst`).
3. **Normalize timestamps & protocols:** integer UTC epoch seconds (`start`, `end`), IANA protocol numbers (`6 -> "TCP"`, `17 -> "UDP"`, `1 -> "ICMP"`).
4. **Aggregate deterministically:** sum `count`, widen `[first_seen, last_seen]`, and return sorted by `(source, target, port or 0)`.

---

## 5. Error & Dropped-Record Reporting

Every collector returns a `CollectorResult` containing `CollectorStats`:
- `records_in`: total raw records/packets inspected
- `observations_out`: normalized `FlowObservation` count emitted
- `records_dropped`: total rejected/malformed/self-traffic records skipped
- `drop_reasons`: breakdown dict (e.g. `{"non_accepted_action": 12, "malformed_packet": 1}`)
- `live`: `True` only when connected to a real live endpoint; `False` for fixture/fake runs

A dead or failing source must never crash the runner — it is logged with `stats.error` and excluded from that cycle while healthy sources still issue the signed graph.

---

## 6. Proposed Future CMDB Export Shape (Read-Only Today)

This order is strictly **read-only** against ServiceNow (`Item 5`). A future write-back order would export reconciled drift as a signed advisory payload (never auto-mutating CMDB tables without human approval):

```json
{
  "envelope_sha256": "<sha256-of-dsse-envelope>",
  "graph_id": "estate-graph",
  "sequence": 42,
  "proposed_ci_updates": [
    {
      "action": "propose_relationship",
      "source_sys_id": "<cmdb_ci_sys_id>",
      "target_id": "ip:203.0.113.66",
      "evidence": {"flow_count": 3, "first_seen": 1795716000, "last_seen": 1795719600},
      "requires_human_approval": true
    }
  ]
}
```
