"""Pure parsers for Azure NSG Flow Logs (v2) and GCP VPC Flow Logs.

Both parsers follow the exact G1-Manifest contract:
- Pure functions (no network, no clock, no filesystem).
- Only completed / allowed traffic becomes a FlowObservation.
- Unmapped IPs keep their honest ``ip:<addr>`` identity.
- Malformed records are cleanly refused and counted in ``CollectorStats``.
"""

from __future__ import annotations

import json

from ..ingestors.contract import CollectorStats, IdentityResolver, validate_observations
from ..model import FlowObservation, parse_ts

ORIGIN_AZURE_NSG = "azure-nsg-flow"
ORIGIN_GCP_VPC = "gcp-vpc-flow"

_AZURE_PROTO = {"T": "TCP", "U": "UDP", "6": "TCP", "17": "UDP", "1": "ICMP"}
_IANA_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMP"}


def parse_azure_nsg_flow_logs(
    data: str | dict | list,
    resolver: IdentityResolver | None = None,
    *,
    stats: CollectorStats | None = None,
) -> list[FlowObservation]:
    """Parse Azure NSG Flow Logs v2 JSON into FlowObservations."""
    if isinstance(data, str):
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            if stats:
                stats.records_in += 1
                stats.record_drop("invalid_json")
            return []
    else:
        parsed = data

    records = (
        parsed.get("records", [])
        if isinstance(parsed, dict)
        else (parsed if isinstance(parsed, list) else [])
    )
    agg: dict[tuple, FlowObservation] = {}

    for rec in records:
        if not isinstance(rec, dict):
            continue
        props = rec.get("properties") or {}
        for rule_group in props.get("flows") or []:
            for flow_group in rule_group.get("flows") or []:
                for raw_tuple in flow_group.get("flowTuples") or []:
                    if stats:
                        stats.records_in += 1
                    parts = str(raw_tuple).split(",")
                    if len(parts) < 8:
                        if stats:
                            stats.record_drop("truncated_tuple")
                        continue
                    ts_s, src_ip, dst_ip, _src_p, dst_p, proto_s, _dir, decision = parts[:8]
                    if decision.strip().upper() != "A":
                        if stats:
                            stats.record_drop("denied_flow")
                        continue
                    try:
                        ts = parse_ts(ts_s)
                        port = int(dst_p) if dst_p and dst_p != "-" else None
                    except (ValueError, TypeError):
                        if stats:
                            stats.record_drop("malformed_field")
                        continue
                    src = resolver.resolve(src_ip)[0] if resolver else f"ip:{src_ip}"
                    dst = resolver.resolve(dst_ip)[0] if resolver else f"ip:{dst_ip}"
                    if src == dst:
                        if stats:
                            stats.record_drop("self_traffic")
                        continue
                    proto = _AZURE_PROTO.get(proto_s.strip().upper(), proto_s.strip().upper())
                    key = (src, dst, port, proto)
                    obs = agg.get(key)
                    if obs is None:
                        agg[key] = FlowObservation(
                            source=src,
                            target=dst,
                            port=port,
                            protocol=proto,
                            count=1,
                            first_seen=ts,
                            last_seen=ts,
                            origin=ORIGIN_AZURE_NSG,
                        )
                    else:
                        obs.count += 1
                        obs.first_seen = min(obs.first_seen, ts) if ts else obs.first_seen
                        obs.last_seen = max(obs.last_seen, ts)

    observations = validate_observations(list(agg.values()), stats=stats)
    if stats:
        stats.observations_out = len(observations)
    return observations


def parse_gcp_vpc_flow_logs(
    data: str | dict | list,
    resolver: IdentityResolver | None = None,
    *,
    stats: CollectorStats | None = None,
) -> list[FlowObservation]:
    """Parse GCP VPC Flow Log JSON/JSONL export entries into FlowObservations."""
    entries: list = []
    if isinstance(data, str):
        text = data.strip()
        if not text:
            return []
        if text.startswith("[") or text.startswith("{"):
            try:
                obj = json.loads(text)
                entries = obj if isinstance(obj, list) else [obj]
            except json.JSONDecodeError:
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        if stats:
                            stats.records_in += 1
                            stats.record_drop("invalid_json_line")
        else:
            if stats:
                stats.records_in += 1
                stats.record_drop("invalid_json")
            return []
    elif isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = [data]

    agg: dict[tuple, FlowObservation] = {}
    for entry in entries:
        if stats:
            stats.records_in += 1
        if not isinstance(entry, dict):
            if stats:
                stats.record_drop("non_dict_entry")
            continue
        payload = entry.get("jsonPayload") or entry
        conn = payload.get("connection") or {}
        src_ip = str(conn.get("src_ip") or "").strip()
        dst_ip = str(conn.get("dest_ip") or "").strip()
        if not src_ip or not dst_ip:
            if stats:
                stats.record_drop("missing_ip")
            continue
        # Reject explicitly denied entries if a disposition/action is present
        disposition = str(payload.get("disposition") or "ALLOWED").upper()
        if disposition not in ("ALLOWED", "ALLOW", "ACCEPTED", "ACCEPT"):
            if stats:
                stats.record_drop("denied_flow")
            continue
        try:
            raw_port = conn.get("dest_port")
            port = int(raw_port) if raw_port is not None else None
            raw_proto = conn.get("protocol")
            proto = (
                _IANA_PROTO.get(int(raw_proto), str(raw_proto))
                if raw_proto is not None and str(raw_proto).isdigit()
                else (str(raw_proto).upper() if raw_proto else None)
            )
            ts_start = parse_ts(
                payload.get("start_time") or entry.get("timestamp") or 0
            )
            ts_end = parse_ts(
                payload.get("end_time")
                or payload.get("start_time")
                or entry.get("timestamp")
                or 0
            )
        except (ValueError, TypeError):
            if stats:
                stats.record_drop("malformed_field")
            continue

        src = resolver.resolve(src_ip)[0] if resolver else f"ip:{src_ip}"
        dst = resolver.resolve(dst_ip)[0] if resolver else f"ip:{dst_ip}"
        if src == dst:
            if stats:
                stats.record_drop("self_traffic")
            continue
        if proto == "ICMP":
            port = None
        key = (src, dst, port, proto)
        obs = agg.get(key)
        if obs is None:
            agg[key] = FlowObservation(
                source=src,
                target=dst,
                port=port,
                protocol=proto,
                count=1,
                first_seen=ts_start,
                last_seen=ts_end,
                origin=ORIGIN_GCP_VPC,
            )
        else:
            obs.count += 1
            obs.first_seen = min(obs.first_seen, ts_start) if ts_start else obs.first_seen
            obs.last_seen = max(obs.last_seen, ts_end)

    observations = validate_observations(list(agg.values()), stats=stats)
    if stats:
        stats.observations_out = len(observations)
    return observations
