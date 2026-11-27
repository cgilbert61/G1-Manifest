"""Pure parsers for Cisco Catalyst Center inventory and Cisco SNA flow exports.

Cisco is treated strictly as a source of evidence, never a dependency:
- NetFlow v9 / IPFIX (``sources/netflow.py``) already covers Cisco network
  hardware flow exports via open standards.
- ``parse_cisco_catalyst_inventory`` maps Catalyst Center (formerly DNA Center)
  device inventory (``/dna/intent/api/v1/network-device``) into IP->service
  identity mappings and ``ServiceNode`` records.
- ``parse_cisco_sna_flows`` normalizes Cisco Secure Network Analytics (formerly
  Stealthwatch) flow-search JSON exports into ``FlowObservation`` records.
"""

from __future__ import annotations

import json

from ..ingestors.contract import CollectorStats, IdentityResolver, validate_observations
from ..model import FlowObservation, ServiceNode, parse_ts

ORIGIN_CATALYST = "cisco-catalyst"
ORIGIN_SNA = "cisco-sna"


def parse_cisco_catalyst_inventory(
    data: str | dict | list,
) -> tuple[dict[str, str], list[ServiceNode]]:
    """Parse Catalyst Center ``network-device`` JSON -> (ip_map, ServiceNodes)."""
    if isinstance(data, str):
        parsed = json.loads(data)
    else:
        parsed = data
    devices = (
        parsed.get("response", [])
        if isinstance(parsed, dict)
        else (parsed if isinstance(parsed, list) else [])
    )
    ip_map: dict[str, str] = {}
    nodes: dict[str, ServiceNode] = {}
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        hostname = str(dev.get("hostname") or "").strip()
        mgmt_ip = str(dev.get("managementIpAddress") or "").strip()
        if not hostname:
            continue  # never guess a hostname
        if mgmt_ip:
            ip_map[mgmt_ip] = hostname
        nodes[hostname] = ServiceNode(
            id=hostname,
            kind="service",
            substrate=ORIGIN_CATALYST,
            labels={
                "identity_sources": [ORIGIN_CATALYST],
                "cisco_device_id": str(dev.get("id") or ""),
                "role": str(dev.get("role") or ""),
                "platform": str(dev.get("platformId") or ""),
            },
        )
    return ip_map, sorted(nodes.values(), key=lambda n: n.id)


def parse_cisco_sna_flows(
    data: str | dict | list,
    resolver: IdentityResolver | None = None,
    *,
    stats: CollectorStats | None = None,
) -> list[FlowObservation]:
    """Parse Cisco Secure Network Analytics flow export JSON into FlowObservations."""
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

    flows = (
        parsed.get("data", {}).get("flows", [])
        if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict)
        else (parsed.get("flows", []) if isinstance(parsed, dict) else (parsed if isinstance(parsed, list) else []))
    )
    agg: dict[tuple, FlowObservation] = {}
    for rec in flows:
        if stats:
            stats.records_in += 1
        if not isinstance(rec, dict):
            if stats:
                stats.record_drop("non_dict_record")
            continue
        action = str(rec.get("action") or "ALLOW").upper()
        if action not in ("ALLOW", "ALLOWED", "ACCEPT", "PERMIT"):
            if stats:
                stats.record_drop("denied_flow")
            continue
        subj = rec.get("subject") or {}
        peer = rec.get("peer") or {}
        src_ip = str(subj.get("ipAddress") or rec.get("src_ip") or "").strip()
        dst_ip = str(peer.get("ipAddress") or rec.get("dst_ip") or "").strip()
        if not src_ip or not dst_ip:
            if stats:
                stats.record_drop("missing_ip")
            continue
        src = resolver.resolve(src_ip)[0] if resolver else f"ip:{src_ip}"
        dst = resolver.resolve(dst_ip)[0] if resolver else f"ip:{dst_ip}"
        if src == dst:
            if stats:
                stats.record_drop("self_traffic")
            continue

        # peer.portProtocol is commonly "443/tcp" or separate port/protocol fields
        port: int | None = None
        proto: str | None = None
        pp = str(peer.get("portProtocol") or "").strip()
        if "/" in pp:
            p_str, pr_str = pp.split("/", 1)
            try:
                port = int(p_str)
            except ValueError:
                port = None
            proto = pr_str.upper() or None
        else:
            raw_port = peer.get("port", rec.get("dst_port"))
            if raw_port is not None:
                try:
                    port = int(raw_port)
                except (ValueError, TypeError):
                    port = None
            raw_proto = peer.get("protocol", rec.get("protocol"))
            proto = str(raw_proto).upper() if raw_proto else None

        st = rec.get("statistics") or {}
        try:
            first_ts = parse_ts(st.get("firstActiveTime") or rec.get("first_seen") or 0)
            last_ts = parse_ts(st.get("lastActiveTime") or rec.get("last_seen") or first_ts)
            count = int(st.get("flowCount") or rec.get("flow_count") or 1)
        except (ValueError, TypeError):
            if stats:
                stats.record_drop("malformed_field")
            continue

        key = (src, dst, port, proto)
        obs = agg.get(key)
        if obs is None:
            agg[key] = FlowObservation(
                source=src,
                target=dst,
                port=port,
                protocol=proto,
                count=max(1, count),
                first_seen=first_ts,
                last_seen=last_ts,
                origin=ORIGIN_SNA,
            )
        else:
            obs.count += max(1, count)
            obs.first_seen = min(obs.first_seen, first_ts) if first_ts else obs.first_seen
            obs.last_seen = max(obs.last_seen, last_ts)

    observations = validate_observations(list(agg.values()), stats=stats)
    if stats:
        stats.observations_out = len(observations)
    return observations
