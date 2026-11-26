"""AWS VPC Flow Logs (v2, default space-delimited text format).

Fields: version account-id interface-id srcaddr dstaddr srcport dstport
protocol packets bytes start end action log-status

Only ACCEPT records with log-status OK are evidence of a dependency.
REJECT records are evidence of an *attempt* — interesting for security,
but a shield allowlist built from attempts would paper things that never
worked. Unmapped IPs keep an ``ip:<addr>`` identity so an unknown external
dependency shows up in the graph as exactly what it is: unknown.
"""

from __future__ import annotations

from ..model import FlowObservation

ORIGIN = "vpc-flow-logs"
_PROTOCOLS = {"1": "ICMP", "6": "TCP", "17": "UDP"}


def parse_flow_logs(
    text: str, ip_to_service: dict[str, str]
) -> list[FlowObservation]:
    """Parse flow-log text and aggregate into flow observations."""
    agg: dict[tuple, FlowObservation] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 14 or parts[0] == "version":
            continue  # blank line or header row
        (
            _ver,
            _acct,
            _iface,
            srcaddr,
            dstaddr,
            _srcport,
            dstport,
            protocol,
            _packets,
            _bytes,
            start,
            end,
            action,
            log_status,
        ) = parts[:14]
        if action != "ACCEPT" or log_status != "OK":
            continue
        if srcaddr == "-" or dstaddr == "-" or start == "-" or end == "-":
            continue
        src = ip_to_service.get(srcaddr, f"ip:{srcaddr}")
        dst = ip_to_service.get(dstaddr, f"ip:{dstaddr}")
        if src == dst:
            continue
        try:
            ts_start, ts_end = int(start), int(end)
            port = None if dstport == "-" else int(dstport)
        except ValueError:
            continue
        proto = _PROTOCOLS.get(protocol, protocol)
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
                origin=ORIGIN,
            )
        else:
            obs.count += 1
            obs.first_seen = min(obs.first_seen, ts_start)
            obs.last_seen = max(obs.last_seen, ts_end)
    return sorted(
        agg.values(), key=lambda o: (o.source, o.target, o.port or 0)
    )


def load_flow_logs(
    path: str, ip_to_service: dict[str, str]
) -> list[FlowObservation]:
    with open(path, encoding="utf-8") as fh:
        return parse_flow_logs(fh.read(), ip_to_service)
