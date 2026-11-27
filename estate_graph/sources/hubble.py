"""Cilium Hubble `observe` JSON-lines input.

Each line is a JSON object (optionally wrapped in a ``flow`` key) with
source/destination endpoints carrying pod name, namespace and labels, a
destination port (top-level or under ``l4``), and a verdict. Only
FORWARDED flows are evidence of a working dependency.

Service identity comes from the ``app`` (or ``app.kubernetes.io/name``)
label when present; otherwise from the pod name with the ReplicaSet hash
and pod suffix stripped (``checkout-api-7d9f8c5b4-x2abc`` -> ``checkout-api``).
"""

from __future__ import annotations

import json
import re

from ..model import FlowObservation, parse_ts

ORIGIN = "hubble"

_HASH_SEGMENT = re.compile(r"^[a-z0-9]{8,10}$")
_POD_SUFFIX = re.compile(r"^[a-z0-9]{5}$")


def _label_value(labels, *names) -> str | None:
    if isinstance(labels, dict):
        items = [f"{k}={v}" for k, v in labels.items()]
    else:
        items = list(labels or [])
    parsed = {}
    for item in items:
        if "=" in item:
            k, v = item.split("=", 1)
            # Short key: "k8s:app" -> "app", "app.kubernetes.io/name" -> "name"
            parsed[k.split(":")[-1].rsplit("/", 1)[-1]] = v
            parsed[k] = v
    for name in names:
        if name in parsed:
            return parsed[name]
    return None


def _pod_base_name(pod_name: str) -> str:
    parts = pod_name.split("-")
    if len(parts) >= 3 and _POD_SUFFIX.match(parts[-1]) and _HASH_SEGMENT.match(
        parts[-2]
    ):
        return "-".join(parts[:-2])
    return pod_name


def service_identity(endpoint: dict) -> str | None:
    if not endpoint:
        return None
    app = _label_value(
        endpoint.get("labels"), "app", "app.kubernetes.io/name", "name"
    )
    if app:
        return app
    pod = endpoint.get("pod_name")
    if pod:
        return _pod_base_name(pod)
    return None


def _port_and_protocol(flow: dict) -> tuple[int | None, str | None]:
    port = flow.get("destination_port")
    l4 = flow.get("l4") or {}
    for proto in ("TCP", "UDP", "ICMPv4", "ICMPv6"):
        if proto in l4:
            if port is None:
                port = l4[proto].get("destination_port")
            return port, "ICMP" if proto.startswith("ICMP") else proto
    return port, flow.get("protocol")


def parse_hubble(text: str) -> list[FlowObservation]:
    agg: dict[tuple, FlowObservation] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        flow = obj.get("flow", obj)
        if not isinstance(flow, dict):
            continue
        if flow.get("verdict") not in (None, "FORWARDED"):
            continue
        raw_src = flow.get("source")
        raw_dst = flow.get("destination")
        if not isinstance(raw_src, dict) or not isinstance(raw_dst, dict):
            continue
        src = service_identity(raw_src)
        dst = service_identity(raw_dst)
        if not src or not dst or src == dst:
            continue
        port, protocol = _port_and_protocol(flow)
        try:
            ts = parse_ts(obj.get("time") or flow.get("time") or 0)
        except (ValueError, TypeError):
            ts = 0
        key = (src, dst, port, protocol)
        obs = agg.get(key)
        if obs is None:
            agg[key] = FlowObservation(
                source=src,
                target=dst,
                port=port,
                protocol=protocol,
                count=1,
                first_seen=ts,
                last_seen=ts,
                origin=ORIGIN,
            )
        else:
            obs.count += 1
            obs.first_seen = min(obs.first_seen, ts) if ts else obs.first_seen
            obs.last_seen = max(obs.last_seen, ts)
    return sorted(agg.values(), key=lambda o: (o.source, o.target, o.port or 0))


def load_hubble(path: str) -> list[FlowObservation]:
    with open(path, encoding="utf-8") as fh:
        return parse_hubble(fh.read())
