"""OpenLineage RunEvent importer.

Lineage edges say a dataset was *derived from* another dataset. That is a
different claim from a network flow — a derivation is not a connection a
shield can cut — so lineage edges are kept on their own layer in the graph
(``layer="lineage"``) and never take part in network reconciliation.

Input: one RunEvent object, a list of them, or a ``{"events": [...]}``
wrapper. Each event's inputs become upstreams of its outputs.
"""

from __future__ import annotations

import json

from ..model import Edge, Evidence, ServiceNode, parse_ts

ORIGIN = "openlineage"


def _dataset_id(ds: dict) -> str:
    return f"{ds.get('namespace', '')}/{ds.get('name', '')}".strip("/")


def parse_lineage(data) -> tuple[list[Edge], list[ServiceNode]]:
    if isinstance(data, dict) and "events" in data:
        events = data["events"]
    elif isinstance(data, list):
        events = data
    else:
        events = [data]
    edges: dict[tuple, Edge] = {}
    nodes: dict[str, ServiceNode] = {}
    for event in events:
        ts = parse_ts(event.get("eventTime", 0))
        inputs = [_dataset_id(d) for d in event.get("inputs", [])]
        outputs = [_dataset_id(d) for d in event.get("outputs", [])]
        for ds_id in inputs + outputs:
            if ds_id:
                nodes.setdefault(
                    ds_id,
                    ServiceNode(id=ds_id, kind="dataset", substrate="lineage"),
                )
        for up in inputs:
            for down in outputs:
                if not up or not down or up == down:
                    continue
                key = (up, down)
                ev = Evidence(
                    flow_count=1, first_seen=ts, last_seen=ts, sources=[ORIGIN]
                )
                if key in edges:
                    edges[key].evidence = edges[key].evidence.merge(ev)
                else:
                    edges[key] = Edge(
                        source=up, target=down, layer="lineage", evidence=ev
                    )
    return sorted(edges.values(), key=lambda e: (e.source, e.target)), sorted(
        nodes.values(), key=lambda n: n.id
    )


def load_lineage(path: str) -> tuple[list[Edge], list[ServiceNode]]:
    with open(path, encoding="utf-8") as fh:
        return parse_lineage(json.load(fh))
