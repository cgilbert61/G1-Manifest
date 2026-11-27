"""Aggregation: merge every source's observations into one graph.

Deterministic by construction — same inputs, same graph, byte for byte.
Edges are merged on (source, target, port, protocol, layer); evidence is
summed, never averaged: counts add, the window widens to the extremes,
and the source list is the union. An edge seen even once is kept. Rare
flows are how real dependencies hide (the monthly license check), so a
low count earns a flag, not a deletion.
"""

from __future__ import annotations

import time

from .model import (
    DependencyGraph,
    Edge,
    Evidence,
    FlowObservation,
    ServiceNode,
)

DEFAULT_LOW_FREQUENCY_THRESHOLD = 3


def aggregate(
    observations: list[FlowObservation],
    *,
    declared_nodes: list[ServiceNode] | None = None,
    extra_edges: list[Edge] | None = None,
    extra_nodes: list[ServiceNode] | None = None,
    graph_id: str = "estate-graph",
    producer: str = "g1-estate-graph",
    issued_at: int | None = None,
    ttl_seconds: int = 86400,
    low_frequency_threshold: int = DEFAULT_LOW_FREQUENCY_THRESHOLD,
    sequence: int = 1,
) -> DependencyGraph:
    issued = int(issued_at if issued_at is not None else time.time())
    nodes: dict[str, ServiceNode] = {}

    def ensure_node(node_id: str) -> None:
        if node_id in nodes:
            return
        if node_id.startswith("ip:"):
            # An endpoint no declaration names. It stays in the graph as an
            # external unknown — reconciliation will price it accordingly.
            nodes[node_id] = ServiceNode(
                id=node_id, kind="external", substrate="observed"
            )
        else:
            nodes[node_id] = ServiceNode(id=node_id, kind="service")

    for node in declared_nodes or []:
        nodes[node.id] = node
    for node in extra_nodes or []:
        nodes.setdefault(node.id, node)

    edges: dict[tuple, Edge] = {}
    for obs in observations:
        ensure_node(obs.source)
        ensure_node(obs.target)
        ev = Evidence(
            flow_count=obs.count,
            first_seen=obs.first_seen,
            last_seen=obs.last_seen,
            sources=[obs.origin],
        )
        key = (obs.source, obs.target, obs.port, obs.protocol, "network")
        if key in edges:
            edges[key].evidence = edges[key].evidence.merge(ev)
            if obs.labels:
                edges[key].labels.update(obs.labels)
        else:
            edges[key] = Edge(
                source=obs.source,
                target=obs.target,
                port=obs.port,
                protocol=obs.protocol,
                layer="network",
                evidence=ev,
                labels=dict(obs.labels) if obs.labels else {},
            )
    for edge in extra_edges or []:
        ensure_node(edge.source)
        ensure_node(edge.target)
        key = edge.key()
        if key in edges:
            edges[key].evidence = edges[key].evidence.merge(edge.evidence)
        else:
            edges[key] = Edge(
                source=edge.source,
                target=edge.target,
                port=edge.port,
                protocol=edge.protocol,
                layer=edge.layer,
                evidence=Evidence(
                    flow_count=edge.evidence.flow_count,
                    first_seen=edge.evidence.first_seen,
                    last_seen=edge.evidence.last_seen,
                    sources=list(edge.evidence.sources),
                ),
                labels=dict(edge.labels),
                low_frequency=edge.low_frequency,
            )

    for edge in edges.values():
        if edge.layer == "network":
            edge.low_frequency = (
                edge.evidence.flow_count < low_frequency_threshold
            )

    return DependencyGraph(
        graph_id=graph_id,
        producer=producer,
        issued_at=issued,
        expires_at=issued + ttl_seconds,
        sequence=sequence,
        nodes=sorted(nodes.values(), key=lambda n: n.id),
        edges=sorted(
            edges.values(),
            key=lambda e: (
                e.source,
                e.target,
                e.port or 0,
                e.protocol or "",
                e.layer,
            ),
        ),
    )
