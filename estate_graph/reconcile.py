"""Reconciliation: learned graph vs declared model.

Three buckets, no fourth:

- ``confirmed`` — declared and observed. The claim held.
- ``observed_undeclared`` — the estate does it and nobody wrote it down.
  Each one is a named finding. Severity is high when the target is an
  external/unknown endpoint: that is either a forgotten dependency or
  somebody else's traffic, and a human decides which. Nothing here is
  ever auto-promoted into a declared list — observation proposes,
  a signature disposes.
- ``declared_unobserved`` — declared but never seen in the window.
  A stale candidate: flagged, reported, never silently dropped, because
  the window might just be shorter than the flow's period.

Comparison is at (source, target) pair level because declared lists
(Warrant's AllowedEgressServices) carry no ports. Port detail rides
along in each entry for the human reading it.
"""

from __future__ import annotations

from .model import DependencyGraph
from .sources.declared import DeclaredModel


def _learned_pairs(graph: DependencyGraph) -> dict[tuple, list[dict]]:
    pairs: dict[tuple, list[dict]] = {}
    for edge in graph.network_edges():
        pairs.setdefault(edge.pair(), []).append(
            {
                "port": edge.port,
                "protocol": edge.protocol,
                "flow_count": edge.evidence.flow_count,
                "first_seen": edge.evidence.first_seen,
                "last_seen": edge.evidence.last_seen,
                "sources": edge.evidence.sources,
                "low_frequency": edge.low_frequency,
            }
        )
    return pairs


def reconcile(graph: DependencyGraph, declared: DeclaredModel) -> dict:
    learned = _learned_pairs(graph)
    learned_pairs = set(learned)
    declared_pairs = set(declared.pairs)

    def entry(pair: tuple) -> dict:
        return {"source": pair[0], "target": pair[1]}

    confirmed = []
    for pair in sorted(learned_pairs & declared_pairs):
        e = entry(pair)
        e["observations"] = learned[pair]
        confirmed.append(e)

    observed_undeclared = []
    for pair in sorted(learned_pairs - declared_pairs):
        e = entry(pair)
        node = graph.node(pair[1])
        external = node is not None and node.kind == "external"
        e["severity"] = "high" if external else "medium"
        e["target_kind"] = node.kind if node else "unknown"
        e["observations"] = learned[pair]
        observed_undeclared.append(e)

    declared_unobserved = []
    for pair in sorted(declared_pairs - learned_pairs):
        e = entry(pair)
        e["severity"] = "low"
        e["note"] = "declared but not observed in window; stale candidate"
        declared_unobserved.append(e)

    return {
        "graph_id": graph.graph_id,
        "summary": {
            "confirmed": len(confirmed),
            "observed_undeclared": len(observed_undeclared),
            "declared_unobserved": len(declared_unobserved),
        },
        "confirmed": confirmed,
        "observed_undeclared": observed_undeclared,
        "declared_unobserved": declared_unobserved,
    }
