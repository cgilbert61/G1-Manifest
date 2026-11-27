"""Core data model for the estate dependency graph.

Design rule (Chuck's terms): every edge carries *evidence* — flow counts and
timestamps from observation — never an opinion. The graph is a claim about
what the estate actually does, and it expires like every other G1 record:
expired means expired.

Timestamps are epoch seconds (UTC) everywhere internally; helpers convert
to/from ISO-8601 for humans and for foreign formats (Hubble, OpenLineage).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0"
SUPPORTED_VERSIONS = {"1.0"}

LAYER_NETWORK = "network"
LAYER_LINEAGE = "lineage"
LAYER_PACKAGE = "package"
LAYER_OBSERVED_LOAD = "observed-load"


def parse_ts(value) -> int:
    """Accept epoch seconds (int/float/str) or ISO-8601; return epoch int."""
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip()
    if text.lstrip("-").isdigit():
        return int(text)
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def iso_utc(epoch: int) -> str:
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


@dataclass
class Evidence:
    """Why we believe an edge exists. Counts and timestamps, not opinion."""

    flow_count: int = 0
    first_seen: int = 0
    last_seen: int = 0
    sources: list[str] = field(default_factory=list)

    @property
    def window_seconds(self) -> int:
        return max(0, self.last_seen - self.first_seen)

    def merge(self, other: "Evidence") -> "Evidence":
        first_candidates = [t for t in (self.first_seen, other.first_seen) if t]
        return Evidence(
            flow_count=self.flow_count + other.flow_count,
            first_seen=min(first_candidates) if first_candidates else 0,
            last_seen=max(self.last_seen, other.last_seen),
            sources=sorted(set(self.sources) | set(other.sources)),
        )

    def to_dict(self) -> dict:
        return {
            "flow_count": self.flow_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sources": sorted(self.sources),
            "window_seconds": self.window_seconds,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Evidence":
        return cls(
            flow_count=int(d.get("flow_count", 0)),
            first_seen=int(d.get("first_seen", 0)),
            last_seen=int(d.get("last_seen", 0)),
            sources=list(d.get("sources", [])),
        )


@dataclass
class ServiceNode:
    id: str
    kind: str = "service"  # service | dataset | external
    substrate: str = "unknown"  # aws | kubernetes | declared | ...
    labels: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "substrate": self.substrate,
            "labels": self.labels,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ServiceNode":
        return cls(
            id=d["id"],
            kind=d.get("kind", "service"),
            substrate=d.get("substrate", "unknown"),
            labels=dict(d.get("labels", {})),
        )


@dataclass
class Edge:
    source: str
    target: str
    port: int | None = None
    protocol: str | None = None
    layer: str = LAYER_NETWORK  # network | lineage | package | observed-load
    evidence: Evidence = field(default_factory=Evidence)
    # Free-form annotations a source needs to keep (e.g. a pip requirement
    # that only applies under an environment marker). Serialized only when
    # non-empty, so existing graphs' canonical bytes do not change.
    labels: dict = field(default_factory=dict)
    # Rare flows are the point, not noise: a dependency that fires once a
    # month must survive. Seen-once edges are kept and flagged, never dropped.
    low_frequency: bool = False

    def key(self) -> tuple:
        return (self.source, self.target, self.port, self.protocol, self.layer)

    def pair(self) -> tuple:
        return (self.source, self.target)

    def to_dict(self) -> dict:
        d = {
            "source": self.source,
            "target": self.target,
            "port": self.port,
            "protocol": self.protocol,
            "layer": self.layer,
            "low_frequency": self.low_frequency,
            "evidence": self.evidence.to_dict(),
        }
        if self.labels:
            d["labels"] = self.labels
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Edge":
        return cls(
            source=d["source"],
            target=d["target"],
            port=d.get("port"),
            protocol=d.get("protocol"),
            layer=d.get("layer", LAYER_NETWORK),
            low_frequency=bool(d.get("low_frequency", False)),
            evidence=Evidence.from_dict(d.get("evidence", {})),
            labels=dict(d.get("labels", {})),
        )


@dataclass
class FlowObservation:
    """One aggregated flow fact from one source, before graph merging."""

    source: str
    target: str
    port: int | None
    protocol: str | None
    count: int
    first_seen: int
    last_seen: int
    origin: str  # which source produced it, e.g. "vpc-flow-logs"
    labels: dict = field(default_factory=dict)  # e.g. {"sampling_rate": 1000}


@dataclass
class DependencyGraph:
    graph_id: str
    producer: str
    issued_at: int
    expires_at: int
    nodes: list[ServiceNode] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    version: str = SCHEMA_VERSION
    sequence: int = 1  # instance revision; re-learning bumps this

    def node(self, node_id: str) -> ServiceNode | None:
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def network_edges(self) -> list[Edge]:
        return [e for e in self.edges if e.layer == LAYER_NETWORK]

    def edges_on_layer(self, layer: str) -> list[Edge]:
        return [e for e in self.edges if e.layer == layer]

    def is_expired(self, now: int) -> bool:
        return now >= self.expires_at

    def to_dict(self) -> dict:
        return {
            "graph_id": self.graph_id,
            "version": self.version,
            "sequence": self.sequence,
            "producer": self.producer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nodes": [n.to_dict() for n in sorted(self.nodes, key=lambda n: n.id)],
            "edges": [
                e.to_dict()
                for e in sorted(
                    self.edges,
                    key=lambda e: (
                        e.source,
                        e.target,
                        e.port or 0,
                        e.protocol or "",
                        e.layer,
                    ),
                )
            ],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DependencyGraph":
        return cls(
            graph_id=d["graph_id"],
            version=d.get("version", ""),
            sequence=int(d.get("sequence", 1)),
            producer=d.get("producer", ""),
            issued_at=int(d.get("issued_at", 0)),
            expires_at=int(d.get("expires_at", 0)),
            nodes=[ServiceNode.from_dict(n) for n in d.get("nodes", [])],
            edges=[Edge.from_dict(e) for e in d.get("edges", [])],
        )

    def canonical_json(self) -> bytes:
        """Stable bytes for signing: sorted keys, no whitespace drift."""
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
