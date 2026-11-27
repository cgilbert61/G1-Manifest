"""Ingestor contract, identity resolution with provenance, and checkpointing.

Every live ingestor splits cleanly into two layers:
1. Parser (``estate_graph/sources/<name>.py``): pure function from raw records
   to ``list[FlowObservation]`` (or ``(edges, nodes)`` for lineage / declared).
   No network, no clock, no filesystem.
2. Collector (``estate_graph/ingestors/<name>.py``): talks to the outside world
   (UDP socket, cloud API, HTTP listener, streaming RPC), handles credentials,
   retries, and checkpointing, and feeds raw records to its pure parser.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..model import Edge, FlowObservation, ServiceNode


@dataclass
class CollectorStats:
    """Empirical accounting for a single collector run."""

    origin: str
    records_in: int = 0
    observations_out: int = 0
    records_dropped: int = 0
    drop_reasons: dict[str, int] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    live: bool = False
    error: str | None = None

    def record_drop(self, reason: str, count: int = 1) -> None:
        self.records_dropped += count
        self.drop_reasons[reason] = self.drop_reasons.get(reason, 0) + count

    def to_dict(self) -> dict:
        return {
            "origin": self.origin,
            "records_in": self.records_in,
            "observations_out": self.observations_out,
            "records_dropped": self.records_dropped,
            "drop_reasons": dict(sorted(self.drop_reasons.items())),
            "elapsed_ms": round(self.elapsed_ms, 2),
            "live": self.live,
            "error": self.error,
        }


@dataclass
class CollectorResult:
    """Normalized output returned by every collector's ``collect()`` call."""

    origin: str
    observations: list[FlowObservation] = field(default_factory=list)
    extra_edges: list[Edge] = field(default_factory=list)
    extra_nodes: list[ServiceNode] = field(default_factory=list)
    stats: CollectorStats = field(default_factory=lambda: CollectorStats(origin="unknown"))


class IdentityResolver:
    """Resolve IP addresses to service IDs strictly from named mapping sources.

    Never guesses a service name. Any unmapped IP keeps its honest ``ip:<addr>``
    identity. Records which mapping source resolved each service so provenance
    is preserved on the resulting ``ServiceNode.labels``.
    """

    def __init__(self) -> None:
        # ip -> (service_id, mapping_source)
        self._ip_map: dict[str, tuple[str, str]] = {}
        self._service_sources: dict[str, set[str]] = {}

    def register(self, ip: str, service_id: str, mapping_source: str) -> None:
        ip_s = str(ip).strip()
        svc_s = str(service_id).strip()
        src_s = str(mapping_source).strip() or "unknown"
        if not ip_s or not svc_s:
            return
        # First registered higher-priority mapping wins; record all sources.
        if ip_s not in self._ip_map:
            self._ip_map[ip_s] = (svc_s, src_s)
        self._service_sources.setdefault(svc_s, set()).add(src_s)

    def register_bulk(self, mapping: dict[str, str], mapping_source: str) -> None:
        for ip, svc in sorted(mapping.items()):
            self.register(ip, svc, mapping_source)

    def resolve(self, ip: str) -> tuple[str, str | None]:
        ip_s = str(ip).strip()
        if ip_s in self._ip_map:
            return self._ip_map[ip_s]
        return f"ip:{ip_s}", None

    def as_ip_to_service(self) -> dict[str, str]:
        return {ip: svc for ip, (svc, _src) in self._ip_map.items()}

    def provenance_nodes(self) -> list[ServiceNode]:
        """Return ServiceNodes annotated with ``identity_sources`` metadata."""
        return [
            ServiceNode(
                id=svc,
                kind="service",
                substrate="resolved",
                labels={"identity_sources": sorted(sources)},
            )
            for svc, sources in sorted(self._service_sources.items())
        ]


class CheckpointStore:
    """Atomic per-source JSON checkpoint store for restart-safe ingestion."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._state: dict[str, dict] = {}
        if self.path.is_file():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._state = data
            except Exception:
                self._state = {}

    def get(self, source_id: str) -> dict:
        return dict(self._state.get(source_id, {}))

    def set(self, source_id: str, checkpoint: dict) -> None:
        self._state[source_id] = dict(checkpoint)
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._state, indent=2, sort_keys=True) + "\n"
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".ckpt-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp_name, self.path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise


def validate_observations(
    observations: list[FlowObservation],
    *,
    stats: CollectorStats | None = None,
) -> list[FlowObservation]:
    """Enforce contract invariants: no self-edges, positive counts, valid timestamps."""
    valid: list[FlowObservation] = []
    for obs in observations:
        if not obs.source or not obs.target:
            if stats:
                stats.record_drop("missing_endpoint")
            continue
        if obs.source == obs.target:
            if stats:
                stats.record_drop("self_traffic")
            continue
        if obs.count <= 0:
            if stats:
                stats.record_drop("non_positive_count")
            continue
        if obs.first_seen < 0 or obs.last_seen < 0:
            if stats:
                stats.record_drop("negative_timestamp")
            continue
        valid.append(obs)
    return sorted(
        valid,
        key=lambda o: (o.source, o.target, o.port or 0, o.protocol or "", o.origin),
    )
