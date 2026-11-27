"""Skeleton ingestor module demonstrating the G1-Manifest source contract.

Third parties can copy this file as a starting point for a new telemetry
source. Keep the pure parser and the live collector strictly separated:
- ``parse_skeleton_records``: pure function, zero I/O, deterministic output.
- ``SkeletonCollector``: handles transport, credentials, and checkpointing.
"""

from __future__ import annotations

import time

from ..model import FlowObservation, parse_ts
from .contract import (
    CheckpointStore,
    CollectorResult,
    CollectorStats,
    IdentityResolver,
    validate_observations,
)

ORIGIN = "skeleton-example"


def parse_skeleton_records(
    records: list[dict],
    resolver: IdentityResolver | None = None,
    *,
    stats: CollectorStats | None = None,
) -> list[FlowObservation]:
    """Pure parser: raw record dicts -> deterministic list[FlowObservation]."""
    agg: dict[tuple, FlowObservation] = {}
    for rec in records:
        if stats:
            stats.records_in += 1
        if not isinstance(rec, dict):
            if stats:
                stats.record_drop("non_dict_record")
            continue
        if str(rec.get("action", "")).upper() != "ACCEPT":
            if stats:
                stats.record_drop("non_accepted_action")
            continue
        src_ip = str(rec.get("src_ip") or "").strip()
        dst_ip = str(rec.get("dst_ip") or "").strip()
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
        try:
            port = int(rec["dst_port"]) if rec.get("dst_port") is not None else None
            ts = parse_ts(rec.get("timestamp", 0))
        except (ValueError, TypeError):
            if stats:
                stats.record_drop("malformed_field")
            continue
        proto = str(rec.get("protocol") or "TCP").upper()
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
                origin=ORIGIN,
            )
        else:
            obs.count += 1
            obs.first_seen = min(obs.first_seen, ts) if ts else obs.first_seen
            obs.last_seen = max(obs.last_seen, ts)

    observations = validate_observations(list(agg.values()), stats=stats)
    if stats:
        stats.observations_out = len(observations)
    return observations


class SkeletonCollector:
    """Example collector implementing the ``collect() -> CollectorResult`` contract."""

    origin = ORIGIN

    def __init__(
        self,
        records_provider,
        *,
        resolver: IdentityResolver | None = None,
        checkpoint_store: CheckpointStore | None = None,
        source_id: str = ORIGIN,
    ) -> None:
        self._provider = records_provider
        self._resolver = resolver
        self._checkpoints = checkpoint_store
        self._source_id = source_id

    def collect(self) -> CollectorResult:
        t0 = time.perf_counter()
        stats = CollectorStats(origin=self.origin, live=False)
        cursor = (
            self._checkpoints.get(self._source_id).get("cursor", 0)
            if self._checkpoints
            else 0
        )
        raw_records, next_cursor = self._provider(cursor)
        observations = parse_skeleton_records(
            raw_records, self._resolver, stats=stats
        )
        if self._checkpoints is not None:
            self._checkpoints.set(self._source_id, {"cursor": next_cursor})
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return CollectorResult(
            origin=self.origin,
            observations=observations,
            stats=stats,
        )
