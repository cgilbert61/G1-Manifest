"""Cloud live pull collectors (AWS S3/CloudWatch, Azure NSG, GCP VPC, Hubble live).

All cloud SDKs (``boto3``, ``azure-storage-blob``, ``google-cloud-storage``)
are imported lazily and remain optional extras so the core runtime stays
minimal and zero-CVE. Every collector supports an injectable client/stream
for deterministic offline testing and persists per-source checkpoints in
``CheckpointStore`` so overlapping pulls never double-count edges.
"""

from __future__ import annotations

import gzip
import time

from ..sources.cloud_flows import (
    ORIGIN_AZURE_NSG,
    ORIGIN_GCP_VPC,
    parse_azure_nsg_flow_logs,
    parse_gcp_vpc_flow_logs,
)
from ..sources.flowlog import parse_flow_logs
from ..sources.hubble import ORIGIN as ORIGIN_HUBBLE, parse_hubble
from .contract import (
    CheckpointStore,
    CollectorResult,
    CollectorStats,
    IdentityResolver,
    validate_observations,
)


def _maybe_gunzip(raw: bytes) -> str:
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw).decode("utf-8", errors="replace")
    return raw.decode("utf-8", errors="replace")


class AWSVPCFlowS3Collector:
    """Scheduled pull of AWS VPC Flow Logs from an S3 bucket (read-only)."""

    origin = "aws-vpc-s3"

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        *,
        s3_client=None,
        resolver: IdentityResolver | None = None,
        checkpoint_store: CheckpointStore | None = None,
        source_id: str | None = None,
        live: bool = False,
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix
        self._client = s3_client
        self._resolver = resolver
        self._checkpoints = checkpoint_store
        self._source_id = source_id or f"{self.origin}:{bucket}/{prefix}"
        self._live = live

    def _get_client(self):
        if self._client is not None:
            return self._client
        import boto3  # optional extra: pip install "g1-estate-graph[aws]"

        self._client = boto3.client("s3")
        self._live = True
        return self._client

    def collect(self) -> CollectorResult:
        t0 = time.perf_counter()
        stats = CollectorStats(origin=self.origin, live=self._live)
        client = self._get_client()
        ckpt = self._checkpoints.get(self._source_id) if self._checkpoints else {}
        seen_keys: set[str] = set(ckpt.get("seen_keys", []))

        resp = client.list_objects_v2(Bucket=self.bucket, Prefix=self.prefix)
        contents = sorted(resp.get("Contents") or [], key=lambda o: o["Key"])
        ip_map = self._resolver.as_ip_to_service() if self._resolver else {}
        all_obs = []

        for item in contents:
            key = item["Key"]
            if key in seen_keys:
                stats.record_drop("already_checkpointed")
                continue
            obj = client.get_object(Bucket=self.bucket, Key=key)
            raw = obj["Body"].read()
            text = _maybe_gunzip(raw if isinstance(raw, bytes) else str(raw).encode("utf-8"))
            stats.records_in += sum(1 for ln in text.splitlines() if ln.strip())
            parsed = parse_flow_logs(text, ip_map)
            for obs in parsed:
                obs.origin = self.origin
            all_obs.extend(parsed)
            seen_keys.add(key)

        if self._checkpoints is not None:
            self._checkpoints.set(
                self._source_id, {"seen_keys": sorted(seen_keys)[-5000:]}
            )
        observations = validate_observations(all_obs, stats=stats)
        stats.observations_out = len(observations)
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return CollectorResult(origin=self.origin, observations=observations, stats=stats)


class AWSVPCFlowCloudWatchCollector:
    """Scheduled pull of AWS VPC Flow Logs from CloudWatch Logs (read-only)."""

    origin = "aws-vpc-cwlogs"

    def __init__(
        self,
        log_group: str,
        *,
        logs_client=None,
        resolver: IdentityResolver | None = None,
        checkpoint_store: CheckpointStore | None = None,
        source_id: str | None = None,
        live: bool = False,
    ) -> None:
        self.log_group = log_group
        self._client = logs_client
        self._resolver = resolver
        self._checkpoints = checkpoint_store
        self._source_id = source_id or f"{self.origin}:{log_group}"
        self._live = live

    def _get_client(self):
        if self._client is not None:
            return self._client
        import boto3  # optional extra

        self._client = boto3.client("logs")
        self._live = True
        return self._client

    def collect(self) -> CollectorResult:
        t0 = time.perf_counter()
        stats = CollectorStats(origin=self.origin, live=self._live)
        client = self._get_client()
        ckpt = self._checkpoints.get(self._source_id) if self._checkpoints else {}
        start_time = int(ckpt.get("last_timestamp_ms", 0))
        seen_ids: set[str] = set(ckpt.get("seen_event_ids", []))

        resp = client.filter_log_events(
            logGroupName=self.log_group, startTime=start_time
        )
        lines: list[str] = []
        max_ts = start_time
        for ev in resp.get("events") or []:
            eid = str(ev.get("eventId") or "")
            if eid and eid in seen_ids:
                stats.record_drop("duplicate_event_id")
                continue
            stats.records_in += 1
            lines.append(str(ev.get("message") or ""))
            if eid:
                seen_ids.add(eid)
            ts = int(ev.get("timestamp") or 0)
            if ts > max_ts:
                max_ts = ts

        ip_map = self._resolver.as_ip_to_service() if self._resolver else {}
        parsed = parse_flow_logs("\n".join(lines), ip_map)
        for obs in parsed:
            obs.origin = self.origin
        if self._checkpoints is not None:
            self._checkpoints.set(
                self._source_id,
                {
                    "last_timestamp_ms": max_ts,
                    "seen_event_ids": sorted(seen_ids)[-5000:],
                },
            )
        observations = validate_observations(parsed, stats=stats)
        stats.observations_out = len(observations)
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return CollectorResult(origin=self.origin, observations=observations, stats=stats)


class AzureNSGFlowCollector:
    """Scheduled pull of Azure NSG Flow Logs from Azure Blob Storage (read-only)."""

    origin = ORIGIN_AZURE_NSG

    def __init__(
        self,
        container_name: str,
        *,
        container_client=None,
        resolver: IdentityResolver | None = None,
        checkpoint_store: CheckpointStore | None = None,
        source_id: str | None = None,
        live: bool = False,
    ) -> None:
        self.container_name = container_name
        self._client = container_client
        self._resolver = resolver
        self._checkpoints = checkpoint_store
        self._source_id = source_id or f"{self.origin}:{container_name}"
        self._live = live

    def collect(self) -> CollectorResult:
        t0 = time.perf_counter()
        stats = CollectorStats(origin=self.origin, live=self._live)
        if self._client is None:
            raise RuntimeError(
                "AzureNSGFlowCollector requires a configured container_client "
                "(install optional extra 'azure')"
            )
        ckpt = self._checkpoints.get(self._source_id) if self._checkpoints else {}
        seen_blobs: dict[str, str] = dict(ckpt.get("seen_blobs", {}))
        all_obs = []

        for blob in sorted(self._client.list_blobs(), key=lambda b: b["name"]):
            name = blob["name"]
            etag = str(blob.get("etag") or "")
            if seen_blobs.get(name) == etag:
                stats.record_drop("already_checkpointed")
                continue
            raw = self._client.download_blob(name)
            text = _maybe_gunzip(raw if isinstance(raw, bytes) else str(raw).encode("utf-8"))
            all_obs.extend(
                parse_azure_nsg_flow_logs(text, self._resolver, stats=stats)
            )
            seen_blobs[name] = etag

        if self._checkpoints is not None:
            self._checkpoints.set(self._source_id, {"seen_blobs": seen_blobs})
        observations = validate_observations(all_obs, stats=stats)
        stats.observations_out = len(observations)
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return CollectorResult(origin=self.origin, observations=observations, stats=stats)


class GCPVPCFlowCollector:
    """Scheduled pull of GCP VPC Flow Logs from a GCS export bucket (read-only)."""

    origin = ORIGIN_GCP_VPC

    def __init__(
        self,
        bucket_name: str,
        *,
        bucket_client=None,
        resolver: IdentityResolver | None = None,
        checkpoint_store: CheckpointStore | None = None,
        source_id: str | None = None,
        live: bool = False,
    ) -> None:
        self.bucket_name = bucket_name
        self._client = bucket_client
        self._resolver = resolver
        self._checkpoints = checkpoint_store
        self._source_id = source_id or f"{self.origin}:{bucket_name}"
        self._live = live

    def collect(self) -> CollectorResult:
        t0 = time.perf_counter()
        stats = CollectorStats(origin=self.origin, live=self._live)
        if self._client is None:
            raise RuntimeError(
                "GCPVPCFlowCollector requires a configured bucket_client "
                "(install optional extra 'gcp')"
            )
        ckpt = self._checkpoints.get(self._source_id) if self._checkpoints else {}
        seen_objects: dict[str, str] = dict(ckpt.get("seen_objects", {}))
        all_obs = []

        for obj in sorted(self._client.list_blobs(), key=lambda b: b["name"]):
            name = obj["name"]
            gen = str(obj.get("generation") or "")
            if seen_objects.get(name) == gen:
                stats.record_drop("already_checkpointed")
                continue
            raw = self._client.download_blob(name)
            text = _maybe_gunzip(raw if isinstance(raw, bytes) else str(raw).encode("utf-8"))
            all_obs.extend(parse_gcp_vpc_flow_logs(text, self._resolver, stats=stats))
            seen_objects[name] = gen

        if self._checkpoints is not None:
            self._checkpoints.set(self._source_id, {"seen_objects": seen_objects})
        observations = validate_observations(all_obs, stats=stats)
        stats.observations_out = len(observations)
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return CollectorResult(origin=self.origin, observations=observations, stats=stats)


class HubbleLiveCollector:
    """Subscribe to a Hubble Relay / observe JSONL stream reusing ``parse_hubble``."""

    origin = ORIGIN_HUBBLE

    def __init__(
        self,
        stream_provider,
        *,
        checkpoint_store: CheckpointStore | None = None,
        source_id: str = "hubble-live",
        live: bool = False,
    ) -> None:
        self._stream_provider = stream_provider
        self._checkpoints = checkpoint_store
        self._source_id = source_id
        self._live = live

    def collect(self) -> CollectorResult:
        t0 = time.perf_counter()
        stats = CollectorStats(origin=self.origin, live=self._live)
        ckpt = self._checkpoints.get(self._source_id) if self._checkpoints else {}
        cursor = ckpt.get("cursor")
        lines, next_cursor = self._stream_provider(cursor)
        stats.records_in = len(lines)
        observations = validate_observations(
            parse_hubble("\n".join(lines)), stats=stats
        )
        if self._checkpoints is not None and next_cursor is not None:
            self._checkpoints.set(self._source_id, {"cursor": next_cursor})
        stats.observations_out = len(observations)
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return CollectorResult(origin=self.origin, observations=observations, stats=stats)
