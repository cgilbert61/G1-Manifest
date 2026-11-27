"""Continuous / scheduled ingest runner (`estate-graph ingest`).

Runs configured collectors on a cycle strictly shorter than the graph TTL,
bumps ``sequence`` monotonically on every re-issue, isolates per-source
failures (quarantining dead or garbage sources loudly while still issuing from
healthy sources), reconciles against an optional declared model (file or
ServiceNow CMDB), signs the DSSEv1 Ed25519 envelope, and writes it atomically.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from ..aggregate import aggregate
from ..model import Edge, FlowObservation, ServiceNode, iso_utc
from ..reconcile import reconcile
from ..sign import (
    DEFAULT_TTL_SECONDS,
    envelope_to_json,
    load_private_key,
    sign_graph,
)
from ..sources.declared import DeclaredModel, load_declared
from .contract import (
    CheckpointStore,
    CollectorResult,
    IdentityResolver,
    validate_observations,
)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".env-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


class IngestRunner:
    """Orchestrates live collectors -> aggregate -> reconcile -> sign -> atomic emit."""

    def __init__(
        self,
        collectors: list,
        *,
        private_key,
        out_envelope: str | Path,
        checkpoint_store: CheckpointStore,
        declared: DeclaredModel | None = None,
        declared_loader=None,
        resolver: IdentityResolver | None = None,
        graph_id: str = "estate-graph",
        producer: str = "estate-graph/ingest",
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        reissue_interval_seconds: int = 3600,
        out_reconcile: str | Path | None = None,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if reissue_interval_seconds <= 0 or reissue_interval_seconds >= ttl_seconds:
            raise ValueError(
                f"reissue_interval_seconds ({reissue_interval_seconds}) must be "
                f"strictly shorter than ttl_seconds ({ttl_seconds})"
            )
        self.collectors = list(collectors)
        self._private_key = private_key
        self.out_envelope = Path(out_envelope)
        self.out_reconcile = Path(out_reconcile) if out_reconcile else None
        self.checkpoints = checkpoint_store
        self.declared = declared
        self._declared_loader = declared_loader
        self.resolver = resolver
        self.graph_id = graph_id
        self.producer = producer
        self.ttl_seconds = int(ttl_seconds)
        self.reissue_interval_seconds = int(reissue_interval_seconds)

        # Retained observations & lineage across cycles within the runner's lifetime
        self._observations: list[FlowObservation] = []
        self._extra_edges: list[Edge] = []
        self._extra_nodes: list[ServiceNode] = []

    def _next_sequence(self) -> int:
        state = self.checkpoints.get("_runner")
        seq = int(state.get("sequence", 0)) + 1
        self.checkpoints.set("_runner", {"sequence": seq})
        return seq

    def run_cycle(self, *, now: int | None = None) -> dict:
        """Execute one full collect -> aggregate -> reconcile -> sign cycle."""
        t0 = time.perf_counter()
        issued_at = int(now if now is not None else time.time())
        source_reports: list[dict] = []
        failed_sources: list[dict] = []

        for col in self.collectors:
            origin = getattr(col, "origin", type(col).__name__)
            try:
                res = col.collect()
                if not isinstance(res, CollectorResult):
                    raise TypeError(
                        f"collector {origin!r} returned {type(res).__name__}, "
                        "expected CollectorResult (quarantined)"
                    )
                clean_obs = validate_observations(res.observations, stats=res.stats)
                self._observations.extend(clean_obs)
                self._extra_edges.extend(res.extra_edges)
                self._extra_nodes.extend(res.extra_nodes)
                source_reports.append(res.stats.to_dict())
            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {exc}"
                failed_sources.append({"origin": origin, "error": err_msg})
                source_reports.append(
                    {"origin": origin, "status": "QUARANTINED", "error": err_msg}
                )

        declared = self.declared
        if self._declared_loader is not None:
            try:
                declared = self._declared_loader()
            except Exception as exc:
                failed_sources.append(
                    {"origin": "declared-loader", "error": f"{type(exc).__name__}: {exc}"}
                )

        extra_nodes = list(self._extra_nodes)
        if self.resolver is not None:
            extra_nodes.extend(self.resolver.provenance_nodes())

        seq = self._next_sequence()
        graph = aggregate(
            self._observations,
            declared_nodes=declared.nodes if declared else None,
            extra_edges=self._extra_edges,
            extra_nodes=extra_nodes,
            graph_id=self.graph_id,
            producer=self.producer,
            issued_at=issued_at,
            ttl_seconds=self.ttl_seconds,
            sequence=seq,
        )
        envelope = sign_graph(graph, self._private_key, ttl_seconds=self.ttl_seconds)
        _atomic_write_text(self.out_envelope, envelope_to_json(envelope))

        reconcile_summary = None
        if declared is not None:
            report = reconcile(graph, declared)
            reconcile_summary = report["summary"]
            if self.out_reconcile is not None:
                _atomic_write_text(
                    self.out_reconcile,
                    json.dumps(report, indent=2, sort_keys=True) + "\n",
                )

        return {
            "graph_id": graph.graph_id,
            "sequence": seq,
            "issued_at": issued_at,
            "expires_at": graph.expires_at,
            "expires_utc": iso_utc(graph.expires_at),
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "envelope_path": str(self.out_envelope),
            "reconcile_summary": reconcile_summary,
            "sources": source_reports,
            "failed_sources": failed_sources,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
        }

    def run(self, *, max_cycles: int = 0) -> list[dict]:
        """Run continuously (max_cycles=0) or for `max_cycles` iterations."""
        reports: list[dict] = []
        cycle = 0
        while max_cycles == 0 or cycle < max_cycles:
            reports.append(self.run_cycle())
            cycle += 1
            if max_cycles == 0 or cycle < max_cycles:
                time.sleep(self.reissue_interval_seconds)
        return reports


def build_runner_from_config(config_path: str | Path) -> tuple[IngestRunner, list]:
    """Instantiate an IngestRunner and its live collectors from a JSON config file."""
    from .cisco import CiscoCollector
    from .cloud import (
        AWSVPCFlowCloudWatchCollector,
        AWSVPCFlowS3Collector,
        AzureNSGFlowCollector,
        GCPVPCFlowCollector,
    )
    from .openlineage_http import OpenLineageHTTPCollector
    from .servicenow import ServiceNowCMDBCollector
    from .udp_flow import NetFlowUDPCollector, SFlowUDPCollector

    cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))
    key_env = str(cfg.get("private_key_env") or "G1_MANIFEST_PRIVATE_KEY_PATH")
    key_path = os.environ.get(key_env) or cfg.get("private_key_path")
    if not key_path:
        raise ValueError(
            f"Private key path required via env var {key_env!r} or config 'private_key_path'"
        )
    private_key = load_private_key(key_path)
    checkpoints = CheckpointStore(cfg.get("checkpoint_path", "state/checkpoints.json"))

    resolver = IdentityResolver()
    declared = None
    declared_loader = None
    if cfg.get("declared_path"):
        declared = load_declared(cfg["declared_path"])
        resolver.register_bulk(declared.ip_to_service, "declared")
    elif isinstance(cfg.get("servicenow"), dict):
        sn = cfg["servicenow"]
        sn_col = ServiceNowCMDBCollector(sn["instance_url"])
        declared_loader = sn_col.load_declared

    collectors = []
    startables = []
    for src in cfg.get("sources") or []:
        stype = str(src.get("type") or "").lower()
        if stype in ("netflow", "ipfix"):
            col = NetFlowUDPCollector(
                host=src.get("host", "127.0.0.1"),
                port=int(src.get("port", 2055)),
                resolver=resolver,
            )
            startables.append(col)
            collectors.append(col)
        elif stype == "sflow":
            col = SFlowUDPCollector(
                host=src.get("host", "127.0.0.1"),
                port=int(src.get("port", 6343)),
                resolver=resolver,
            )
            startables.append(col)
            collectors.append(col)
        elif stype == "openlineage-http":
            col = OpenLineageHTTPCollector(
                host=src.get("host", "127.0.0.1"),
                port=int(src.get("port", 5000)),
            )
            startables.append(col)
            collectors.append(col)
        elif stype == "aws-s3":
            collectors.append(
                AWSVPCFlowS3Collector(
                    bucket=src["bucket"],
                    prefix=src.get("prefix", ""),
                    resolver=resolver,
                    checkpoint_store=checkpoints,
                    source_id=src.get("id"),
                )
            )
        elif stype == "aws-cwlogs":
            collectors.append(
                AWSVPCFlowCloudWatchCollector(
                    log_group=src["log_group"],
                    resolver=resolver,
                    checkpoint_store=checkpoints,
                    source_id=src.get("id"),
                )
            )
        elif stype == "azure-nsg":
            collectors.append(
                AzureNSGFlowCollector(
                    container_name=src["container"],
                    resolver=resolver,
                    checkpoint_store=checkpoints,
                    source_id=src.get("id"),
                )
            )
        elif stype == "gcp-vpc":
            collectors.append(
                GCPVPCFlowCollector(
                    bucket_name=src["bucket"],
                    resolver=resolver,
                    checkpoint_store=checkpoints,
                    source_id=src.get("id"),
                )
            )
        elif stype == "cisco":
            collectors.append(
                CiscoCollector(
                    catalyst_url=src.get("catalyst_url"),
                    sna_flows_url=src.get("sna_flows_url"),
                    resolver=resolver,
                )
            )
        else:
            raise ValueError(f"unsupported source type: {stype!r}")

    runner = IngestRunner(
        collectors,
        private_key=private_key,
        out_envelope=cfg.get("output_envelope", "out/estate.envelope.json"),
        checkpoint_store=checkpoints,
        declared=declared,
        declared_loader=declared_loader,
        resolver=resolver,
        graph_id=cfg.get("graph_id", "estate-graph"),
        ttl_seconds=int(cfg.get("ttl_seconds", DEFAULT_TTL_SECONDS)),
        reissue_interval_seconds=int(cfg.get("reissue_interval_seconds", 3600)),
        out_reconcile=cfg.get("output_reconcile"),
    )
    return runner, startables
