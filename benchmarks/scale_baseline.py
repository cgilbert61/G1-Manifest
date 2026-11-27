"""Item 0 — Empirical scale baseline for G1-Manifest (5,000 and 50,000 edges).

Generates deterministic synthetic estates and measures wall time, peak memory
(tracemalloc), graph/envelope/HTML byte sizes across:
  aggregate -> reconcile -> sign -> verify -> render

Run: python benchmarks/scale_baseline.py
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from estate_graph.aggregate import aggregate
from estate_graph.model import FlowObservation, ServiceNode
from estate_graph.reconcile import reconcile
from estate_graph.render import render_html
from estate_graph.sign import (
    envelope_to_json,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_graph,
)
from estate_graph.sources.declared import DeclaredModel
from estate_graph.verify import verify_envelope

BASE_TS = 1795716000


def generate_synthetic_estate(
    target_edges: int, *, num_services: int = 250
) -> tuple[list[FlowObservation], DeclaredModel]:
    """Deterministically generate `target_edges` unique network observations."""
    nodes = [
        ServiceNode(id=f"svc-{i:04d}", kind="service", substrate="synthetic")
        for i in range(num_services)
    ]
    declared = DeclaredModel(nodes=nodes)
    observations: list[FlowObservation] = []
    ports = (443, 8443, 5432, 6379, 9092, 8080)

    count = 0
    for s in range(num_services):
        src = f"svc-{s:04d}"
        for step in range(1, num_services):
            if count >= target_edges:
                break
            t = (s + step) % num_services
            # 5% external unknown endpoints to exercise observed_undeclared
            if count % 20 == 0:
                dst = f"ip:203.0.113.{(count % 250) + 1}"
            else:
                dst = f"svc-{t:04d}"
                if count % 10 != 0:
                    declared.pairs.add((src, dst))
            port = ports[count % len(ports)]
            observations.append(
                FlowObservation(
                    source=src,
                    target=dst,
                    port=port,
                    protocol="TCP",
                    count=(count % 50) + 1,
                    first_seen=BASE_TS - 3600,
                    last_seen=BASE_TS,
                    origin="synthetic-flow",
                )
            )
            count += 1
        if count >= target_edges:
            break
    return observations, declared


def measure_stage(fn):
    tracemalloc.start()
    t0 = time.perf_counter()
    result = fn()
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    _curr, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, round(elapsed_ms, 2), round(peak / (1024 * 1024), 2)


def run_scale_case(target_edges: int, num_services: int, *, render_limit: int = 50000) -> dict:
    observations, declared = generate_synthetic_estate(
        target_edges, num_services=num_services
    )
    stages: dict[str, dict] = {}

    graph, ms, mb = measure_stage(
        lambda: aggregate(
            observations,
            declared_nodes=declared.nodes,
            issued_at=BASE_TS,
            ttl_seconds=86400,
        )
    )
    stages["aggregate"] = {"wall_ms": ms, "peak_mem_mb": mb}

    report, ms, mb = measure_stage(lambda: reconcile(graph, declared))
    stages["reconcile"] = {"wall_ms": ms, "peak_mem_mb": mb}

    with tempfile.TemporaryDirectory() as tmp:
        priv_path, pub_path = generate_keypair(tmp)
        priv = load_private_key(priv_path)
        pub = load_public_key(pub_path)

        envelope, ms, mb = measure_stage(
            lambda: sign_graph(graph, priv, ttl_seconds=86400)
        )
        stages["sign"] = {"wall_ms": ms, "peak_mem_mb": mb}

        verified, ms, mb = measure_stage(
            lambda: verify_envelope(envelope, pub, now=BASE_TS + 60)
        )
        stages["verify"] = {"wall_ms": ms, "peak_mem_mb": mb}

    graph_bytes = len(graph.canonical_json())
    envelope_bytes = len(envelope_to_json(envelope).encode("utf-8"))

    if len(graph.edges) <= render_limit:
        html_doc, ms, mb = measure_stage(
            lambda: render_html(verified, reconcile_report=report)
        )
        stages["render"] = {
            "wall_ms": ms,
            "peak_mem_mb": mb,
            "html_bytes": len(html_doc.encode("utf-8")),
        }
    else:
        stages["render"] = {
            "wall_ms": None,
            "peak_mem_mb": None,
            "note": f"Skipped above render_limit={render_limit}",
        }

    return {
        "target_edges": target_edges,
        "actual_nodes": len(graph.nodes),
        "actual_edges": len(graph.edges),
        "reconcile_summary": report["summary"],
        "graph_canonical_bytes": graph_bytes,
        "envelope_json_bytes": envelope_bytes,
        "stages": stages,
    }


def main() -> int:
    results = {
        "control_5k": run_scale_case(5000, num_services=100),
        "scale_50k": run_scale_case(50000, num_services=260),
    }
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
