"""Empirical latency benchmark for G1-Manifest core operations.

Measures real wall-clock timings for build/aggregate, reconcile, Ed25519
DSSE sign, Ed25519 DSSE verify, and deterministic layered HTML render.
Never reports 0.0 ms for empty sample buckets.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from estate_graph.cli import DEMO_DIR, DEMO_ISSUED_AT, build_graph
from estate_graph.reconcile import reconcile
from estate_graph.render import render_html
from estate_graph.sign import generate_keypair, load_private_key, load_public_key, sign_graph
from estate_graph.verify import verify_envelope


def _percentile(samples_ms: list[float], pct: float) -> float | None:
    if not samples_ms:
        return None
    ordered = sorted(samples_ms)
    idx = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return round(ordered[idx], 3)


def run_benchmark(iterations: int = 50) -> dict:
    buckets: dict[str, list[float]] = {
        "build_ms": [],
        "reconcile_ms": [],
        "sign_ms": [],
        "verify_ms": [],
        "render_ms": [],
    }
    with tempfile.TemporaryDirectory() as tmp:
        priv_path, pub_path = generate_keypair(tmp)
        priv = load_private_key(priv_path)
        pub = load_public_key(pub_path)

        for _ in range(iterations):
            t0 = time.perf_counter()
            graph, declared = build_graph(
                DEMO_DIR / "declared_model.json",
                [DEMO_DIR / "vpc_flow_logs.txt"],
                [DEMO_DIR / "hubble.jsonl"],
                [DEMO_DIR / "lineage.json"],
                issued_at=DEMO_ISSUED_AT,
            )
            buckets["build_ms"].append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            report = reconcile(graph, declared)
            buckets["reconcile_ms"].append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            envelope = sign_graph(graph, priv, ttl_seconds=86400)
            buckets["sign_ms"].append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            verified = verify_envelope(envelope, pub, now=DEMO_ISSUED_AT + 60)
            buckets["verify_ms"].append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            render_html(verified, reconcile_report=report)
            buckets["render_ms"].append((time.perf_counter() - t0) * 1000.0)

    return {
        "iterations": iterations,
        "metrics": {
            name: {
                "samples": len(vals),
                "p50_ms": _percentile(vals, 50),
                "p95_ms": _percentile(vals, 95),
                "p99_ms": _percentile(vals, 99),
            }
            for name, vals in buckets.items()
        },
    }


if __name__ == "__main__":
    print(json.dumps(run_benchmark(), indent=2))
