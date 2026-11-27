"""Empirical acceptance benchmark for the Interactive WebGL Explorer.

Runs:
1. Demo estate across all 4 views (Diff with 1 planted change, Ego, Findings, Zoom)
2. 10,000-node synthetic estate across all 4 views with wall-clock timings
3. Expired-envelope check across all 4 views
4. Tampered-envelope refusal check

Prints a structured JSON summary for recording in docs/EXPLORER-RUNS.md.
"""

from __future__ import annotations

import base64
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from estate_graph.cli import DEMO_DIR, DEMO_ISSUED_AT, build_graph
from estate_graph.explorer import (
    build_diff_view,
    build_ego_view,
    build_findings_view,
    build_zoom_view,
    load_verified_or_expired,
    render_explorer_html,
)
from estate_graph.model import (
    LAYER_NETWORK,
    DependencyGraph,
    Edge,
    Evidence,
    ServiceNode,
)
from estate_graph.sign import generate_keypair, load_private_key, load_public_key, sign_graph
from estate_graph.sources.declared import DeclaredModel
from estate_graph.verify import BadSignature


def run_acceptance() -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        priv_p, pub_p = generate_keypair(Path(tmp))
        priv = load_private_key(priv_p)
        pub = load_public_key(pub_p)

        # 1. Demo estate + 1 planted change
        demo_a, declared = build_graph(
            DEMO_DIR / "declared_model.json",
            [DEMO_DIR / "vpc_flow_logs.txt"],
            [DEMO_DIR / "hubble.jsonl"],
            [DEMO_DIR / "lineage.json"],
            issued_at=DEMO_ISSUED_AT,
        )
        demo_a.sequence = 1
        env_demo_a = sign_graph(demo_a, priv, ttl_seconds=86400)

        demo_b, _ = build_graph(
            DEMO_DIR / "declared_model.json",
            [DEMO_DIR / "vpc_flow_logs.txt"],
            [DEMO_DIR / "hubble.jsonl"],
            [DEMO_DIR / "lineage.json"],
            issued_at=DEMO_ISSUED_AT + 300,
        )
        demo_b.sequence = 2
        demo_b.nodes.append(
            ServiceNode(
                id="fraud-scorer",
                kind="service",
                substrate="kubernetes",
                labels={"namespace": "payments", "tier": "risk"},
            )
        )
        demo_b.edges.append(
            Edge(
                source="checkout-api",
                target="fraud-scorer",
                port=443,
                protocol="tcp",
                layer=LAYER_NETWORK,
                evidence=Evidence(
                    flow_count=14,
                    first_seen=DEMO_ISSUED_AT + 100,
                    last_seen=DEMO_ISSUED_AT + 290,
                    sources=["hubble"],
                ),
            )
        )
        env_demo_b = sign_graph(demo_b, priv, ttl_seconds=86400)
        now_demo = DEMO_ISSUED_AT + 600

        demo_diff = build_diff_view(env_demo_a, env_demo_b, pub, now=now_demo)
        g_demo_b, p_demo_b = load_verified_or_expired(env_demo_b, pub, now=now_demo)
        demo_ego = build_ego_view(g_demo_b, p_demo_b, "checkout-api", rings=1)
        demo_findings = build_findings_view(g_demo_b, p_demo_b, declared, selected_index=0)
        demo_zoom = build_zoom_view(g_demo_b, p_demo_b, level="estate", group_by="substrate")

        # 2. Expired-envelope check across all 4 views
        expired_now = DEMO_ISSUED_AT + 200000
        exp_diff = build_diff_view(env_demo_a, env_demo_b, pub, now=expired_now)
        g_exp, p_exp = load_verified_or_expired(env_demo_b, pub, now=expired_now)
        exp_ego = build_ego_view(g_exp, p_exp, "checkout-api", rings=1)
        exp_findings = build_findings_view(g_exp, p_exp, declared, selected_index=0)
        exp_zoom = build_zoom_view(g_exp, p_exp, level="estate", group_by="substrate")

        # 3. Tampered-envelope refusal check
        payload = json.loads(base64.b64decode(env_demo_b["payload"]))
        payload["producer"] = "mallory"
        tampered = dict(
            env_demo_b,
            payload=base64.b64encode(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).decode("ascii"),
        )
        tamper_refused = False
        try:
            build_diff_view(env_demo_a, tampered, pub, now=now_demo)
        except BadSignature:
            tamper_refused = True

        # 4. 10,000-node synthetic estate (10,000 nodes, 20,000 edges)
        t_gen = time.perf_counter()
        now_10k = 1795800000
        substrates = ("aws", "kubernetes", "azure", "onprem")
        namespaces = ("core", "payments", "analytics", "edge", "identity")
        nodes_10k = [
            ServiceNode(
                id=f"svc-{i:05d}",
                kind="service",
                substrate=substrates[i % len(substrates)],
                labels={"namespace": namespaces[(i // 4) % len(namespaces)]},
            )
            for i in range(10000)
        ]
        edges_10k = []
        for i in range(10000):
            edges_10k.append(
                Edge(
                    source=f"svc-{i:05d}",
                    target=f"svc-{(i + 1) % 10000:05d}",
                    port=443,
                    protocol="tcp",
                    layer=LAYER_NETWORK,
                    evidence=Evidence(
                        flow_count=10 + (i % 50),
                        first_seen=now_10k - 3600,
                        last_seen=now_10k,
                        sources=["hubble"],
                    ),
                )
            )
            edges_10k.append(
                Edge(
                    source=f"svc-{i:05d}",
                    target=f"svc-{(i + 97) % 10000:05d}",
                    port=8443,
                    protocol="tcp",
                    layer=LAYER_NETWORK,
                    evidence=Evidence(
                        flow_count=5 + (i % 20),
                        first_seen=now_10k - 1800,
                        last_seen=now_10k,
                        sources=["vpc-flow"],
                    ),
                )
            )
        g_10k_a = DependencyGraph(
            graph_id="synthetic-10k-estate",
            issued_at=now_10k,
            expires_at=now_10k + 86400,
            producer="g1-manifest-bench",
            sequence=1,
            nodes=nodes_10k,
            edges=edges_10k,
        )
        env_10k_a = sign_graph(g_10k_a, priv, ttl_seconds=86400)

        g_10k_b = DependencyGraph(
            graph_id="synthetic-10k-estate",
            issued_at=now_10k + 60,
            expires_at=now_10k + 86460,
            producer="g1-manifest-bench",
            sequence=2,
            nodes=list(nodes_10k),
            edges=list(edges_10k)
            + [
                Edge(
                    source="svc-00000",
                    target="svc-05000",
                    port=9443,
                    protocol="tcp",
                    layer=LAYER_NETWORK,
                    evidence=Evidence(
                        flow_count=7,
                        first_seen=now_10k,
                        last_seen=now_10k + 60,
                        sources=["hubble"],
                    ),
                )
            ],
        )
        env_10k_b = sign_graph(g_10k_b, priv, ttl_seconds=86400)
        gen_sign_ms = round((time.perf_counter() - t_gen) * 1000.0, 2)

        diff_10k = build_diff_view(env_10k_a, env_10k_b, pub, now=now_10k + 120)
        g_10k_v, p_10k_v = load_verified_or_expired(env_10k_b, pub, now=now_10k + 120)
        ego_10k = build_ego_view(g_10k_v, p_10k_v, "svc-00000", rings=1)
        declared_10k = DeclaredModel(
            nodes=[],
            pairs={(f"svc-{i:05d}", f"svc-{(i + 1) % 10000:05d}") for i in range(10000)},
            ip_to_service={},
        )
        findings_10k = build_findings_view(g_10k_v, p_10k_v, declared_10k, selected_index=0)
        zoom_10k = build_zoom_view(g_10k_v, p_10k_v, level="estate", group_by="substrate")
        html_10k = render_explorer_html(
            initial_data={
                "diff": diff_10k,
                "ego": ego_10k,
                "findings": findings_10k,
                "zoom": zoom_10k,
            }
        )

        return {
            "demo_estate": {
                "envelope_id_a": demo_diff["proof"]["envelope_id_a"],
                "envelope_id_b": demo_diff["proof"]["envelope_id_b"],
                "diff": {
                    "summary": demo_diff["summary"],
                    "timing_ms": demo_diff["timing_ms"],
                },
                "ego": {
                    "center": demo_ego["center"],
                    "nodes_rendered": len(demo_ego["graph"]["nodes"]),
                    "blast_radius": demo_ego["blast_radius"],
                    "timing_ms": demo_ego["timing_ms"],
                },
                "findings": {
                    "total_findings": len(demo_findings["findings"]),
                    "nodes_rendered": len(demo_findings["graph"]["nodes"]),
                    "timing_ms": demo_findings["timing_ms"],
                },
                "zoom": {
                    "level": demo_zoom["level"],
                    "group_nodes": demo_zoom["summary"]["group_nodes"],
                    "rolled_edges": demo_zoom["summary"]["rolled_edges"],
                    "timing_ms": demo_zoom["timing_ms"],
                },
            },
            "expired_check": {
                "diff": exp_diff["proof"]["status"],
                "ego": exp_ego["proof"]["status"],
                "findings": exp_findings["proof"]["status"],
                "zoom": exp_zoom["proof"]["status"],
            },
            "tamper_refused": tamper_refused,
            "synthetic_10k": {
                "nodes": 10000,
                "edges": 20001,
                "gen_and_sign_ms": gen_sign_ms,
                "envelope_id_a": diff_10k["proof"]["envelope_id_a"],
                "envelope_id_b": diff_10k["proof"]["envelope_id_b"],
                "diff": {
                    "summary": diff_10k["summary"],
                    "timing_ms": diff_10k["timing_ms"],
                },
                "ego": {
                    "nodes_rendered": len(ego_10k["graph"]["nodes"]),
                    "edges_rendered": len(ego_10k["graph"]["edges"]),
                    "blast_radius": ego_10k["blast_radius"],
                    "timing_ms": ego_10k["timing_ms"],
                },
                "findings": {
                    "total_findings": len(findings_10k["findings"]),
                    "nodes_rendered": len(findings_10k["graph"]["nodes"]),
                    "timing_ms": findings_10k["timing_ms"],
                },
                "zoom": {
                    "group_nodes": zoom_10k["summary"]["group_nodes"],
                    "rolled_edges": zoom_10k["summary"]["rolled_edges"],
                    "total_rolled_flows": zoom_10k["summary"]["total_rolled_flows"],
                    "timing_ms": zoom_10k["timing_ms"],
                },
                "standalone_html_bytes": len(html_10k.encode("utf-8")),
            },
        }


if __name__ == "__main__":
    print(json.dumps(run_acceptance(), indent=2))
