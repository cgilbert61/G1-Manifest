"""Comprehensive tests for the Interactive WebGL Explorer (Items 1-4 + acceptance checks)."""

from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from estate_graph.cli import DEMO_DIR, DEMO_ISSUED_AT, build_graph, main as cli_main
from estate_graph.explorer import (
    build_diff_view,
    build_ego_view,
    build_findings_view,
    build_zoom_view,
    load_verified_or_expired,
    render_explorer_html,
    search_nodes,
)
from estate_graph.model import (
    LAYER_LINEAGE,
    LAYER_NETWORK,
    DependencyGraph,
    Edge,
    Evidence,
    ServiceNode,
)
from http.server import ThreadingHTTPServer
from estate_graph.serve import make_handler
from estate_graph.sign import generate_keypair, load_private_key, load_public_key, sign_graph
from estate_graph.sources.declared import DeclaredModel
from estate_graph.verify import BadSignature


@pytest.fixture()
def demo_pair(tmp_path: Path):
    priv_p, pub_p = generate_keypair(tmp_path)
    priv = load_private_key(priv_p)
    pub = load_public_key(pub_p)

    graph_a, declared = build_graph(
        DEMO_DIR / "declared_model.json",
        [DEMO_DIR / "vpc_flow_logs.txt"],
        [DEMO_DIR / "hubble.jsonl"],
        [DEMO_DIR / "lineage.json"],
        issued_at=DEMO_ISSUED_AT,
    )
    graph_a.sequence = 1
    env_a = sign_graph(graph_a, priv, ttl_seconds=86400)

    # Successive envelope B with EXACTLY ONE planted change (1 new node + 1 new edge)
    graph_b, _ = build_graph(
        DEMO_DIR / "declared_model.json",
        [DEMO_DIR / "vpc_flow_logs.txt"],
        [DEMO_DIR / "hubble.jsonl"],
        [DEMO_DIR / "lineage.json"],
        issued_at=DEMO_ISSUED_AT + 300,
    )
    graph_b.sequence = 2
    graph_b.nodes.append(
        ServiceNode(
            id="fraud-scorer",
            kind="service",
            substrate="kubernetes",
            labels={"namespace": "payments", "tier": "risk"},
        )
    )
    graph_b.edges.append(
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
    env_b = sign_graph(graph_b, priv, ttl_seconds=86400)
    return {
        "priv": priv,
        "pub": pub,
        "priv_path": priv_p,
        "pub_path": pub_p,
        "graph_a": graph_a,
        "graph_b": graph_b,
        "env_a": env_a,
        "env_b": env_b,
        "declared": declared,
        "now": DEMO_ISSUED_AT + 600,
    }


def _tamper(envelope: dict) -> dict:
    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload["producer"] = "mallory"
    return dict(
        envelope,
        payload=base64.b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii"),
    )


# ---------------------------------------------------------------------------
# Item 1 — Diff View
# ---------------------------------------------------------------------------


def test_diff_view_exact_one_planted_change(demo_pair):
    diff = build_diff_view(
        demo_pair["env_a"],
        demo_pair["env_b"],
        demo_pair["pub"],
        now=demo_pair["now"],
    )
    assert diff["view"] == "diff"
    assert diff["proof"]["status"] == "verified"
    assert diff["proof"]["envelope_id_a"] != diff["proof"]["envelope_id_b"]
    assert ":seq1:" in diff["proof"]["envelope_id_a"]
    assert ":seq2:" in diff["proof"]["envelope_id_b"]

    # Exact delta: 1 added node, 1 added edge, 0 removed, 0 changed — no more, no less
    s = diff["summary"]
    assert s["added_nodes"] == 1
    assert s["removed_nodes"] == 0
    assert s["added_edges"] == 1
    assert s["removed_edges"] == 0
    assert s["changed_edges"] == 0
    assert s["total_delta_edges"] == 1
    assert s["total_delta_nodes"] == 2  # checkout-api (context) + fraud-scorer (added)

    assert diff["delta"]["added_nodes"][0]["id"] == "fraud-scorer"
    assert diff["delta"]["added_edges"][0]["source"] == "checkout-api"
    assert diff["delta"]["added_edges"][0]["target"] == "fraud-scorer"


def test_diff_view_detects_changed_and_removed_edges(demo_pair):
    g_a = DependencyGraph.from_dict(demo_pair["graph_a"].to_dict())
    g_b = DependencyGraph.from_dict(demo_pair["graph_a"].to_dict())
    g_b.sequence = 3
    # Modify evidence on first edge and remove last edge
    g_b.edges[0].evidence.flow_count += 25
    removed_edge = g_b.edges.pop()

    env_a = sign_graph(g_a, demo_pair["priv"], ttl_seconds=86400)
    env_b = sign_graph(g_b, demo_pair["priv"], ttl_seconds=86400)
    diff = build_diff_view(env_a, env_b, demo_pair["pub"], now=demo_pair["now"])

    assert diff["summary"]["changed_edges"] == 1
    assert diff["delta"]["changed_edges"][0]["flow_delta"] == 25
    assert diff["summary"]["removed_edges"] == 1
    assert diff["delta"]["removed_edges"][0]["source"] == removed_edge.source
    assert diff["delta"]["removed_edges"][0]["target"] == removed_edge.target


def test_diff_view_refuses_tampered_envelope(demo_pair):
    bad_b = _tamper(demo_pair["env_b"])
    with pytest.raises(BadSignature):
        build_diff_view(demo_pair["env_a"], bad_b, demo_pair["pub"], now=demo_pair["now"])

    bad_a = _tamper(demo_pair["env_a"])
    with pytest.raises(BadSignature):
        build_diff_view(bad_a, demo_pair["env_b"], demo_pair["pub"], now=demo_pair["now"])


# ---------------------------------------------------------------------------
# Item 2 — Ego View
# ---------------------------------------------------------------------------


def test_ego_view_rings_direction_and_blast_radius(demo_pair):
    graph, proof = load_verified_or_expired(
        demo_pair["env_b"], demo_pair["pub"], now=demo_pair["now"]
    )
    matches = search_nodes(graph, "checkout")
    assert matches and matches[0]["id"] == "checkout-api"

    ego1 = build_ego_view(graph, proof, "checkout-api", rings=1)
    assert ego1["view"] == "ego"
    assert ego1["proof"]["status"] == "verified"
    assert ego1["rings"] == 1
    assert all(n["ring"] <= 1 for n in ego1["graph"]["nodes"])
    assert all(
        e["direction"] in ("upstream", "downstream", "lateral")
        for e in ego1["graph"]["edges"]
    )
    assert ego1["blast_radius"]["by_ring"]["1"] >= 1
    assert ego1["blast_radius"]["total_downstream"] >= 1

    ego2 = build_ego_view(graph, proof, "checkout-api", rings=2)
    assert ego2["rings"] == 2
    assert len(ego2["graph"]["nodes"]) >= len(ego1["graph"]["nodes"])


# ---------------------------------------------------------------------------
# Item 3 — Findings-First View
# ---------------------------------------------------------------------------


def test_findings_first_view_focus_and_pin(demo_pair):
    graph, proof = load_verified_or_expired(
        demo_pair["env_a"], demo_pair["pub"], now=demo_pair["now"]
    )
    fv = build_findings_view(graph, proof, demo_pair["declared"], selected_index=0)
    assert fv["view"] == "findings"
    assert fv["proof"]["status"] == "verified"
    assert len(fv["findings"]) >= 1
    assert fv["pinned_finding"] is not None
    types = {f["finding_type"] for f in fv["findings"]}
    assert "observed_undeclared" in types
    assert "declared_unobserved" in types

    # Focused subgraph contains source and target of pinned finding
    node_ids = {n["id"] for n in fv["graph"]["nodes"]}
    assert fv["pinned_finding"]["source"] in node_ids
    assert fv["pinned_finding"]["target"] in node_ids

    # Selecting another finding switches the pinned finding
    if len(fv["findings"]) > 1:
        fv2 = build_findings_view(graph, proof, demo_pair["declared"], selected_index=1)
        assert fv2["pinned_finding"]["index"] == 1


# ---------------------------------------------------------------------------
# Item 4 — Zoom Levels
# ---------------------------------------------------------------------------


def test_zoom_levels_rollup_expand_and_collapse(demo_pair):
    graph, proof = load_verified_or_expired(
        demo_pair["env_b"], demo_pair["pub"], now=demo_pair["now"]
    )
    z_estate = build_zoom_view(graph, proof, level="estate", group_by="substrate")
    assert z_estate["level"] == "estate"
    assert z_estate["summary"]["group_nodes"] >= 1
    assert z_estate["summary"]["total_rolled_flows"] > 0

    first_group = z_estate["graph"]["nodes"][0]["id"]
    z_seg = build_zoom_view(
        graph, proof, level="segment", parent_group=first_group, group_by="substrate"
    )
    assert z_seg["level"] == "segment"
    assert z_seg["parent_group"] == first_group
    assert z_seg["navigation"]["parent_level"] == "estate"

    # Collapse back to estate
    z_back = build_zoom_view(
        graph,
        proof,
        level=z_seg["navigation"]["parent_level"],
        parent_group=z_seg["navigation"]["grandparent_group"],
        group_by="substrate",
    )
    assert z_back["level"] == "estate"
    assert z_back["summary"]["group_nodes"] == z_estate["summary"]["group_nodes"]


# ---------------------------------------------------------------------------
# Filters + Expired-Envelope Check across ALL 4 views
# ---------------------------------------------------------------------------


def test_filters_layer_time_and_min_flow(demo_pair):
    graph, proof = load_verified_or_expired(
        demo_pair["env_b"], demo_pair["pub"], now=demo_pair["now"]
    )
    z_net = build_zoom_view(graph, proof, level="instance", layers=[LAYER_NETWORK])
    assert all(e["layer"] == LAYER_NETWORK for e in z_net["graph"]["edges"])

    z_lin = build_zoom_view(graph, proof, level="instance", layers=[LAYER_LINEAGE])
    assert all(e["layer"] == LAYER_LINEAGE for e in z_lin["graph"]["edges"])

    z_hi = build_zoom_view(graph, proof, level="instance", min_flow_count=999999)
    assert len(z_hi["graph"]["edges"]) == 0


def test_expired_envelope_marked_expired_in_every_view(demo_pair):
    # Past the 86400s TTL
    expired_now = DEMO_ISSUED_AT + 200000

    diff = build_diff_view(
        demo_pair["env_a"], demo_pair["env_b"], demo_pair["pub"], now=expired_now
    )
    assert diff["proof"]["status"] == "expired"

    graph, proof = load_verified_or_expired(
        demo_pair["env_b"], demo_pair["pub"], now=expired_now
    )
    assert proof["status"] == "expired"

    ego = build_ego_view(graph, proof, "checkout-api", rings=1)
    assert ego["proof"]["status"] == "expired"

    findings = build_findings_view(graph, proof, demo_pair["declared"])
    assert findings["proof"]["status"] == "expired"

    zoom = build_zoom_view(graph, proof, level="estate")
    assert zoom["proof"]["status"] == "expired"

    html_doc = render_explorer_html(
        initial_data={"diff": diff, "ego": ego, "findings": findings, "zoom": zoom}
    )
    assert "badge-expired" in html_doc
    assert "EXPIRED" in html_doc


# ---------------------------------------------------------------------------
# HTTP Server (/explorer & /api/explorer/*) + CLI (`explore`)
# ---------------------------------------------------------------------------


def test_explorer_http_endpoints_and_cli(demo_pair, tmp_path: Path):
    views_dir = tmp_path / "views"
    keys_dir = tmp_path / "keys"
    views_dir.mkdir()
    keys_dir.mkdir()

    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(views_dir, keys_dir=keys_dir, require_auth=False),
    )
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}"
        with urllib.request.urlopen(f"{base}/explorer") as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "G1-Manifest Explorer" in body
            assert "gl-canvas" in body

        with urllib.request.urlopen(f"{base}/api/explorer/demo") as resp:
            meta = json.loads(resp.read().decode("utf-8"))
            assert meta["ok"] is True
            assert meta["envelope_id_a"] != meta["envelope_id_b"]

        for route, payload in [
            ("/api/explorer/diff", {"use_demo": True}),
            ("/api/explorer/ego", {"use_demo": True, "center_node": "checkout-api", "rings": 1}),
            ("/api/explorer/findings", {"use_demo": True, "selected_index": 0}),
            ("/api/explorer/zoom", {"use_demo": True, "level": "estate"}),
        ]:
            req = urllib.request.Request(
                f"{base}{route}",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                assert data["ok"] is True
                assert data["result"]["proof"]["status"] == "verified"

        # Stored scan envelopes: run demo scan -> persisted -> listed -> downloadable -> queryable
        demo_req = urllib.request.Request(
            f"{base}/api/scan/demo",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(demo_req) as resp:
            demo_res = json.loads(resp.read().decode("utf-8"))
            assert demo_res["ok"] is True
            assert any(v.get("has_envelope") for v in demo_res["views"])

        with urllib.request.urlopen(f"{base}/api/explorer/envelopes") as resp:
            env_list = json.loads(resp.read().decode("utf-8"))
            assert env_list["ok"] is True
            ids = [e["id"] for e in env_list["envelopes"]]
            assert "demo_view" in ids

        with urllib.request.urlopen(
            f"{base}/api/explorer/envelopes/demo_view.envelope.json"
        ) as resp:
            raw_env = json.loads(resp.read().decode("utf-8"))
            assert "payload" in raw_env and "signatures" in raw_env

        stored_req = urllib.request.Request(
            f"{base}/api/explorer/zoom",
            data=json.dumps({"envelope_name": "demo_view", "level": "estate"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(stored_req) as resp:
            zdata = json.loads(resp.read().decode("utf-8"))
            assert zdata["ok"] is True
            assert zdata["result"]["proof"]["status"] == "verified"

        # Forged envelope must return 400
        bad_req = urllib.request.Request(
            f"{base}/api/explorer/diff",
            data=json.dumps(
                {
                    "use_demo": False,
                    "envelope_a": demo_pair["env_a"],
                    "envelope_b": _tamper(demo_pair["env_b"]),
                    "pub_pem": demo_pair["pub_path"].read_text(encoding="utf-8"),
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_req)
        assert exc_info.value.code == 400
    finally:
        server.shutdown()
        server.server_close()

    # CLI `explore` subcommand
    env_a_p = tmp_path / "env_a.json"
    env_b_p = tmp_path / "env_b.json"
    out_html = tmp_path / "standalone_explorer.html"
    env_a_p.write_text(json.dumps(demo_pair["env_a"]), encoding="utf-8")
    env_b_p.write_text(json.dumps(demo_pair["env_b"]), encoding="utf-8")
    rc = cli_main(
        [
            "explore",
            "--envelope",
            str(env_a_p),
            "--envelope-b",
            str(env_b_p),
            "--pub",
            str(demo_pair["pub_path"]),
            "--declared",
            str(DEMO_DIR / "declared_model.json"),
            "--now",
            str(demo_pair["now"]),
            "--out",
            str(out_html),
        ]
    )
    assert rc == 0
    assert out_html.is_file()
    assert "G1-Manifest Explorer" in out_html.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 10,000-node Synthetic Estate Scale Check
# ---------------------------------------------------------------------------


def test_explorer_handles_10000_node_estate(tmp_path: Path):
    priv_p, pub_p = generate_keypair(tmp_path)
    priv = load_private_key(priv_p)
    pub = load_public_key(pub_p)
    now = 1795800000

    substrates = ("aws", "kubernetes", "azure", "onprem")
    namespaces = ("core", "payments", "analytics", "edge", "identity")
    nodes = [
        ServiceNode(
            id=f"svc-{i:05d}",
            kind="service",
            substrate=substrates[i % len(substrates)],
            labels={"namespace": namespaces[(i // 4) % len(namespaces)]},
        )
        for i in range(10000)
    ]
    edges = [
        Edge(
            source=f"svc-{i:05d}",
            target=f"svc-{(i + 1) % 10000:05d}",
            port=443,
            protocol="tcp",
            layer=LAYER_NETWORK,
            evidence=Evidence(
                flow_count=10 + (i % 50),
                first_seen=now - 3600,
                last_seen=now,
                sources=["hubble"],
            ),
        )
        for i in range(10000)
    ]
    g_a = DependencyGraph(
        graph_id="synthetic-10k",
        issued_at=now,
        expires_at=now + 86400,
        producer="g1-manifest-bench",
        sequence=1,
        nodes=nodes,
        edges=edges,
    )
    env_a = sign_graph(g_a, priv, ttl_seconds=86400)

    # Envelope B adds 1 planted edge on top of 10,000 nodes
    g_b = DependencyGraph(
        graph_id="synthetic-10k",
        issued_at=now + 60,
        expires_at=now + 86460,
        producer="g1-manifest-bench",
        sequence=2,
        nodes=list(nodes),
        edges=list(edges)
        + [
            Edge(
                source="svc-00000",
                target="svc-05000",
                port=8443,
                protocol="tcp",
                layer=LAYER_NETWORK,
                evidence=Evidence(flow_count=3, first_seen=now, last_seen=now + 60, sources=["hubble"]),
            )
        ],
    )
    env_b = sign_graph(g_b, priv, ttl_seconds=86400)

    diff = build_diff_view(env_a, env_b, pub, now=now + 120)
    assert diff["summary"]["added_edges"] == 1
    assert diff["summary"]["total_delta_nodes"] == 2

    graph_b, proof_b = load_verified_or_expired(env_b, pub, now=now + 120)
    ego = build_ego_view(graph_b, proof_b, "svc-00000", rings=1)
    assert len(ego["graph"]["nodes"]) <= 5  # bounded, never renders 10,000 nodes

    declared = DeclaredModel(nodes=[], pairs={("svc-00000", "svc-00001")}, ip_to_service={})
    findings = build_findings_view(graph_b, proof_b, declared, selected_index=0)
    assert len(findings["graph"]["nodes"]) <= 10  # focused subgraph only

    zoom = build_zoom_view(graph_b, proof_b, level="estate", group_by="substrate")
    assert zoom["summary"]["group_nodes"] == 4
    assert zoom["summary"]["total_estate_nodes"] == 10000
