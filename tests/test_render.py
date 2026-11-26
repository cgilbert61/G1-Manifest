"""The HTML witness page: badges, findings, escaping, determinism.

The page is a witness, not a console — these tests pin the properties
that make it one: the proof state is on the face of it, findings are
marked in the canvas and listed in the panel, a forged envelope gets
no witness, and the same graph renders the same bytes twice.
"""

import base64
import html as html_mod
import json
import re
import time
from pathlib import Path

import pytest

from estate_graph.aggregate import aggregate
from estate_graph.cli import main
from estate_graph.model import DependencyGraph, Edge, Evidence, ServiceNode
from estate_graph.reconcile import reconcile
from estate_graph.render import render_html
from estate_graph.sign import (
    envelope_to_json,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_graph,
)
from estate_graph.sources.flowlog import load_flow_logs
from estate_graph.sources.hubble import load_hubble

LICENSE_IP = "203.0.113.66"  # the demo estate's undeclared 2 a.m. flow


def _fresh_graph(demo_dir, declared, issued_at):
    observations = load_flow_logs(
        demo_dir / "vpc_flow_logs.txt", declared.ip_to_service
    ) + load_hubble(demo_dir / "hubble.jsonl")
    return aggregate(
        observations, declared_nodes=declared.nodes, issued_at=issued_at
    )


@pytest.fixture()
def keys(tmp_path):
    priv, pub = generate_keypair(tmp_path / "keys")
    return load_private_key(priv), load_public_key(pub), tmp_path / "keys"


def _write_envelope(graph, priv, path, ttl_seconds=86400):
    envelope = sign_graph(graph, priv, ttl_seconds=ttl_seconds)
    Path(path).write_text(envelope_to_json(envelope))
    return envelope


def test_render_contains_every_node_id(demo_graph):
    out = render_html(demo_graph)
    for node in demo_graph.nodes:
        assert html_mod.escape(node.id) in out


def test_render_marks_undeclared_finding(demo_graph, declared):
    out = render_html(demo_graph, reconcile_report=reconcile(demo_graph, declared))
    # The planted license-server flow is in the findings panel, in the
    # CLI's wording, and the edge itself is marked in the canvas.
    assert LICENSE_IP in out
    assert "FINDING" in out and "declared nowhere" in out
    assert 'data-status="observed_undeclared"' in out
    # The stale declaration is listed too.
    assert "declared but never observed" in out
    assert 'data-status="declared_unobserved"' in out


def test_render_unsigned_badge_for_raw_graph(demo_graph, tmp_path):
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps(demo_graph.to_dict()))
    out_path = tmp_path / "view.html"
    rc = main(
        [
            "render",
            "--graph",
            str(graph_path),
            "--out",
            str(out_path),
        ]
    )
    assert rc == 0
    assert "UNSIGNED" in out_path.read_text()


def test_render_verified_badge(demo_dir, declared, keys, tmp_path):
    priv, _pub, key_dir = keys
    graph = _fresh_graph(demo_dir, declared, int(time.time()))
    env_path = tmp_path / "envelope.json"
    _write_envelope(graph, priv, env_path)
    out_path = tmp_path / "view.html"
    rc = main(
        [
            "render",
            "--envelope",
            str(env_path),
            "--pub",
            str(key_dir / "public.pem"),
            "--declared",
            str(demo_dir / "declared_model.json"),
            "--out",
            str(out_path),
        ]
    )
    assert rc == 0
    page = out_path.read_text()
    assert "VERIFIED" in page and "badge-verified" in page
    assert LICENSE_IP in page  # reconcile ran against the verified graph


def test_render_expired_badge(demo_dir, declared, keys, tmp_path):
    priv, _pub, key_dir = keys
    graph = _fresh_graph(demo_dir, declared, int(time.time()) - 7200)
    env_path = tmp_path / "envelope.json"
    _write_envelope(graph, priv, env_path, ttl_seconds=3600)
    out_path = tmp_path / "view.html"
    rc = main(
        [
            "render",
            "--envelope",
            str(env_path),
            "--pub",
            str(key_dir / "public.pem"),
            "--out",
            str(out_path),
        ]
    )
    # Expired papers still get a witness — a red one. Acting on them is
    # the consumer's sin; hiding them would be ours.
    assert rc == 0
    page = out_path.read_text()
    assert "EXPIRED" in page and "badge-expired" in page


def test_render_refuses_tampered_envelope(demo_dir, declared, keys, tmp_path):
    priv, _pub, key_dir = keys
    graph = _fresh_graph(demo_dir, declared, int(time.time()))
    envelope = sign_graph(graph, priv)
    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload["producer"] = "mallory"
    envelope["payload"] = base64.b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    env_path = tmp_path / "envelope.json"
    env_path.write_text(envelope_to_json(envelope))
    out_path = tmp_path / "view.html"
    rc = main(
        [
            "render",
            "--envelope",
            str(env_path),
            "--pub",
            str(key_dir / "public.pem"),
            "--out",
            str(out_path),
        ]
    )
    assert rc != 0
    assert not out_path.exists()  # a forged graph gets no witness


def test_render_escapes_malicious_node_id():
    evil = "<script>alert(1)</script>"
    graph = DependencyGraph(
        graph_id="escape-test",
        producer="test",
        issued_at=1795716000,
        expires_at=1795716000 + 3600,
        nodes=[ServiceNode(id=evil), ServiceNode(id="plain-svc")],
        edges=[
            Edge(
                source=evil,
                target="plain-svc",
                port=443,
                evidence=Evidence(flow_count=5, first_seen=1, last_seen=2),
            )
        ],
    )
    out = render_html(graph)
    assert "<script>alert(1)</script>" not in out
    assert "&lt;script&gt;alert(1)" in out  # SVG label, HTML-escaped
    assert "\\u003cscript\\u003e" in out  # JSON blob, unicode-escaped


def test_render_is_deterministic(demo_graph, declared):
    report = reconcile(demo_graph, declared)
    once = render_html(demo_graph, reconcile_report=report)
    twice = render_html(demo_graph, reconcile_report=report)
    assert once == twice


# -- the layered layout --------------------------------------------------
# The first layout was a force-directed clump: nodes overlapped, labels
# clipped, and one arrowhead (scaled by stroke width) ate the canvas.
# These tests pin the replacement: a left-to-right layered layout in
# which no two rects ever overlap and every rect fits its label.


def _node_rects(page: str) -> dict:
    """Node rect geometry out of the rendered SVG, keyed by node id."""
    rects = {}
    for tag in re.findall(r'<g class="node"[^>]*>', page):

        def attr(name):
            m = re.search(rf'{name}="([^"]+)"', tag)
            return m.group(1) if m else None

        nid = html_mod.unescape(attr("data-node-id"))
        rects[nid] = tuple(
            float(attr(a)) for a in ("data-x", "data-y", "data-w", "data-h")
        )
    return rects


def _assert_no_overlap(rects: dict, clearance: float = 4.0):
    items = sorted(rects.items())
    for i, (id1, (x1, y1, w1, h1)) in enumerate(items):
        for id2, (x2, y2, w2, h2) in items[i + 1 :]:
            separated = (
                x1 + w1 + clearance <= x2
                or x2 + w2 + clearance <= x1
                or y1 + h1 + clearance <= y2
                or y2 + h2 + clearance <= y1
            )
            assert separated, f"{id1} overlaps {id2}"


def _layered_graph() -> DependencyGraph:
    """A synthetic 25-node graph: five ranks of five, densely linked."""
    nodes = [ServiceNode(id=f"svc-{r}-{i}") for r in range(5) for i in range(5)]
    edges = []
    for r in range(4):
        for i in range(5):
            for j in (i, (i + 1) % 5):
                edges.append(
                    Edge(
                        source=f"svc-{r}-{i}",
                        target=f"svc-{r + 1}-{j}",
                        port=443,
                        evidence=Evidence(flow_count=3, first_seen=1, last_seen=2),
                    )
                )
    edges.append(
        Edge(
            source="svc-0-0",
            target="svc-2-2",
            port=443,
            evidence=Evidence(flow_count=1, first_seen=1, last_seen=2),
        )
    )
    return DependencyGraph(
        graph_id="layout-test",
        producer="test",
        issued_at=1795716000,
        expires_at=1795716000 + 3600,
        nodes=nodes,
        edges=edges,
    )


def test_layout_no_overlaps_demo(demo_graph, declared):
    page = render_html(demo_graph, reconcile_report=reconcile(demo_graph, declared))
    rects = _node_rects(page)
    assert len(rects) == len(demo_graph.nodes)
    assert "analytics-api" in rects  # reachable only via the phantom edge
    _assert_no_overlap(rects)


def test_layout_no_overlaps_synthetic():
    rects = _node_rects(render_html(_layered_graph()))
    assert len(rects) == 25
    _assert_no_overlap(rects)


def test_layout_rects_fit_labels(demo_graph, declared):
    page = render_html(demo_graph, reconcile_report=reconcile(demo_graph, declared))
    for nid, (_x, _y, w, _h) in _node_rects(page).items():
        assert w >= 7.2 * len(nid) + 14 - 1e-6, nid


def test_layout_flows_left_to_right(demo_graph, declared):
    page = render_html(demo_graph, reconcile_report=reconcile(demo_graph, declared))
    rects = _node_rects(page)
    # checkout-api is a source; ledger-db sits three hops downstream.
    assert rects["checkout-api"][0] < rects["payments-api"][0]
    assert rects["payments-api"][0] < rects["ledger-db"][0]
    # The undeclared external endpoint is forced into the last rank.
    last_x = max(x for x, _y, _w, _h in rects.values())
    assert rects[f"ip:{LICENSE_IP}"][0] == last_x


def test_arrowheads_do_not_scale_with_stroke(demo_graph):
    out = render_html(demo_graph)
    assert 'markerUnits="userSpaceOnUse"' in out
    assert 'markerWidth="9"' in out


# -- static testimony: the page must not need JavaScript to testify -------
# The click panel is a progressive enhancement. These tests pin the
# structural fix: the complete evidence is rendered into the page as
# HTML, and every node and edge carries a native SVG tooltip, so the
# witness testifies with scripts blocked, stripped, or broken.


def _evidence_rows(page: str) -> dict:
    """Static evidence table rows: {(source, target): [(count, first)]}."""
    m = re.search(r'<table class="evidence-table">(.*?)</table>', page, re.S)
    assert m, "static evidence table missing"
    rows: dict = {}
    for tag, cells in re.findall(
        r'(<tr class="ev-row"[^>]*>)(.*?)</tr>', m.group(1), re.S
    ):
        src = html_mod.unescape(re.search(r'data-source="([^"]*)"', tag).group(1))
        tgt = html_mod.unescape(re.search(r'data-target="([^"]*)"', tag).group(1))
        count = re.search(r'<td class="ev-count num">(\d+)</td>', cells).group(1)
        first = re.search(r'<td class="ev-first">([^<]*)</td>', cells).group(1)
        rows.setdefault((src, tgt), []).append((int(count), first))
    return rows


def test_evidence_table_covers_every_edge(demo_graph, declared):
    page = render_html(
        demo_graph, reconcile_report=reconcile(demo_graph, declared)
    )
    rows = _evidence_rows(page)
    # Every real edge is testified, with its own flow count.
    for edge in demo_graph.edges:
        assert (edge.source, edge.target) in rows
        counts = [c for c, _f in rows[(edge.source, edge.target)]]
        assert edge.evidence.flow_count in counts
    # The phantom declared edge testifies too — as zero observed flows.
    assert rows[("payments-api", "analytics-api")] == [(0, "—")]


def test_evidence_table_license_row(demo_graph, declared):
    page = render_html(
        demo_graph, reconcile_report=reconcile(demo_graph, declared)
    )
    rows = _evidence_rows(page)
    # The planted 2 a.m. flow: one sighting, first seen 02:00:13Z.
    assert rows[("checkout-api", f"ip:{LICENSE_IP}")] == [
        (1, "2026-11-26T02:00:13Z")
    ]


def test_node_summary_lists_every_node(demo_graph, declared):
    page = render_html(
        demo_graph, reconcile_report=reconcile(demo_graph, declared)
    )
    m = re.search(r'<ul class="node-summary">(.*?)</ul>', page, re.S)
    assert m, "node summary missing"
    for node in demo_graph.nodes:
        assert html_mod.escape(node.id) in m.group(1)


def test_svg_tooltips_on_nodes_and_edges(demo_graph, declared):
    page = render_html(
        demo_graph, reconcile_report=reconcile(demo_graph, declared)
    )
    groups = re.findall(r'<g class="node".*?</g>', page, re.S)
    assert len(groups) == len(demo_graph.nodes)
    titled = [g for g in groups if "<title>" in g]
    assert len(titled) >= len(demo_graph.nodes)
    # Edges carry native tooltips as well (plus the document <title>).
    assert page.count("<title>") >= len(groups) + len(demo_graph.edges)


def test_details_panel_points_at_static_table(demo_graph):
    out = render_html(demo_graph)
    assert 'id="evidence"' in out
    assert "table below" in out  # the panel defers to the static testimony
