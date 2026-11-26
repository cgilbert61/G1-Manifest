"""Render a graph as a standalone HTML witness page.

The viewer is a *witness to the attested artifact*, not a console:
read-only, one file, no server, no external assets — it works offline
by double-clicking. The proof state goes on the face of it (signer,
issue/expiry, verification result), the reconcile findings are a
first-class panel, and every edge carries its evidence, visible on
click. Nothing on the page can change the graph; it can only show what
the graph claims and whether the papers check out.

Layout is computed here, in Python, with a deterministic layered
layout: a dependency graph reads left-to-right like a flow diagram,
so nodes are ranked by longest path from any source over the network
edges, ordered within each rank by a barycenter sweep to reduce edge
crossings, and drawn as label-sized rects joined by Bézier curves.
Every iteration is over sorted ids, so the same graph renders
byte-identical pages on every run.

A witness must not need JavaScript to testify. The full evidence —
every edge's counts, timestamps, and sources, plus a per-node summary
— is rendered into the page as a static table, and every node and
edge carries an SVG <title> tooltip. The JavaScript (pan/zoom and a
click-to-details panel fed by an embedded JSON blob) is a progressive
enhancement on top of that testimony, never a load-bearing part of
it: with scripts blocked or stripped, the page still says everything
it has to say.
"""

from __future__ import annotations

import base64
import functools
import html
import json
import math
from pathlib import Path

from .model import LAYER_LINEAGE, DependencyGraph, ServiceNode, iso_utc


@functools.lru_cache(maxsize=1)
def logo_data_uri() -> str:
    """Return the bundled G1 logo as an inline data URI (offline-safe)."""
    logo_path = Path(__file__).resolve().parent / "assets" / "g1-logo.jpg"
    if not logo_path.is_file():
        return ""
    b64 = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    return f"data:image/jpeg;base64,{b64}"

# -- layered layout geometry -------------------------------------------
# Node rects are sized to their labels (CHAR_W is the per-character
# width estimate for the 11px page font) so a label can never clip.
NODE_H = 30.0
NODE_MIN_W = 110.0
NODE_PAD = 14.0
CHAR_W = 7.2
RANK_GAP = 90.0  # horizontal room between ranks, for edge routing
V_GAP = 18.0  # vertical room between stacked nodes in a rank
MARGIN = 40.0  # canvas margin around the whole drawing

# Node fill by kind — pale tints on the light G1 house theme. An `ip:`
# node (an endpoint no declaration names) always renders as external.
_KIND_FILLS = {
    "service": "#e9f1fb",
    "package": "#fdf2dc",
    "library": "#efeafa",
    "system-library": "#eceff1",
    "process": "#e4f2ee",
    "external": "#fdecea",
    "dataset": "#edf5e4",
}
_DEFAULT_FILL = "#f2f2f2"

# Edge stroke by reconciliation status (and lineage, which is a layer,
# not a status: provenance, never a network connection).
_STATUS_STROKES = {
    "confirmed": "#7d9b76",
    "observed_undeclared": "#c0392b",
    "declared_unobserved": "#d29a26",
    "observed": "#a3adaa",
    "lineage": "#8d84b8",
}

_BADGES = {
    "verified": (
        "badge-verified",
        "VERIFIED — signature valid, key {keyid}",
    ),
    "expired": (
        "badge-expired",
        "EXPIRED — this graph's papers have lapsed",
    ),
    "unsigned": (
        "badge-unsigned",
        "UNSIGNED — rendered from a raw graph, no envelope",
    ),
}


def _node_fill(node: ServiceNode) -> str:
    if node.id.startswith("ip:"):
        return _KIND_FILLS["external"]
    return _KIND_FILLS.get(node.kind, _DEFAULT_FILL)


def _node_width(nid: str) -> float:
    return max(NODE_MIN_W, NODE_PAD + CHAR_W * len(nid))


def _is_external(nid: str, nodes: dict) -> bool:
    return nid.startswith("ip:") or nodes[nid].kind == "external"


def _layout_layered(nodes: dict, data_edges: list[dict]):
    """Deterministic layered layout, left-to-right.

    Returns (pos, canvas_w, canvas_h) with pos[nid] = (x, y, w, h) of
    the node's rect (top-left origin). Ranks come from the network
    edges only — a node's rank is the longest path from any source —
    while lineage-only nodes and external endpoints sit in the last
    rank. Within a rank, barycenter sweeps order nodes by where their
    neighbours sit in the adjacent rank, which keeps crossings down.
    Same graph in, same page out.
    """
    node_ids = sorted(nodes)
    if not node_ids:
        return {}, 2 * MARGIN, 2 * MARGIN
    net_pairs = {
        (e["source"], e["target"])
        for e in data_edges
        if e["layer"] != LAYER_LINEAGE
        and e["source"] in nodes
        and e["target"] in nodes
        and e["source"] != e["target"]
    }
    lineage_ids = {
        nid
        for e in data_edges
        if e["layer"] == LAYER_LINEAGE
        for nid in (e["source"], e["target"])
        if nid in nodes
    }
    in_net = {nid for pair in net_pairs for nid in pair}
    preds = {nid: set() for nid in node_ids}
    succs = {nid: set() for nid in node_ids}
    for s, t in net_pairs:
        preds[t].add(s)
        succs[s].add(t)

    # Externals and lineage-only nodes are placed, not ranked: they
    # belong at the far end of the flow, in the last rank.
    last_rank_ids = {
        nid
        for nid in node_ids
        if _is_external(nid, nodes) or (nid in lineage_ids and nid not in in_net)
    }
    core = [nid for nid in node_ids if nid not in last_rank_ids]

    # Longest-path ranking over the core. A node ranks once every core
    # predecessor has a rank; nodes the passes leave behind sit in a
    # cycle (or hang off one) and fall back to the deepest rank found.
    rank: dict[str, int] = {}
    remaining = set(core)
    progress = True
    while remaining and progress:
        progress = False
        for nid in sorted(remaining):
            ps = [p for p in preds[nid] if p not in last_rank_ids]
            if all(p in rank for p in ps):
                rank[nid] = max((rank[p] + 1 for p in ps), default=0)
                remaining.discard(nid)
                progress = True
    max_rank = max(rank.values(), default=0)
    for nid in remaining:
        rank[nid] = max_rank
    for nid in last_rank_ids:
        rank[nid] = max_rank

    ranks: dict[int, list[str]] = {}
    for nid in node_ids:
        ranks.setdefault(rank[nid], []).append(nid)
    for r in ranks:
        ranks[r].sort()
    rank_numbers = sorted(ranks)

    # Barycenter ordering: alternate forward sweeps (order a rank by
    # its nodes' predecessors in the previous rank) and backward
    # sweeps (successors in the next rank). Ties — and nodes with no
    # neighbours on that side — fall back to current position, then id.
    for sweep in range(4):
        forward = sweep % 2 == 0
        order = rank_numbers if forward else list(reversed(rank_numbers))
        for r in order:
            adj_r = r - 1 if forward else r + 1
            if adj_r not in ranks:
                continue
            adj_pos = {nid: i for i, nid in enumerate(ranks[adj_r])}
            neighbours = preds if forward else succs

            def _key(item, adj_pos=adj_pos, neighbours=neighbours):
                idx, nid = item
                ns = [adj_pos[n] for n in neighbours[nid] if n in adj_pos]
                bc = sum(ns) / len(ns) if ns else float(idx)
                return (bc, nid)

            ranks[r] = [nid for _i, nid in sorted(enumerate(ranks[r]), key=_key)]

    # Geometry: columns left-to-right, each as wide as its widest
    # label; columns are centred vertically against the tallest one.
    col_x: dict[int, float] = {}
    x = MARGIN
    for r in rank_numbers:
        col_x[r] = x
        x += max(_node_width(nid) for nid in ranks[r]) + RANK_GAP
    canvas_w = x - RANK_GAP + MARGIN
    col_h = {
        r: len(ranks[r]) * NODE_H + (len(ranks[r]) - 1) * V_GAP
        for r in rank_numbers
    }
    max_h = max(col_h.values())
    canvas_h = max_h + 2 * MARGIN
    pos: dict[str, tuple] = {}
    for r in rank_numbers:
        y = MARGIN + (max_h - col_h[r]) / 2
        for nid in ranks[r]:
            pos[nid] = (col_x[r], y, _node_width(nid), NODE_H)
            y += NODE_H + V_GAP
    return pos, canvas_w, canvas_h


def _edge_status(edge, status_by_pair: dict) -> str:
    if edge.layer == LAYER_LINEAGE:
        return "lineage"
    return status_by_pair.get(edge.pair(), "observed")


def _evidence_view(evidence) -> dict:
    return {
        "flow_count": evidence.flow_count,
        "first_seen": iso_utc(evidence.first_seen) if evidence.first_seen else None,
        "last_seen": iso_utc(evidence.last_seen) if evidence.last_seen else None,
        "sources": list(evidence.sources),
    }


def render_html(
    graph: DependencyGraph,
    *,
    reconcile_report: dict | None = None,
    verification: dict | None = None,
    title: str = "G1-Manifest",
    subtitle: str = "G1163RT Security Labs",
) -> str:
    """Render `graph` as one complete, self-contained HTML document."""
    # -- statuses from the reconcile report, at (source, target) pair level
    status_by_pair: dict[tuple, str] = {}
    phantom_pairs: list[tuple] = []
    if reconcile_report is not None:
        for entry in reconcile_report.get("confirmed", []):
            status_by_pair[(entry["source"], entry["target"])] = "confirmed"
        for entry in reconcile_report.get("observed_undeclared", []):
            status_by_pair[(entry["source"], entry["target"])] = (
                "observed_undeclared"
            )
        for entry in reconcile_report.get("declared_unobserved", []):
            pair = (entry["source"], entry["target"])
            status_by_pair[pair] = "declared_unobserved"
            phantom_pairs.append(pair)

    # -- render node set: graph nodes plus any declared-only phantom targets
    nodes = {n.id: n for n in graph.nodes}
    for pair in phantom_pairs:
        for nid in pair:
            if nid not in nodes:
                nodes[nid] = ServiceNode(id=nid, kind="service", substrate="declared")
    node_ids = sorted(nodes)

    edges = sorted(
        graph.edges,
        key=lambda e: (e.source, e.target, e.port or 0, e.protocol or "", e.layer),
    )

    # -- data blob for the details panel (JSON with <, >, & unicode-escaped
    #    so no id can break out of the script block)
    data_edges = []
    for edge in edges:
        data_edges.append(
            {
                "source": edge.source,
                "target": edge.target,
                "port": edge.port,
                "protocol": edge.protocol,
                "layer": edge.layer,
                "status": _edge_status(edge, status_by_pair),
                "low_frequency": edge.low_frequency,
                "phantom": False,
                "evidence": _evidence_view(edge.evidence),
            }
        )
    for pair in sorted(phantom_pairs):
        data_edges.append(
            {
                "source": pair[0],
                "target": pair[1],
                "port": None,
                "protocol": None,
                "layer": "network",
                "status": "declared_unobserved",
                "low_frequency": False,
                "phantom": True,
                "evidence": {
                    "flow_count": 0,
                    "first_seen": None,
                    "last_seen": None,
                    "sources": [],
                },
            }
        )
    pos, canvas_w, canvas_h = _layout_layered(nodes, data_edges)
    data_nodes = [
        {
            "id": nid,
            "kind": nodes[nid].kind,
            "substrate": nodes[nid].substrate,
            "x": round(pos[nid][0] + pos[nid][2] / 2, 1),
            "y": round(pos[nid][1] + pos[nid][3] / 2, 1),
        }
        for nid in node_ids
    ]
    blob = {"nodes": data_nodes, "edges": data_edges}
    blob_json = (
        json.dumps(blob, sort_keys=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append(f"<title>{html.escape(title)} — {html.escape(subtitle)}</title>")
    parts.append("<style>" + _CSS + "</style></head><body>")

    # -- header band: identity, validity window, proof state on the face
    parts.append('<header class="band">')
    logo_uri = logo_data_uri()
    logo_img = (
        f'<img class="brand-logo" src="{logo_uri}" alt="G1 Logo">'
        if logo_uri
        else ""
    )
    parts.append(
        '<div class="brand">'
        f"{logo_img}"
        '<div class="brand-text">'
        f"<h1>{html.escape(title)}</h1>"
        f'<div class="brand-sub">{html.escape(subtitle)}</div>'
        "</div></div>"
    )
    parts.append('<div class="meta">')
    parts.append(
        f"<span>Graph <strong>{html.escape(graph.graph_id)}</strong></span>"
        f"<span>Producer {html.escape(graph.producer)}</span>"
        f"<span>Schema v{html.escape(graph.version)} · seq {graph.sequence}</span>"
        f"<span>Issued {html.escape(iso_utc(graph.issued_at))}</span>"
        f"<span>Expires {html.escape(iso_utc(graph.expires_at))}</span>"
        f"<span>{len(data_nodes)} nodes · {len(data_edges)} edges</span>"
    )
    parts.append("</div>")
    if verification is not None:
        status = verification.get("status", "unsigned")
        css_class, text = _BADGES.get(status, _BADGES["unsigned"])
        text = text.replace("{keyid}", str(verification.get("keyid") or "—"))
        parts.append(f'<div class="badge {css_class}">{html.escape(text)}</div>')
        detail = verification.get("detail")
        if detail:
            parts.append(
                f'<div class="badge-detail">{html.escape(str(detail))}</div>'
            )
    parts.append("</header>")

    parts.append('<main class="layout">')
    parts.append('<section class="canvas-wrap">')
    parts.append(_svg(nodes, node_ids, pos, canvas_w, canvas_h, data_edges))
    parts.append("</section>")

    parts.append('<aside class="side">')
    parts.append('<section class="panel" id="details">')
    parts.append("<h2>Details</h2>")
    parts.append(
        '<div id="details-body"><p>Each line is a dependency the estate '
        "was observed to use — or, for dotted lineage lines, a recorded "
        "derivation; its thickness is the flow count and its colour is "
        "its reconciliation status. Click any node or line to see the "
        "evidence behind it: counts, first and last seen, and which "
        "sources saw it. The full evidence for every edge is in the "
        "table below this panel, rendered into the page itself — this "
        "panel is a convenience, not a requirement.</p></div>"
    )
    parts.append("</section>")

    # -- findings panel: the reconcile verdict, first-class, not a footnote
    parts.append('<section class="panel" id="findings">')
    parts.append("<h2>Reconcile findings</h2>")
    if reconcile_report is None:
        parts.append(
            "<p>Reconciliation was not run for this rendering. Render "
            "with a declared model (<code>--declared</code>) to diff this "
            "graph against what the estate claims.</p>"
        )
    else:
        summary = reconcile_report.get("summary", {})
        parts.append(
            "<p class=\"summary\">"
            f"{summary.get('confirmed', 0)} confirmed · "
            f"{summary.get('observed_undeclared', 0)} observed-undeclared · "
            f"{summary.get('declared_unobserved', 0)} declared-unobserved"
            "</p>"
        )
        for finding in reconcile_report.get("observed_undeclared", []):
            obs = (finding.get("observations") or [{}])[0]
            first_seen = (
                iso_utc(obs["first_seen"]) if obs.get("first_seen") else "—"
            )
            parts.append(
                '<p class="finding finding-undeclared">'
                f"FINDING [{html.escape(str(finding.get('severity', '')))}] "
                f"{html.escape(finding['source'])} -&gt; "
                f"{html.escape(finding['target'])} observed "
                f"x{obs.get('flow_count', 0)}, first seen "
                f"{html.escape(first_seen)} — declared nowhere</p>"
            )
        for stale in reconcile_report.get("declared_unobserved", []):
            parts.append(
                '<p class="finding finding-stale">'
                f"STALE [{html.escape(str(stale.get('severity', '')))}] "
                f"{html.escape(stale['source'])} -&gt; "
                f"{html.escape(stale['target'])} declared but never "
                "observed</p>"
            )
        if not reconcile_report.get("observed_undeclared") and not (
            reconcile_report.get("declared_unobserved")
        ):
            parts.append(
                "<p>No findings: every observed dependency is declared, "
                "and every declaration was observed.</p>"
            )
    parts.append("</section>")
    parts.append("</aside></main>")

    # -- static testimony: the whole evidence, in the page, no JS required
    parts.append(
        _evidence_section(nodes, node_ids, data_edges, reconcile_report is not None)
    )

    parts.append(
        '<script type="application/json" id="graph-data">'
        + blob_json
        + "</script>"
    )
    parts.append("<script>" + _JS + "</script>")
    parts.append("</body></html>")
    return "".join(parts)


def _edge_title(e: dict) -> str:
    """One line of evidence for an edge, plain text (escaped by callers)."""
    ev = e["evidence"]
    s = f"{e['source']} -> {e['target']}"
    if e["port"]:
        s += f":{e['port']}"
    if e["protocol"]:
        s += f" ({e['protocol']})"
    s += f" [{e['layer']}"
    if e["status"] and e["status"] != "observed":
        s += f", {e['status']}"
    if e["phantom"]:
        s += ", declared only"
    s += f"] x{ev['flow_count']}"
    s += f", first {ev['first_seen'] or '—'}, last {ev['last_seen'] or '—'}"
    if ev["sources"]:
        s += f", via {', '.join(ev['sources'])}"
    if e["low_frequency"]:
        s += " (low frequency)"
    return s


def _evidence_section(nodes, node_ids, data_edges, has_reconcile: bool) -> str:
    """The static testimony: every edge's evidence, and a node summary.

    Server-rendered HTML, no JavaScript involved — a witness must not
    need scripts to testify. Rows follow `data_edges` order (sorted,
    phantoms last), the node list is the sorted render set.
    """
    out: list[str] = []
    out.append('<section class="panel evidence" id="evidence">')
    out.append("<h2>Edge evidence</h2>")
    out.append(
        "<p>Every edge in the graph, with the evidence behind it — "
        "counts and timestamps from the sources that saw it, not "
        "opinion. This table is part of the page; it needs no script "
        "to read.</p>"
    )
    out.append('<table class="evidence-table">')
    out.append(
        "<thead><tr><th>Edge</th><th>Layer</th><th>Status</th>"
        '<th class="num">Flows</th><th>First seen</th><th>Last seen</th>'
        "<th>Sources</th></tr></thead><tbody>"
    )
    for e in data_edges:
        ev = e["evidence"]
        edge_cell = f"{html.escape(e['source'])} -&gt; {html.escape(e['target'])}"
        if e["port"]:
            edge_cell += f":{e['port']}"
        if e["protocol"]:
            edge_cell += f" ({html.escape(str(e['protocol']))})"
        if e["phantom"]:
            status_cell = "declared_unobserved"
        elif has_reconcile:
            status_cell = e["status"]
        elif e["layer"] == LAYER_LINEAGE:
            status_cell = "lineage"
        else:
            status_cell = "—"
        out.append(
            f'<tr class="ev-row" data-source="{html.escape(e["source"], quote=True)}" '
            f'data-target="{html.escape(e["target"], quote=True)}">'
            f'<td class="ev-edge">{edge_cell}</td>'
            f'<td class="ev-layer">{html.escape(e["layer"])}</td>'
            f'<td class="ev-status status-{html.escape(status_cell, quote=True)}">'
            f"{html.escape(status_cell)}</td>"
            f'<td class="ev-count num">{ev["flow_count"]}</td>'
            f'<td class="ev-first">{html.escape(ev["first_seen"] or "—")}</td>'
            f'<td class="ev-last">{html.escape(ev["last_seen"] or "—")}</td>'
            f'<td class="ev-sources">'
            f'{html.escape(", ".join(ev["sources"]) or "—")}</td></tr>'
        )
    out.append("</tbody></table>")

    out_count = {nid: 0 for nid in node_ids}
    in_count = {nid: 0 for nid in node_ids}
    for e in data_edges:
        if e["source"] in out_count:
            out_count[e["source"]] += 1
        if e["target"] in in_count:
            in_count[e["target"]] += 1
    out.append("<h2>Node summary</h2>")
    out.append('<ul class="node-summary">')
    for nid in node_ids:
        node = nodes[nid]
        out.append(
            f"<li><strong>{html.escape(nid)}</strong> — "
            f"{html.escape(node.kind)} · {html.escape(node.substrate)} · "
            f"{out_count[nid]} out · {in_count[nid]} in</li>"
        )
    out.append("</ul>")
    out.append("</section>")
    return "".join(out)


def _svg(nodes, node_ids, pos, canvas_w, canvas_h, data_edges) -> str:
    """The graph canvas: Bézier edges under label-sized node rects."""
    out: list[str] = []
    out.append(
        f'<svg id="canvas" viewBox="0 0 {canvas_w:.0f} {canvas_h:.0f}" '
        'xmlns="http://www.w3.org/2000/svg" role="img">'
    )
    out.append("<defs>")
    for name, color in _STATUS_STROKES.items():
        # userSpaceOnUse pins the arrowhead to ~9px whatever the stroke
        # width is. The default (strokeWidth units) multiplies the
        # marker by the line width — that is what once let a thick
        # edge grow an arrowhead the size of a node.
        out.append(
            f'<marker id="arrow-{name}" viewBox="0 0 10 10" refX="8" '
            f'refY="5" markerWidth="9" markerHeight="9" '
            f'markerUnits="userSpaceOnUse" orient="auto">'
            f'<path d="M0,0 L10,5 L0,10 z" fill="{color}"></path></marker>'
        )
    out.append("</defs>")
    out.append('<g id="viewport">')

    # In/out counts for the node <title> tooltips.
    out_count = {nid: 0 for nid in node_ids}
    in_count = {nid: 0 for nid in node_ids}
    for e in data_edges:
        if e["source"] in out_count:
            out_count[e["source"]] += 1
        if e["target"] in in_count:
            in_count[e["target"]] += 1

    # Group edges between the same unordered pair so parallel edges fan out.
    groups: dict[tuple, list[int]] = {}
    for idx, e in enumerate(data_edges):
        groups.setdefault(tuple(sorted((e["source"], e["target"]))), []).append(idx)

    for idx, e in enumerate(data_edges):
        if e["source"] == e["target"] or e["source"] not in pos:
            continue
        if e["target"] not in pos:
            continue
        sx, sy, sw, sh = pos[e["source"]]
        tx, ty, tw, th = pos[e["target"]]
        group = groups[tuple(sorted((e["source"], e["target"])))]
        slot = group.index(idx)
        slot_off = (slot - (len(group) - 1) / 2) * 8.0
        status = e["status"]
        stroke = _STATUS_STROKES[status]
        if status == "lineage":
            width = 1.0
        else:
            width = min(3.5, 1.0 + 0.5 * math.sqrt(e["evidence"]["flow_count"]))
        dash = ""
        if status == "declared_unobserved":
            dash = ' stroke-dasharray="7 5"'
        elif status == "lineage":
            dash = ' stroke-dasharray="2 4"'
        # Right edge of the source rect to left edge of the target
        # rect, as a cubic Bézier whose control points leave and enter
        # horizontally — the flow-diagram S-curve.
        x1, y1 = sx + sw, sy + sh / 2 + slot_off
        x2, y2 = tx - 1.0, ty + th / 2 + slot_off
        bend = max(RANK_GAP / 2, abs(x2 - x1) / 2)
        d = (
            f"M{x1:.1f},{y1:.1f} C{x1 + bend:.1f},{y1:.1f} "
            f"{x2 - bend:.1f},{y2:.1f} {x2:.1f},{y2:.1f}"
        )
        out.append(
            f'<path class="edge edge-{status}" data-status="{status}" '
            f'data-idx="{idx}" d="{d}" fill="none" stroke="{stroke}" '
            f'stroke-width="{width:.1f}"{dash} '
            f'marker-end="url(#arrow-{status})">'
            f"<title>{html.escape(_edge_title(e))}</title></path>"
        )
        out.append(
            f'<path class="edge-hit" data-idx="{idx}" d="{d}" fill="none" '
            f'stroke="rgba(0,0,0,0)" stroke-width="14"></path>'
        )

    for nid in node_ids:
        node = nodes[nid]
        x, y, w, h = pos[nid]
        fill = _node_fill(node)
        esc = html.escape(nid, quote=True)
        out.append(
            f'<g class="node" data-id="{esc}" data-node-id="{esc}" '
            f'data-x="{x:.1f}" data-y="{y:.1f}" data-w="{w:.1f}" '
            f'data-h="{h:.1f}">'
            f"<title>{html.escape(nid)} — {html.escape(node.kind)} on "
            f"{html.escape(node.substrate)}; {out_count[nid]} outbound, "
            f"{in_count[nid]} inbound</title>"
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" '
            f'height="{h:.1f}" rx="7" fill="{fill}" stroke="#5a6a72" '
            f'stroke-width="1"></rect>'
            f'<text x="{x + w / 2:.1f}" y="{y + h / 2 + 4:.1f}" '
            f'text-anchor="middle">{html.escape(nid)}</text></g>'
        )
    out.append("</g></svg>")
    return "".join(out)


_CSS = """
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, "Segoe UI", Roboto, Helvetica,
  Arial, sans-serif; background: #f7f9fb; color: #1d2733; }
.band { background: #ffffff; border-bottom: 1px solid #d8e0e8;
  padding: 16px 22px 14px; }
.brand { display: flex; align-items: center; gap: 14px; margin-bottom: 10px; }
.brand-logo { width: 48px; height: 48px; object-fit: contain; flex: 0 0 auto; }
.brand-text h1 { margin: 0; font-size: 22px; font-weight: 700; line-height: 1.15;
  letter-spacing: -0.01em; }
.brand-sub { margin-top: 2px; font-size: 13px; font-weight: 500; color: #43536a;
  letter-spacing: 0.02em; }
.meta { display: flex; flex-wrap: wrap; gap: 6px 18px; font-size: 13px;
  color: #43536a; }
.badge { display: inline-block; margin-top: 10px; padding: 6px 12px;
  border-radius: 6px; font-size: 14px; font-weight: 700;
  letter-spacing: 0.02em; border: 1.5px solid; }
.badge-verified { background: #e2f0e3; border-color: #4a7d4f; color: #1e4620; }
.badge-expired { background: #fbe3e1; border-color: #b03a2e; color: #7c211a; }
.badge-unsigned { background: #fdf3d8; border-color: #b8860b; color: #6d5203; }
.badge-detail { margin-top: 5px; font-size: 12.5px; color: #43536a; }
.layout { display: flex; gap: 14px; padding: 14px; align-items: flex-start; }
.canvas-wrap { flex: 1 1 auto; min-width: 0; background: #ffffff;
  border: 1px solid #d8e0e8; border-radius: 8px; }
#canvas { width: 100%; height: auto; display: block; cursor: grab;
  touch-action: none; }
#canvas:active { cursor: grabbing; }
.node { cursor: pointer; }
.node text { font-size: 11px; fill: #1d2733; pointer-events: none; }
.edge { cursor: pointer; }
.edge-hit { cursor: pointer; pointer-events: stroke; }
.side { flex: 0 0 340px; display: flex; flex-direction: column; gap: 14px; }
.panel { background: #ffffff; border: 1px solid #d8e0e8; border-radius: 8px;
  padding: 12px 14px; font-size: 13.5px; line-height: 1.45; }
.panel h2 { margin: 0 0 8px; font-size: 15px; }
.panel p { margin: 0 0 8px; }
.panel .summary { font-weight: 600; }
.panel ul { margin: 0 0 8px; padding-left: 18px; }
.finding { padding: 6px 8px; border-radius: 5px; }
.finding-undeclared { background: #fbeeea; border-left: 4px solid #c0392b; }
.finding-stale { background: #fdf6e0; border-left: 4px solid #d29a26; }
code { background: #eef2f6; padding: 0 3px; border-radius: 3px; }
.evidence { margin: 0 14px 14px; }
.evidence table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.evidence th, .evidence td { text-align: left; padding: 4px 8px;
  border-bottom: 1px solid #e3e9ef; vertical-align: top; }
.evidence th { color: #43536a; font-weight: 600; }
.evidence td.num, .evidence th.num { text-align: right; }
.evidence .status-observed_undeclared { color: #c0392b; font-weight: 600; }
.evidence .status-declared_unobserved { color: #9a6d0d; font-weight: 600; }
.node-summary { columns: 2; column-gap: 28px; }
"""

_JS = """
// Progressive enhancement only. The page's testimony — the evidence
// table and the SVG tooltips — is static HTML and needs none of this.
// The two halves are initialised in isolation, each in its own
// try/catch, so a failure in pan/zoom can never take the click
// handlers down with it (and vice versa).
let suppressClick = false;
function initDetails() {
  const data = JSON.parse(document.getElementById('graph-data').textContent);
  const body = document.getElementById('details-body');
  function esc(s) { return String(s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  function evLine(e) {
    const ev = e.evidence;
    let s = esc(e.source) + ' -&gt; ' + esc(e.target);
    if (e.port) s += ':' + e.port;
    s += ' [' + esc(e.layer);
    if (e.status && e.status !== 'observed') s += ', ' + esc(e.status);
    if (e.phantom) s += ', declared only';
    s += '] x' + ev.flow_count;
    s += ', first ' + (ev.first_seen || '—') + ', last ' + (ev.last_seen || '—');
    if (ev.sources && ev.sources.length) s += ', via ' + esc(ev.sources.join(', '));
    if (e.low_frequency) s += ' (low frequency)';
    return s;
  }
  function showNode(id) {
    const n = data.nodes.find(x => x.id === id);
    const out = data.edges.filter(e => e.source === id);
    const inc = data.edges.filter(e => e.target === id);
    let h = '<p><strong>' + esc(id) + '</strong><br>kind ' + esc(n.kind) +
      ' · substrate ' + esc(n.substrate) + '</p>';
    h += '<p>Outbound (' + out.length + '):</p><ul>' +
      (out.map(e => '<li>' + evLine(e) + '</li>').join('') || '<li>none</li>') +
      '</ul>';
    h += '<p>Inbound (' + inc.length + '):</p><ul>' +
      (inc.map(e => '<li>' + evLine(e) + '</li>').join('') || '<li>none</li>') +
      '</ul>';
    body.innerHTML = h;
  }
  function showEdge(idx) {
    const e = data.edges[idx];
    body.innerHTML = '<p><strong>Edge</strong></p><ul><li>' + evLine(e) +
      '</li></ul><p>Evidence is what the sources observed — counts and ' +
      'timestamps, not opinion.</p>';
  }
  document.querySelectorAll('.node').forEach(g =>
    g.addEventListener('click', () => { if (!suppressClick) showNode(g.dataset.id); }));
  document.querySelectorAll('.edge-hit').forEach(p =>
    p.addEventListener('click', () => { if (!suppressClick) showEdge(Number(p.dataset.idx)); }));
}
function initPanZoom() {
  const svg = document.getElementById('canvas');
  const vb0 = svg.viewBox.baseVal;
  const vb = { x: vb0.x, y: vb0.y, w: vb0.width, h: vb0.height };
  const aspect = vb0.height / vb0.width;
  function apply() { svg.setAttribute('viewBox',
    vb.x + ' ' + vb.y + ' ' + vb.w + ' ' + vb.h); }
  svg.addEventListener('wheel', e => {
    e.preventDefault();
    const f = e.deltaY > 0 ? 1.12 : 0.89;
    const nw = Math.min(vb0.width * 2, Math.max(150, vb.w * f));
    const nh = nw * aspect;
    vb.x += (vb.w - nw) / 2; vb.y += (vb.h - nh) / 2; vb.w = nw; vb.h = nh;
    apply();
  }, { passive: false });
  let drag = null;
  svg.addEventListener('pointerdown', e => {
    // Deliberately NO setPointerCapture here. Capturing on pointerdown
    // retargets every later pointer event for this press — including
    // the click — to the <svg> itself, so a plain click on a node or
    // an edge never reaches that element's own click handler. That
    // was the bug that made the page look dead. Capture is taken only
    // once the press has actually moved enough to be a drag.
    drag = { x: e.clientX, y: e.clientY, moved: 0, captured: false };
  });
  svg.addEventListener('pointermove', e => {
    if (!drag) return;
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    drag.moved += Math.abs(dx) + Math.abs(dy);
    if (drag.moved > 4 && !drag.captured) {
      try { svg.setPointerCapture(e.pointerId); drag.captured = true; }
      catch (err) { /* capture is a nicety; panning still works */ }
    }
    vb.x -= dx * vb.w / svg.clientWidth;
    vb.y -= dy * vb.h / svg.clientHeight;
    drag.x = e.clientX; drag.y = e.clientY;
    apply();
  });
  svg.addEventListener('pointerup', () => {
    if (drag && drag.moved > 4) {
      suppressClick = true;
      setTimeout(() => { suppressClick = false; }, 50);
    }
    drag = null;
  });
}
function init() {
  try { initDetails(); } catch (err) { /* enhancement, not testimony */ }
  try { initPanZoom(); } catch (err) { /* likewise */ }
}
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
"""
