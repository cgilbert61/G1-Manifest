"""Interactive WebGL Explorer engine for G1-Manifest signed dependency graphs.

Separate from ``estate_graph/render.py`` (which remains untouched as the static,
deterministic witness-page renderer). Every Explorer view is derived from a
verified DSSEv1 Ed25519 envelope, carries its canonical ``envelope_id`` and
proof state (``verified`` or ``expired``), and refuses forged or tampered
envelopes outright.

Four progressive views designed for humans at 10,000+ node scale:
1. Diff View (Build First) — exact delta between two verified envelopes.
2. Ego View — search a node, show immediate neighbors, expand 1 ring at a time,
   with upstream/downstream direction and blast-radius readout.
3. Findings-First View — start from reconciliation findings
   (``observed_undeclared`` / ``declared_unobserved``) and draw only the focused
   subgraph around the selected finding with evidence pinned beside it.
4. Zoom Levels — hierarchical roll-up (``estate`` -> ``segment`` -> ``service``
   -> ``instance``) weighted by flow count with expand/collapse navigation.
"""

from __future__ import annotations

import base64
import html
import json
import math
import time
from collections import defaultdict, deque
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .destinations.core import envelope_id_for
from .model import (
    LAYER_LINEAGE,
    LAYER_NETWORK,
    LAYER_OBSERVED_LOAD,
    LAYER_PACKAGE,
    DependencyGraph,
    Edge,
    ServiceNode,
    iso_utc,
    parse_ts,
)
from .reconcile import reconcile
from .render import logo_data_uri
from .sign import keyid_for
from .sources.declared import DeclaredModel
from .verify import ExpiredGraph, verify_envelope

ALL_LAYERS = (LAYER_NETWORK, LAYER_LINEAGE, LAYER_PACKAGE, LAYER_OBSERVED_LOAD)
ZOOM_LEVELS = ("estate", "segment", "service", "instance")


# ---------------------------------------------------------------------------
# Envelope verification & proof state
# ---------------------------------------------------------------------------


def load_verified_or_expired(
    envelope: dict,
    public_key: Ed25519PublicKey,
    *,
    now: int | None = None,
) -> tuple[DependencyGraph, dict]:
    """Verify a DSSEv1 Ed25519 envelope for Explorer display.

    - Valid signature + within validity window -> returns ``(graph, proof)``
      with ``proof["status"] == "verified"``.
    - Valid signature + expired window -> ``verify_envelope`` already verified
      the cryptographic signature and schema version before raising
      ``ExpiredGraph``; returns ``(graph, proof)`` with
      ``proof["status"] == "expired"`` so every Explorer view can open it
      clearly marked ``EXPIRED`` and never as current.
    - Forged, tampered, malformed, or unsupported-version envelope -> re-raises
      ``BadSignature`` / ``MalformedEnvelope`` / ``UnsupportedVersion``.
    """
    kid = keyid_for(public_key)
    try:
        graph = verify_envelope(envelope, public_key, now=now)
        env_id = envelope_id_for(envelope, graph)
        return graph, {
            "status": "verified",
            "envelope_id": env_id,
            "graph_id": graph.graph_id,
            "sequence": graph.sequence,
            "producer": graph.producer,
            "issued_at": graph.issued_at,
            "issued_utc": iso_utc(graph.issued_at),
            "expires_at": graph.expires_at,
            "expires_utc": iso_utc(graph.expires_at),
            "keyid": kid,
            "detail": "Ed25519 signature valid and within validity window.",
        }
    except ExpiredGraph:
        payload = base64.b64decode(envelope["payload"])
        graph = DependencyGraph.from_dict(json.loads(payload.decode("utf-8")))
        env_id = envelope_id_for(envelope, graph)
        return graph, {
            "status": "expired",
            "envelope_id": env_id,
            "graph_id": graph.graph_id,
            "sequence": graph.sequence,
            "producer": graph.producer,
            "issued_at": graph.issued_at,
            "issued_utc": iso_utc(graph.issued_at),
            "expires_at": graph.expires_at,
            "expires_utc": iso_utc(graph.expires_at),
            "keyid": kid,
            "detail": (
                f"Signature valid, but graph expired at {iso_utc(graph.expires_at)}. "
                "EXPIRED — historical inspection only; do not treat as current."
            ),
        }


# ---------------------------------------------------------------------------
# Common filter helpers (layer, time window, min flow count)
# ---------------------------------------------------------------------------


def _normalize_filters(
    *,
    layers: list[str] | set[str] | tuple[str, ...] | None = None,
    min_time: int | str | None = None,
    max_time: int | str | None = None,
    min_flow_count: int = 0,
) -> dict:
    layer_set = (
        sorted({str(x).strip() for x in layers if str(x).strip()})
        if layers is not None
        else None
    )
    t_min = parse_ts(min_time) if min_time not in (None, "") else None
    t_max = parse_ts(max_time) if max_time not in (None, "") else None
    m_flow = max(0, int(min_flow_count or 0))
    return {
        "layers": layer_set,
        "min_time": t_min,
        "max_time": t_max,
        "min_flow_count": m_flow,
    }


def _edge_matches(edge: Edge, flt: dict) -> bool:
    if flt["layers"] is not None and edge.layer not in flt["layers"]:
        return False
    if flt["min_flow_count"] > 0 and edge.evidence.flow_count < flt["min_flow_count"]:
        return False
    if flt["min_time"] is not None:
        if edge.evidence.last_seen and edge.evidence.last_seen < flt["min_time"]:
            return False
    if flt["max_time"] is not None:
        if edge.evidence.first_seen and edge.evidence.first_seen > flt["max_time"]:
            return False
    return True


def filter_graph(
    graph: DependencyGraph,
    *,
    layers: list[str] | set[str] | tuple[str, ...] | None = None,
    min_time: int | str | None = None,
    max_time: int | str | None = None,
    min_flow_count: int = 0,
    keep_isolated_nodes: bool = True,
) -> DependencyGraph:
    """Return a filtered DependencyGraph preserving metadata and evidence."""
    flt = _normalize_filters(
        layers=layers,
        min_time=min_time,
        max_time=max_time,
        min_flow_count=min_flow_count,
    )
    is_active = (
        flt["layers"] is not None
        or flt["min_time"] is not None
        or flt["max_time"] is not None
        or flt["min_flow_count"] > 0
    )
    if not is_active:
        return graph

    kept_edges = [e for e in graph.edges if _edge_matches(e, flt)]
    if keep_isolated_nodes:
        kept_nodes = list(graph.nodes)
    else:
        referenced = {e.source for e in kept_edges} | {e.target for e in kept_edges}
        kept_nodes = [n for n in graph.nodes if n.id in referenced]

    return DependencyGraph(
        graph_id=graph.graph_id,
        issued_at=graph.issued_at,
        expires_at=graph.expires_at,
        producer=graph.producer,
        version=graph.version,
        sequence=graph.sequence,
        nodes=kept_nodes,
        edges=kept_edges,
    )


def _node_to_render_dict(node: ServiceNode, **extra: Any) -> dict:
    d = {
        "id": node.id,
        "label": node.id,
        "kind": node.kind,
        "substrate": node.substrate,
        "labels": node.labels,
    }
    d.update(extra)
    return d


def _edge_to_render_dict(edge: Edge, **extra: Any) -> dict:
    d = {
        "source": edge.source,
        "target": edge.target,
        "port": edge.port,
        "protocol": edge.protocol,
        "layer": edge.layer,
        "flow_count": edge.evidence.flow_count,
        "first_seen": edge.evidence.first_seen,
        "last_seen": edge.evidence.last_seen,
        "sources": sorted(edge.evidence.sources),
        "low_frequency": edge.low_frequency,
    }
    d.update(extra)
    return d


def _layout_radial(nodes: list[dict], center_id: str | None = None) -> list[dict]:
    """Deterministic fast O(N) radial/ring layout for WebGL rendering."""
    if not nodes:
        return nodes
    rings: dict[int, list[dict]] = defaultdict(list)
    for n in nodes:
        if center_id and n["id"] == center_id:
            rings[0].append(n)
        else:
            r = int(n.get("ring", 1))
            rings[max(1, r)].append(n)
    out = []
    for ring_idx in sorted(rings):
        bucket = rings[ring_idx]
        count = len(bucket)
        if ring_idx == 0 and count == 1:
            item = dict(bucket[0])
            item["x"] = 0.0
            item["y"] = 0.0
            out.append(item)
            continue
        radius = 160.0 * max(1, ring_idx)
        for i, n in enumerate(bucket):
            angle = (2.0 * math.pi * i) / max(1, count)
            item = dict(n)
            item["x"] = round(radius * math.cos(angle), 2)
            item["y"] = round(radius * math.sin(angle), 2)
            out.append(item)
    return out


def _layout_grid_or_circle(nodes: list[dict]) -> list[dict]:
    """Deterministic O(N) layout: circle for <= 48 nodes, golden-angle phyllotaxis above."""
    count = len(nodes)
    if count == 0:
        return []
    out = []
    if count <= 48:
        radius = max(140.0, count * 14.0)
        for i, n in enumerate(nodes):
            angle = (2.0 * math.pi * i) / count
            item = dict(n)
            item["x"] = round(radius * math.cos(angle), 2)
            item["y"] = round(radius * math.sin(angle), 2)
            out.append(item)
        return out

    golden = math.pi * (3.0 - math.sqrt(5.0))
    scale = 26.0
    for i, n in enumerate(nodes):
        r = scale * math.sqrt(i + 1)
        theta = i * golden
        item = dict(n)
        item["x"] = round(r * math.cos(theta), 2)
        item["y"] = round(r * math.sin(theta), 2)
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# Item 1 (Build First · Highest Value) — Diff View
# ---------------------------------------------------------------------------


def build_diff_view(
    envelope_a: dict,
    envelope_b: dict,
    public_key: Ed25519PublicKey,
    *,
    now: int | None = None,
    layers: list[str] | set[str] | tuple[str, ...] | None = None,
    min_time: int | str | None = None,
    max_time: int | str | None = None,
    min_flow_count: int = 0,
) -> dict:
    """Compute exact delta between two verified DSSEv1 Ed25519 envelopes.

    Refuses outright (raises VerificationError) if either envelope fails
    signature verification. Marks the view ``EXPIRED`` if either envelope is
    expired. Draws and lists ONLY the delta: new nodes/edges, vanished
    nodes/edges, and edges whose evidence changed.
    """
    t0 = time.perf_counter()
    graph_a_raw, proof_a = load_verified_or_expired(envelope_a, public_key, now=now)
    graph_b_raw, proof_b = load_verified_or_expired(envelope_b, public_key, now=now)

    flt = _normalize_filters(
        layers=layers,
        min_time=min_time,
        max_time=max_time,
        min_flow_count=min_flow_count,
    )
    graph_a = filter_graph(
        graph_a_raw,
        layers=flt["layers"],
        min_time=flt["min_time"],
        max_time=flt["max_time"],
        min_flow_count=flt["min_flow_count"],
    )
    graph_b = filter_graph(
        graph_b_raw,
        layers=flt["layers"],
        min_time=flt["min_time"],
        max_time=flt["max_time"],
        min_flow_count=flt["min_flow_count"],
    )

    nodes_a = {n.id: n for n in graph_a.nodes}
    nodes_b = {n.id: n for n in graph_b.nodes}
    edges_a = {e.key(): e for e in graph_a.edges}
    edges_b = {e.key(): e for e in graph_b.edges}

    added_node_ids = sorted(set(nodes_b) - set(nodes_a))
    removed_node_ids = sorted(set(nodes_a) - set(nodes_b))

    added_nodes = [nodes_b[nid].to_dict() for nid in added_node_ids]
    removed_nodes = [nodes_a[nid].to_dict() for nid in removed_node_ids]

    added_edge_keys = sorted(set(edges_b) - set(edges_a))
    removed_edge_keys = sorted(set(edges_a) - set(edges_b))
    common_edge_keys = sorted(set(edges_a) & set(edges_b))

    added_edges = [_edge_to_render_dict(edges_b[k], change="added") for k in added_edge_keys]
    removed_edges = [_edge_to_render_dict(edges_a[k], change="removed") for k in removed_edge_keys]
    changed_edges: list[dict] = []

    for k in common_edge_keys:
        ea = edges_a[k]
        eb = edges_b[k]
        if (
            ea.evidence.flow_count != eb.evidence.flow_count
            or ea.evidence.first_seen != eb.evidence.first_seen
            or ea.evidence.last_seen != eb.evidence.last_seen
            or sorted(ea.evidence.sources) != sorted(eb.evidence.sources)
        ):
            changed_edges.append(
                _edge_to_render_dict(
                    eb,
                    change="changed",
                    before=ea.evidence.to_dict(),
                    after=eb.evidence.to_dict(),
                    flow_delta=eb.evidence.flow_count - ea.evidence.flow_count,
                )
            )

    # Build delta-only subgraph for WebGL rendering
    render_edges = added_edges + removed_edges + changed_edges
    delta_node_ids = set(added_node_ids) | set(removed_node_ids)
    for e in render_edges:
        delta_node_ids.add(e["source"])
        delta_node_ids.add(e["target"])

    added_set = set(added_node_ids)
    removed_set = set(removed_node_ids)
    render_nodes: list[dict] = []
    for nid in sorted(delta_node_ids):
        if nid in added_set:
            render_nodes.append(_node_to_render_dict(nodes_b[nid], change="added"))
        elif nid in removed_set:
            render_nodes.append(_node_to_render_dict(nodes_a[nid], change="removed"))
        else:
            node = nodes_b.get(nid) or nodes_a.get(nid)
            if node is not None:
                render_nodes.append(_node_to_render_dict(node, change="context"))

    render_nodes = _layout_grid_or_circle(render_nodes)

    combined_status = (
        "expired"
        if (proof_a["status"] == "expired" or proof_b["status"] == "expired")
        else "verified"
    )
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "view": "diff",
        "proof": {
            "status": combined_status,
            "envelope_id": f"{proof_a['envelope_id']} -> {proof_b['envelope_id']}",
            "envelope_id_a": proof_a["envelope_id"],
            "envelope_id_b": proof_b["envelope_id"],
            "proof_a": proof_a,
            "proof_b": proof_b,
        },
        "filters": flt,
        "summary": {
            "added_nodes": len(added_nodes),
            "removed_nodes": len(removed_nodes),
            "added_edges": len(added_edges),
            "removed_edges": len(removed_edges),
            "changed_edges": len(changed_edges),
            "total_delta_nodes": len(render_nodes),
            "total_delta_edges": len(render_edges),
            "source_a_nodes": len(graph_a_raw.nodes),
            "source_a_edges": len(graph_a_raw.edges),
            "source_b_nodes": len(graph_b_raw.nodes),
            "source_b_edges": len(graph_b_raw.edges),
        },
        "delta": {
            "added_nodes": added_nodes,
            "removed_nodes": removed_nodes,
            "added_edges": added_edges,
            "removed_edges": removed_edges,
            "changed_edges": changed_edges,
        },
        "graph": {
            "nodes": render_nodes,
            "edges": render_edges,
        },
        "timing_ms": elapsed_ms,
    }


# ---------------------------------------------------------------------------
# Item 2 — Ego View (Start from a Node)
# ---------------------------------------------------------------------------


def search_nodes(
    graph: DependencyGraph,
    query: str = "",
    *,
    limit: int = 50,
) -> list[dict]:
    """Fast case-insensitive node search by id, substrate, kind, or label."""
    q = (query or "").strip().lower()
    exact: list[ServiceNode] = []
    prefix: list[ServiceNode] = []
    substring: list[ServiceNode] = []

    for node in graph.nodes:
        nid = node.id.lower()
        if not q:
            substring.append(node)
            continue
        if nid == q:
            exact.append(node)
        elif nid.startswith(q):
            prefix.append(node)
        elif (
            q in nid
            or q in node.substrate.lower()
            or q in node.kind.lower()
            or any(q in str(v).lower() for v in node.labels.values())
        ):
            substring.append(node)

    ordered = exact + prefix + substring
    return [
        {
            "id": n.id,
            "kind": n.kind,
            "substrate": n.substrate,
            "labels": n.labels,
        }
        for n in ordered[: max(1, int(limit))]
    ]


def build_ego_view(
    graph: DependencyGraph,
    proof: dict,
    center_node: str,
    *,
    rings: int = 1,
    layers: list[str] | set[str] | tuple[str, ...] | None = None,
    min_time: int | str | None = None,
    max_time: int | str | None = None,
    min_flow_count: int = 0,
) -> dict:
    """Build an N-ring ego subgraph around ``center_node``.

    Never auto-expands the whole estate: expands strictly ``rings`` hops
    (1 ring at a time on click). Distinguishes upstream vs. downstream on
    every edge and reports blast-radius counts by ring.
    """
    t0 = time.perf_counter()
    rings = max(1, min(6, int(rings)))
    node_map = {n.id: n for n in graph.nodes}
    if center_node not in node_map:
        raise KeyError(f"node {center_node!r} not found in graph")

    flt = _normalize_filters(
        layers=layers,
        min_time=min_time,
        max_time=max_time,
        min_flow_count=min_flow_count,
    )
    filtered = filter_graph(
        graph,
        layers=flt["layers"],
        min_time=flt["min_time"],
        max_time=flt["max_time"],
        min_flow_count=flt["min_flow_count"],
        keep_isolated_nodes=True,
    )

    out_adj: dict[str, list[Edge]] = defaultdict(list)
    in_adj: dict[str, list[Edge]] = defaultdict(list)
    for edge in filtered.edges:
        out_adj[edge.source].append(edge)
        in_adj[edge.target].append(edge)

    # Undirected ring distance from center
    ring_of: dict[str, int] = {center_node: 0}
    queue: deque[str] = deque([center_node])
    has_more_rings = False

    while queue:
        cur = queue.popleft()
        dist = ring_of[cur]
        neighbors = [e.target for e in out_adj.get(cur, ())] + [
            e.source for e in in_adj.get(cur, ())
        ]
        for nb in neighbors:
            if nb not in ring_of:
                if dist < rings:
                    ring_of[nb] = dist + 1
                    queue.append(nb)
                else:
                    has_more_rings = True

    # Directed downstream (center -> ...) and upstream (... -> center) distances
    downstream_dist: dict[str, int] = {center_node: 0}
    dq: deque[str] = deque([center_node])
    while dq:
        cur = dq.popleft()
        d = downstream_dist[cur]
        if d >= rings:
            continue
        for e in out_adj.get(cur, ()):
            if e.target not in downstream_dist:
                downstream_dist[e.target] = d + 1
                dq.append(e.target)

    upstream_dist: dict[str, int] = {center_node: 0}
    uq: deque[str] = deque([center_node])
    while uq:
        cur = uq.popleft()
        d = upstream_dist[cur]
        if d >= rings:
            continue
        for e in in_adj.get(cur, ()):
            if e.source not in upstream_dist:
                upstream_dist[e.source] = d + 1
                uq.append(e.source)

    reached = set(ring_of)
    render_edges: list[dict] = []
    seen_edge_keys: set[tuple] = set()
    for nid in reached:
        for edge in out_adj.get(nid, ()):
            if edge.target not in reached:
                continue
            ek = edge.key()
            if ek in seen_edge_keys:
                continue
            seen_edge_keys.add(ek)
            if edge.source == center_node or (
                edge.source in downstream_dist
                and edge.target in downstream_dist
                and downstream_dist[edge.target] > downstream_dist[edge.source]
            ):
                direction = "downstream"
            elif edge.target == center_node or (
                edge.target in upstream_dist
                and edge.source in upstream_dist
                and upstream_dist[edge.source] > upstream_dist[edge.target]
            ):
                direction = "upstream"
            else:
                direction = "lateral"
            render_edges.append(_edge_to_render_dict(edge, direction=direction))

    render_nodes: list[dict] = []
    for nid in sorted(reached, key=lambda x: (ring_of[x], x)):
        node = node_map.get(nid) or ServiceNode(id=nid)
        role = "center"
        if nid != center_node:
            in_ds = nid in downstream_dist
            in_us = nid in upstream_dist
            if in_ds and in_us:
                role = "both"
            elif in_ds:
                role = "downstream"
            elif in_us:
                role = "upstream"
            else:
                role = "neighbor"
        render_nodes.append(
            _node_to_render_dict(node, ring=ring_of[nid], direction_role=role)
        )

    render_nodes = _layout_radial(render_nodes, center_id=center_node)

    # Blast-radius readout by ring
    by_ring: dict[str, int] = {}
    downstream_by_ring: dict[str, int] = {}
    upstream_by_ring: dict[str, int] = {}
    for r in range(1, rings + 1):
        by_ring[str(r)] = sum(1 for n, d in ring_of.items() if d == r)
        downstream_by_ring[str(r)] = sum(
            1 for n, d in downstream_dist.items() if d == r
        )
        upstream_by_ring[str(r)] = sum(
            1 for n, d in upstream_dist.items() if d == r
        )

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "view": "ego",
        "proof": proof,
        "filters": flt,
        "center": center_node,
        "rings": rings,
        "has_more_rings": has_more_rings,
        "blast_radius": {
            "total_reached": len(reached) - 1,
            "by_ring": by_ring,
            "downstream_by_ring": downstream_by_ring,
            "upstream_by_ring": upstream_by_ring,
            "total_downstream": max(0, len(downstream_dist) - 1),
            "total_upstream": max(0, len(upstream_dist) - 1),
        },
        "graph": {
            "nodes": render_nodes,
            "edges": render_edges,
        },
        "timing_ms": elapsed_ms,
    }


# ---------------------------------------------------------------------------
# Item 3 — Findings-First View
# ---------------------------------------------------------------------------


def build_findings_view(
    graph: DependencyGraph,
    proof: dict,
    declared: DeclaredModel,
    *,
    selected_index: int = 0,
    max_context_edges: int = 80,
    layers: list[str] | set[str] | tuple[str, ...] | None = None,
    min_time: int | str | None = None,
    max_time: int | str | None = None,
    min_flow_count: int = 0,
) -> dict:
    """Open on reconciliation findings; draw only the focused subgraph for the selected finding."""
    t0 = time.perf_counter()
    flt = _normalize_filters(
        layers=layers,
        min_time=min_time,
        max_time=max_time,
        min_flow_count=min_flow_count,
    )
    filtered = filter_graph(
        graph,
        layers=flt["layers"],
        min_time=flt["min_time"],
        max_time=flt["max_time"],
        min_flow_count=flt["min_flow_count"],
        keep_isolated_nodes=True,
    )
    report = reconcile(filtered, declared)

    findings: list[dict] = []
    for item in report["observed_undeclared"]:
        findings.append(
            {
                "finding_type": "observed_undeclared",
                "severity": item["severity"],
                "source": item["source"],
                "target": item["target"],
                "target_kind": item.get("target_kind", "unknown"),
                "observations": item.get("observations", []),
            }
        )
    for item in report["declared_unobserved"]:
        findings.append(
            {
                "finding_type": "declared_unobserved",
                "severity": item["severity"],
                "source": item["source"],
                "target": item["target"],
                "note": item.get("note", ""),
                "observations": [],
            }
        )

    sev_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(
        key=lambda f: (
            sev_rank.get(f["severity"], 9),
            f["finding_type"],
            f["source"],
            f["target"],
        )
    )
    for idx, f in enumerate(findings):
        f["index"] = idx

    node_map = {n.id: n for n in filtered.nodes}
    pinned: dict | None = None
    render_nodes: list[dict] = []
    render_edges: list[dict] = []

    if findings:
        idx = max(0, min(int(selected_index), len(findings) - 1))
        pinned = findings[idx]
        src_id = pinned["source"]
        tgt_id = pinned["target"]
        focus_ids = {src_id, tgt_id}

        # Collect edges touching source or target (capped for 10k+ scale)
        finding_edges: list[dict] = []
        context_edges: list[dict] = []
        for edge in filtered.edges:
            if edge.source == src_id and edge.target == tgt_id:
                finding_edges.append(
                    _edge_to_render_dict(edge, finding_role=pinned["finding_type"])
                )
            elif edge.source in focus_ids or edge.target in focus_ids:
                if len(context_edges) < max_context_edges:
                    context_edges.append(
                        _edge_to_render_dict(edge, finding_role="context")
                    )

        if not finding_edges and pinned["finding_type"] == "declared_unobserved":
            finding_edges.append(
                {
                    "source": src_id,
                    "target": tgt_id,
                    "port": None,
                    "protocol": None,
                    "layer": LAYER_NETWORK,
                    "flow_count": 0,
                    "first_seen": 0,
                    "last_seen": 0,
                    "sources": ["declared"],
                    "low_frequency": False,
                    "finding_role": "declared_unobserved",
                }
            )

        render_edges = finding_edges + context_edges
        sub_node_ids = {src_id, tgt_id}
        for e in render_edges:
            sub_node_ids.add(e["source"])
            sub_node_ids.add(e["target"])

        for nid in sorted(sub_node_ids):
            node = node_map.get(nid) or ServiceNode(id=nid, kind="declared", substrate="declared")
            if nid == src_id:
                role, ring = "finding_source", 0
            elif nid == tgt_id:
                role, ring = "finding_target", 1
            else:
                role, ring = "context", 2
            render_nodes.append(_node_to_render_dict(node, finding_role=role, ring=ring))

        render_nodes = _layout_radial(render_nodes, center_id=src_id)

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "view": "findings",
        "proof": proof,
        "filters": flt,
        "summary": report["summary"],
        "findings": findings,
        "selected_index": pinned["index"] if pinned is not None else None,
        "pinned_finding": pinned,
        "graph": {
            "nodes": render_nodes,
            "edges": render_edges,
        },
        "timing_ms": elapsed_ms,
    }


# ---------------------------------------------------------------------------
# Item 4 — Zoom Levels (Estate -> Segment -> Service -> Instance)
# ---------------------------------------------------------------------------


def _segment_of(node: ServiceNode, group_by: str) -> str:
    if group_by == "namespace":
        return str(
            node.labels.get("namespace")
            or node.labels.get("segment")
            or node.substrate
            or "default"
        )
    if group_by.startswith("label:"):
        key = group_by.split(":", 1)[1]
        return str(node.labels.get(key) or node.substrate or "default")
    return str(node.substrate or "unknown")


def _subsegment_of(node: ServiceNode) -> str:
    return str(
        node.labels.get("namespace")
        or node.labels.get("segment")
        or node.labels.get("tier")
        or node.labels.get("env")
        or node.kind
        or "default"
    )


def _service_family_of(node: ServiceNode) -> str:
    explicit = node.labels.get("service") or node.labels.get("app")
    if explicit:
        return str(explicit)
    # Strip trailing numeric instance suffix like "svc-001" -> "svc"
    parts = node.id.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return node.id


def _hierarchy_path(node: ServiceNode, group_by: str = "substrate") -> tuple[str, str, str, str]:
    """Return (estate_group, segment_group, service_group, instance_id) for a node."""
    g_estate = _segment_of(node, group_by)
    g_segment = f"{g_estate}/{_subsegment_of(node)}"
    g_service = f"{g_segment}/{_service_family_of(node)}"
    return (g_estate, g_segment, g_service, node.id)


def build_zoom_view(
    graph: DependencyGraph,
    proof: dict,
    *,
    level: str = "estate",
    parent_group: str | None = None,
    group_by: str = "substrate",
    layers: list[str] | set[str] | tuple[str, ...] | None = None,
    min_time: int | str | None = None,
    max_time: int | str | None = None,
    min_flow_count: int = 0,
) -> dict:
    """Aggregate nodes into group nodes at ``estate | segment | service | instance``.

    Edges between groups are rolled up and weighted by summed ``flow_count``.
    Passing ``parent_group`` expands that group down one level; omitting it (or
    stepping up to ``parent_level``) collapses back to the parent roll-up.
    """
    t0 = time.perf_counter()
    if level not in ZOOM_LEVELS:
        raise ValueError(f"unsupported zoom level {level!r}; expected one of {ZOOM_LEVELS}")
    level_idx = ZOOM_LEVELS.index(level)

    flt = _normalize_filters(
        layers=layers,
        min_time=min_time,
        max_time=max_time,
        min_flow_count=min_flow_count,
    )
    filtered = filter_graph(
        graph,
        layers=flt["layers"],
        min_time=flt["min_time"],
        max_time=flt["max_time"],
        min_flow_count=flt["min_flow_count"],
        keep_isolated_nodes=True,
    )

    node_paths: dict[str, tuple[str, str, str, str]] = {}
    for n in filtered.nodes:
        node_paths[n.id] = _hierarchy_path(n, group_by=group_by)

    # Determine which group ID each node maps to at the current zoom level
    group_members: dict[str, list[ServiceNode]] = defaultdict(list)
    node_to_group: dict[str, str] = {}
    external_groups: set[str] = set()

    for n in filtered.nodes:
        path = node_paths[n.id]
        if parent_group and level_idx > 0:
            if path[level_idx - 1] == parent_group:
                gid = path[level_idx]
                node_to_group[n.id] = gid
                group_members[gid].append(n)
            else:
                # Roll outside nodes up to their parent-level group as boundary stubs
                ext_gid = path[level_idx - 1]
                node_to_group[n.id] = ext_gid
                external_groups.add(ext_gid)
        else:
            gid = path[level_idx]
            node_to_group[n.id] = gid
            group_members[gid].append(n)

    # Roll up edges between groups, weighted by summed flow_count
    rolled: dict[tuple[str, str], dict] = {}
    active_external: set[str] = set()
    for edge in filtered.edges:
        gs = node_to_group.get(edge.source)
        gt = node_to_group.get(edge.target)
        if not gs or not gt:
            continue
        if parent_group and level_idx > 0:
            # Skip edges completely outside the expanded parent group
            if gs in external_groups and gt in external_groups:
                continue
            if gs in external_groups:
                active_external.add(gs)
            if gt in external_groups:
                active_external.add(gt)
        if gs == gt:
            continue
        key = (gs, gt)
        acc = rolled.get(key)
        if acc is None:
            acc = {
                "source": gs,
                "target": gt,
                "flow_count": 0,
                "edge_count": 0,
                "layers": set(),
                "first_seen": edge.evidence.first_seen,
                "last_seen": edge.evidence.last_seen,
            }
            rolled[key] = acc
        acc["flow_count"] += edge.evidence.flow_count
        acc["edge_count"] += 1
        acc["layers"].add(edge.layer)
        if edge.evidence.first_seen and (
            not acc["first_seen"] or edge.evidence.first_seen < acc["first_seen"]
        ):
            acc["first_seen"] = edge.evidence.first_seen
        if edge.evidence.last_seen > acc["last_seen"]:
            acc["last_seen"] = edge.evidence.last_seen

    render_nodes: list[dict] = []
    for gid in sorted(group_members):
        members = group_members[gid]
        sample = members[0]
        can_expand = level_idx < len(ZOOM_LEVELS) - 1 and (
            len(members) > 1 or level != "instance"
        )
        render_nodes.append(
            {
                "id": gid,
                "label": gid.rsplit("/", 1)[-1] if "/" in gid else gid,
                "kind": "group" if level != "instance" else sample.kind,
                "substrate": sample.substrate,
                "member_count": len(members),
                "level": level,
                "expandable": can_expand,
                "boundary": False,
            }
        )

    for ext_gid in sorted(active_external):
        if ext_gid not in group_members:
            render_nodes.append(
                {
                    "id": ext_gid,
                    "label": f"[ext] {ext_gid.rsplit('/', 1)[-1]}",
                    "kind": "boundary",
                    "substrate": ext_gid.split("/", 1)[0],
                    "member_count": 0,
                    "level": ZOOM_LEVELS[max(0, level_idx - 1)],
                    "expandable": False,
                    "boundary": True,
                }
            )

    render_nodes = _layout_grid_or_circle(render_nodes)

    render_edges: list[dict] = []
    for (gs, gt) in sorted(rolled):
        acc = rolled[(gs, gt)]
        layers_sorted = sorted(acc["layers"])
        render_edges.append(
            {
                "source": gs,
                "target": gt,
                "layer": layers_sorted[0] if len(layers_sorted) == 1 else "multi",
                "layers": layers_sorted,
                "flow_count": acc["flow_count"],
                "edge_count": acc["edge_count"],
                "first_seen": acc["first_seen"],
                "last_seen": acc["last_seen"],
            }
        )

    # Breadcrumb / collapse navigation
    parent_level = ZOOM_LEVELS[level_idx - 1] if level_idx > 0 else None
    next_level = ZOOM_LEVELS[level_idx + 1] if level_idx < len(ZOOM_LEVELS) - 1 else None
    grandparent_group = (
        parent_group.rsplit("/", 1)[0]
        if (parent_group and "/" in parent_group)
        else None
    )

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "view": "zoom",
        "proof": proof,
        "filters": flt,
        "level": level,
        "parent_group": parent_group,
        "group_by": group_by,
        "navigation": {
            "parent_level": parent_level,
            "grandparent_group": grandparent_group,
            "next_level": next_level,
        },
        "summary": {
            "total_estate_nodes": len(filtered.nodes),
            "total_estate_edges": len(filtered.edges),
            "group_nodes": len(group_members),
            "boundary_nodes": len(active_external),
            "rolled_edges": len(render_edges),
            "total_rolled_flows": sum(e["flow_count"] for e in render_edges),
        },
        "graph": {
            "nodes": render_nodes,
            "edges": render_edges,
        },
        "timing_ms": elapsed_ms,
    }


# ---------------------------------------------------------------------------
# Self-Contained Interactive WebGL Explorer HTML
# ---------------------------------------------------------------------------


def render_explorer_html(
    *,
    initial_data: dict | None = None,
    api_base: str = "/api/explorer",
    title: str = "G1-Manifest — Interactive WebGL Explorer",
) -> str:
    """Render the self-contained WebGL Explorer HTML page.

    Zero external CDN or npm dependencies. Uses WebGL (batched ``gl.LINES`` +
    ``gl.POINTS`` + orthographic pan/zoom + hit-testing + 2D label overlay,
    with automatic Canvas2D fallback) to stay smooth at 10,000+ nodes.

    Can run either:
    - Live against ``serve.py`` (``api_base="/api/explorer"``), or
    - Offline standalone (``initial_data`` embedded directly from CLI).
    """
    logo_uri = logo_data_uri()
    logo_img = (
        f'<img class="brand-logo" src="{logo_uri}" alt="G1 Logo">'
        if logo_uri
        else ""
    )
    boot_payload = json.dumps(
        {
            "api_base": api_base,
            "initial": initial_data,
        },
        separators=(",", ":"),
    ).replace("</", "<\\/")

    # Compute initial server-side proof banner for immediate visibility
    banner_status = "verified"
    banner_text = "Ready — load a verified signed envelope or demo pair"
    banner_env = ""
    if initial_data:
        for key in ("diff", "ego", "findings", "zoom"):
            if key in initial_data and isinstance(initial_data[key], dict):
                p = initial_data[key].get("proof") or {}
                banner_status = p.get("status", "verified")
                banner_env = p.get("envelope_id", "")
                banner_text = (
                    "EXPIRED ENVELOPE — historical view only, do not treat as current"
                    if banner_status == "expired"
                    else "VERIFIED DSSEv1 Ed25519 ENVELOPE"
                )
                break

    badge_cls = "badge-expired" if banner_status == "expired" else "badge-verified"
    badge_lbl = "EXPIRED" if banner_status == "expired" else "VERIFIED"

    return (
        "<!DOCTYPE html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{html.escape(title)}</title>"
        f"<style>{_EXPLORER_CSS}</style>"
        "</head><body>"
        '<header class="topbar">'
        '<div class="brand">'
        f"{logo_img}"
        '<div><h1>G1-Manifest Explorer</h1>'
        '<div class="sub">Interactive WebGL Graph Explorer · Diff · Ego · Findings · Zoom</div>'
        "</div></div>"
        '<div class="proof-banner" id="proof-banner">'
        f'<span class="proof-badge {badge_cls}" id="proof-badge">{badge_lbl}</span>'
        '<div class="proof-meta">'
        f'<div id="proof-detail">{html.escape(banner_text)}</div>'
        f'<code id="proof-env-id">{html.escape(banner_env)}</code>'
        "</div></div>"
        '<div class="top-actions">'
        '<a class="btn-secondary" href="/">Dashboard</a>'
        '<button type="button" class="btn-secondary" id="btn-fit">Fit View</button>'
        "</div>"
        "</header>"
        '<nav class="toolbar">'
        '<div class="tabs">'
        '<button type="button" class="tab active" data-view="diff">1. Diff View</button>'
        '<button type="button" class="tab" data-view="ego">2. Ego View</button>'
        '<button type="button" class="tab" data-view="findings">3. Findings-First</button>'
        '<button type="button" class="tab" data-view="zoom">4. Zoom Levels</button>'
        "</div>"
        '<div class="filters">'
        '<label><input type="checkbox" class="flt-layer" value="network" checked> network</label>'
        '<label><input type="checkbox" class="flt-layer" value="lineage" checked> lineage</label>'
        '<label><input type="checkbox" class="flt-layer" value="package" checked> package</label>'
        '<label><input type="checkbox" class="flt-layer" value="observed-load" checked> observed-load</label>'
        '<label>Min flows <input type="number" id="flt-min-flow" value="0" min="0" style="width:64px"></label>'
        '<label>From <input type="text" id="flt-min-time" placeholder="epoch or ISO" style="width:128px"></label>'
        '<label>To <input type="text" id="flt-max-time" placeholder="epoch or ISO" style="width:128px"></label>'
        '<button type="button" class="btn-primary" id="btn-apply-filters">Apply</button>'
        "</div>"
        "</nav>"
        '<main class="workspace">'
        '<aside class="sidebar" id="sidebar">'
        '<div class="card" id="scan-selector-card" hidden>'
        '<h3>Loaded Scan / Signed Envelope</h3>'
        '<div class="input-row"><select id="sel-env-a"></select></div>'
        '<div class="input-row" id="row-env-b"><select id="sel-env-b"></select></div>'
        '<div class="input-row"><a class="btn-secondary" id="btn-dl-env" href="#" download hidden>Download .envelope.json</a></div>'
        "</div>"
        '<div id="view-controls"></div>'
        '<div id="view-details"></div>'
        "</aside>"
        '<section class="stage">'
        '<canvas id="gl-canvas"></canvas>'
        '<canvas id="label-canvas"></canvas>'
        '<div class="hud" id="hud">Renderer: initializing...</div>'
        '<div class="inspector" id="inspector" hidden></div>'
        "</section>"
        "</main>"
        f"<script>window.__G1_EXPLORER_BOOT={boot_payload};</script>"
        f"<script>{_EXPLORER_JS}</script>"
        "</body></html>"
    )


_EXPLORER_CSS = """
:root {
  --bg: #0b1120; --panel: #111827; --border: #1f2937; --text: #e5e7eb;
  --muted: #9ca3af; --accent: #38bdf8; --ok: #22c55e; --warn: #f59e0b; --bad: #ef4444;
}
* { box-sizing: border-box; }
body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, sans-serif; background: var(--bg); color: var(--text); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
.topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 10px 16px; background: #0f172a; border-bottom: 1px solid var(--border); }
.brand { display: flex; align-items: center; gap: 10px; }
.brand-logo { width: 32px; height: 32px; border-radius: 6px; }
.brand h1 { margin: 0; font-size: 16px; }
.sub { font-size: 11px; color: var(--muted); }
.proof-banner { display: flex; align-items: center; gap: 10px; padding: 6px 12px; border-radius: 8px; background: #111827; border: 1px solid var(--border); max-width: 52%; }
.proof-badge { font-weight: 700; font-size: 11px; padding: 3px 8px; border-radius: 999px; letter-spacing: 0.05em; }
.badge-verified { background: rgba(34,197,94,0.18); color: #4ade80; border: 1px solid #22c55e; }
.badge-expired { background: rgba(239,68,68,0.22); color: #fca5a5; border: 1px solid #ef4444; }
.proof-meta { font-size: 11px; line-height: 1.35; overflow: hidden; }
.proof-meta code { color: var(--accent); font-size: 10.5px; display: block; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; }
.top-actions { display: flex; gap: 8px; }
.toolbar { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; padding: 8px 16px; background: var(--panel); border-bottom: 1px solid var(--border); }
.tabs { display: flex; gap: 6px; }
.tab { background: transparent; color: var(--muted); border: 1px solid var(--border); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; }
.tab.active { background: var(--accent); color: #082f49; border-color: var(--accent); }
.filters { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; font-size: 12px; color: var(--muted); }
.filters input[type="number"], .filters input[type="text"] { background: #0b1120; color: var(--text); border: 1px solid var(--border); border-radius: 4px; padding: 3px 6px; font-size: 12px; }
.btn-primary { background: var(--accent); color: #082f49; border: none; padding: 5px 12px; border-radius: 6px; font-weight: 600; font-size: 12px; cursor: pointer; }
.btn-secondary { background: #1e293b; color: var(--text); border: 1px solid #334155; padding: 5px 10px; border-radius: 6px; font-size: 12px; cursor: pointer; text-decoration: none; }
.workspace { flex: 1; display: flex; min-height: 0; }
.sidebar { width: 340px; min-width: 280px; background: var(--panel); border-right: 1px solid var(--border); padding: 12px; overflow-y: auto; display: flex; flex-direction: column; gap: 12px; font-size: 12.5px; }
.card { background: #0b1120; border: 1px solid var(--border); border-radius: 8px; padding: 10px; }
.card h3 { margin: 0 0 8px; font-size: 13px; color: var(--accent); }
.stat-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px; }
.stat { background: #111827; padding: 6px 8px; border-radius: 6px; border: 1px solid var(--border); }
.stat .k { font-size: 10.5px; color: var(--muted); }
.stat .v { font-size: 15px; font-weight: 700; }
.list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 6px; max-height: 260px; overflow-y: auto; }
.list li { padding: 7px 8px; border-radius: 6px; border: 1px solid var(--border); background: #111827; cursor: pointer; font-size: 12px; }
.list li:hover, .list li.selected { border-color: var(--accent); background: #172554; }
.tag { display: inline-block; font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 4px; margin-right: 4px; text-transform: uppercase; }
.tag-added { background: rgba(34,197,94,0.2); color: #4ade80; }
.tag-removed { background: rgba(239,68,68,0.2); color: #f87171; }
.tag-changed { background: rgba(245,158,11,0.2); color: #fbbf24; }
.tag-high { background: rgba(239,68,68,0.25); color: #fca5a5; }
.tag-medium { background: rgba(245,158,11,0.25); color: #fde68a; }
.tag-low { background: rgba(148,163,184,0.2); color: #cbd5e1; }
.stage { flex: 1; position: relative; background: radial-gradient(circle at center, #0f172a 0%, #060a14 100%); overflow: hidden; }
#gl-canvas, #label-canvas { position: absolute; inset: 0; width: 100%; height: 100%; display: block; }
#label-canvas { pointer-events: none; }
.hud { position: absolute; left: 12px; bottom: 12px; background: rgba(15,23,42,0.88); border: 1px solid var(--border); padding: 6px 10px; border-radius: 6px; font-size: 11.5px; color: var(--muted); }
.inspector { position: absolute; right: 12px; top: 12px; width: 280px; background: rgba(15,23,42,0.95); border: 1px solid var(--accent); border-radius: 8px; padding: 10px; font-size: 12px; }
.input-row { display: flex; gap: 6px; margin-bottom: 8px; }
.input-row input, .input-row select { flex: 1; background: #111827; color: var(--text); border: 1px solid var(--border); border-radius: 5px; padding: 5px 8px; font-size: 12px; }
"""

_EXPLORER_JS = r"""
(function() {
  const BOOT = window.__G1_EXPLORER_BOOT || {};
  const API = BOOT.api_base || "/api/explorer";
  const STATE = {
    view: "diff",
    data: null,
    demoCache: null,
    storedEnvelopes: [],
    envA: "__demo__",
    envB: "__demo__",
    egoCenter: "",
    egoRings: 1,
    findingIdx: 0,
    zoomLevel: "estate",
    zoomParent: null,
    zoomGroupBy: "substrate",
    camera: { x: 0, y: 0, scale: 1.0 },
    nodes: [],
    edges: [],
    rendererKind: "none",
  };

  const glCanvas = document.getElementById("gl-canvas");
  const labelCanvas = document.getElementById("label-canvas");
  const hud = document.getElementById("hud");
  const inspector = document.getElementById("inspector");

  // --- WebGL Batched Renderer (with Canvas2D fallback) ---
  let gl = null, progLine = null, progPoint = null;
  let lineBuf = null, pointBuf = null, lineVerts = 0, pointVerts = 0;

  function initWebGL() {
    gl = glCanvas.getContext("webgl", { antialias: true, preserveDrawingBuffer: true });
    if (!gl) {
      STATE.rendererKind = "canvas2d-fallback";
      return;
    }
    STATE.rendererKind = "webgl";
    const vsLine = `
      attribute vec2 a_pos;
      attribute vec4 a_col;
      uniform vec2 u_res;
      uniform vec2 u_cam;
      uniform float u_scale;
      varying vec4 v_col;
      void main() {
        vec2 p = (a_pos - u_cam) * u_scale;
        vec2 clip = (p / (u_res * 0.5));
        gl_Position = vec4(clip.x, -clip.y, 0.0, 1.0);
        v_col = a_col;
      }`;
    const fsLine = `
      precision mediump float;
      varying vec4 v_col;
      void main() { gl_FragColor = v_col; }`;
    const vsPoint = `
      attribute vec2 a_pos;
      attribute vec4 a_col;
      attribute float a_size;
      uniform vec2 u_res;
      uniform vec2 u_cam;
      uniform float u_scale;
      varying vec4 v_col;
      void main() {
        vec2 p = (a_pos - u_cam) * u_scale;
        vec2 clip = (p / (u_res * 0.5));
        gl_Position = vec4(clip.x, -clip.y, 0.0, 1.0);
        gl_PointSize = clamp(a_size * sqrt(u_scale), 4.0, 28.0);
        v_col = a_col;
      }`;
    const fsPoint = `
      precision mediump float;
      varying vec4 v_col;
      void main() {
        vec2 c = gl_PointCoord - vec2(0.5);
        float r = length(c);
        if (r > 0.5) discard;
        float rim = smoothstep(0.38, 0.5, r);
        vec3 col = mix(v_col.rgb, vec3(0.95, 0.98, 1.0), rim * 0.5);
        gl_FragColor = vec4(col, v_col.a);
      }`;

    function compile(type, src) {
      const s = gl.createShader(type);
      gl.shaderSource(s, src);
      gl.compileShader(s);
      return s;
    }
    function link(vs, fs) {
      const p = gl.createProgram();
      gl.attachShader(p, compile(gl.VERTEX_SHADER, vs));
      gl.attachShader(p, compile(gl.FRAGMENT_SHADER, fs));
      gl.linkProgram(p);
      return p;
    }
    progLine = link(vsLine, fsLine);
    progPoint = link(vsPoint, fsPoint);
    lineBuf = gl.createBuffer();
    pointBuf = gl.createBuffer();
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
  }

  function colorForNode(n) {
    if (n.change === "added") return [0.13, 0.77, 0.37, 1.0];
    if (n.change === "removed") return [0.94, 0.27, 0.27, 1.0];
    if (n.direction_role === "center" || n.finding_role === "finding_source") return [0.22, 0.74, 0.97, 1.0];
    if (n.finding_role === "finding_target") return [0.94, 0.27, 0.27, 1.0];
    if (n.direction_role === "downstream") return [0.96, 0.62, 0.04, 1.0];
    if (n.direction_role === "upstream") return [0.66, 0.33, 0.97, 1.0];
    if (n.boundary) return [0.58, 0.64, 0.72, 0.7];
    if (n.kind === "external") return [0.94, 0.27, 0.27, 1.0];
    if (n.kind === "dataset") return [0.18, 0.83, 0.75, 1.0];
    if (n.kind === "group") return [0.22, 0.74, 0.97, 0.95];
    return [0.38, 0.65, 0.98, 0.95];
  }

  function colorForEdge(e) {
    if (e.change === "added") return [0.13, 0.77, 0.37, 0.9];
    if (e.change === "removed") return [0.94, 0.27, 0.27, 0.9];
    if (e.change === "changed") return [0.96, 0.62, 0.04, 0.9];
    if (e.finding_role === "observed_undeclared") return [0.94, 0.27, 0.27, 0.95];
    if (e.finding_role === "declared_unobserved") return [0.96, 0.62, 0.04, 0.95];
    if (e.direction === "downstream") return [0.96, 0.62, 0.04, 0.85];
    if (e.direction === "upstream") return [0.66, 0.33, 0.97, 0.85];
    return [0.58, 0.64, 0.72, 0.45];
  }

  function uploadBuffers() {
    const posById = new Map();
    for (const n of STATE.nodes) posById.set(n.id, n);
    if (!gl) return;

    const lArr = new Float32Array(STATE.edges.length * 12);
    let li = 0;
    for (const e of STATE.edges) {
      const a = posById.get(e.source), b = posById.get(e.target);
      if (!a || !b) continue;
      const c = colorForEdge(e);
      lArr[li++] = a.x; lArr[li++] = a.y; lArr[li++] = c[0]; lArr[li++] = c[1]; lArr[li++] = c[2]; lArr[li++] = c[3];
      lArr[li++] = b.x; lArr[li++] = b.y; lArr[li++] = c[0]; lArr[li++] = c[1]; lArr[li++] = c[2]; lArr[li++] = c[3];
    }
    lineVerts = li / 6;
    gl.bindBuffer(gl.ARRAY_BUFFER, lineBuf);
    gl.bufferData(gl.ARRAY_BUFFER, lArr.subarray(0, li), gl.STATIC_DRAW);

    const pArr = new Float32Array(STATE.nodes.length * 7);
    let pi = 0;
    for (const n of STATE.nodes) {
      const c = colorForNode(n);
      const sz = n.member_count ? Math.min(26, 10 + Math.log2(n.member_count + 1) * 3) : (n.ring === 0 ? 18 : 12);
      pArr[pi++] = n.x; pArr[pi++] = n.y; pArr[pi++] = c[0]; pArr[pi++] = c[1]; pArr[pi++] = c[2]; pArr[pi++] = c[3]; pArr[pi++] = sz;
    }
    pointVerts = STATE.nodes.length;
    gl.bindBuffer(gl.ARRAY_BUFFER, pointBuf);
    gl.bufferData(gl.ARRAY_BUFFER, pArr, gl.STATIC_DRAW);
  }

  function resize() {
    const rect = glCanvas.parentElement.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    glCanvas.width = Math.max(1, Math.floor(rect.width * dpr));
    glCanvas.height = Math.max(1, Math.floor(rect.height * dpr));
    labelCanvas.width = glCanvas.width;
    labelCanvas.height = glCanvas.height;
    if (gl) gl.viewport(0, 0, glCanvas.width, glCanvas.height);
    draw();
  }

  function fitView() {
    if (!STATE.nodes.length) { STATE.camera = { x: 0, y: 0, scale: 1 }; draw(); return; }
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (const n of STATE.nodes) {
      if (n.x < minX) minX = n.x; if (n.x > maxX) maxX = n.x;
      if (n.y < minY) minY = n.y; if (n.y > maxY) maxY = n.y;
    }
    const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
    const spanX = Math.max(120, maxX - minX + 120);
    const spanY = Math.max(120, maxY - minY + 120);
    const scale = Math.min(glCanvas.width / spanX, glCanvas.height / spanY) * 0.85;
    STATE.camera = { x: cx, y: cy, scale: Math.max(0.05, Math.min(4.0, scale)) };
    draw();
  }

  function draw() {
    const t0 = performance.now();
    const w = glCanvas.width, h = glCanvas.height;
    if (gl) {
      gl.clearColor(0.025, 0.04, 0.08, 1.0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      if (lineVerts > 0) {
        gl.useProgram(progLine);
        gl.uniform2f(gl.getUniformLocation(progLine, "u_res"), w, h);
        gl.uniform2f(gl.getUniformLocation(progLine, "u_cam"), STATE.camera.x, STATE.camera.y);
        gl.uniform1f(gl.getUniformLocation(progLine, "u_scale"), STATE.camera.scale);
        gl.bindBuffer(gl.ARRAY_BUFFER, lineBuf);
        const aPos = gl.getAttribLocation(progLine, "a_pos");
        const aCol = gl.getAttribLocation(progLine, "a_col");
        gl.enableVertexAttribArray(aPos);
        gl.enableVertexAttribArray(aCol);
        gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 24, 0);
        gl.vertexAttribPointer(aCol, 4, gl.FLOAT, false, 24, 8);
        gl.drawArrays(gl.LINES, 0, lineVerts);
      }
      if (pointVerts > 0) {
        gl.useProgram(progPoint);
        gl.uniform2f(gl.getUniformLocation(progPoint, "u_res"), w, h);
        gl.uniform2f(gl.getUniformLocation(progPoint, "u_cam"), STATE.camera.x, STATE.camera.y);
        gl.uniform1f(gl.getUniformLocation(progPoint, "u_scale"), STATE.camera.scale);
        gl.bindBuffer(gl.ARRAY_BUFFER, pointBuf);
        const aPos = gl.getAttribLocation(progPoint, "a_pos");
        const aCol = gl.getAttribLocation(progPoint, "a_col");
        const aSz = gl.getAttribLocation(progPoint, "a_size");
        gl.enableVertexAttribArray(aPos);
        gl.enableVertexAttribArray(aCol);
        gl.enableVertexAttribArray(aSz);
        gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 28, 0);
        gl.vertexAttribPointer(aCol, 4, gl.FLOAT, false, 28, 8);
        gl.vertexAttribPointer(aSz, 1, gl.FLOAT, false, 28, 24);
        gl.drawArrays(gl.POINTS, 0, pointVerts);
      }
    }

    // Label overlay (capped at 120 visible labels for smooth 10k+ node fps)
    const ctx = labelCanvas.getContext("2d");
    ctx.clearRect(0, 0, w, h);
    ctx.font = "600 12px system-ui, sans-serif";
    ctx.fillStyle = "#e2e8f0";
    ctx.textAlign = "center";
    let drawn = 0;
    const maxLabels = 120;
    for (const n of STATE.nodes) {
      if (drawn >= maxLabels) break;
      const sx = (n.x - STATE.camera.x) * STATE.camera.scale + w * 0.5;
      const sy = (n.y - STATE.camera.y) * STATE.camera.scale + h * 0.5;
      if (sx < -40 || sx > w + 40 || sy < -20 || sy > h + 20) continue;
      const lbl = n.member_count ? `${n.label} (${n.member_count})` : (n.label || n.id);
      ctx.fillText(lbl, sx, sy + 18);
      drawn++;
    }
    const ms = (performance.now() - t0).toFixed(1);
    hud.textContent = `Renderer: ${STATE.rendererKind.toUpperCase()} · ${STATE.nodes.length} nodes · ${STATE.edges.length} edges · frame ${ms} ms`;
  }

  // Pan / zoom / click hit-testing
  let dragging = false, lastX = 0, lastY = 0, moved = false;
  glCanvas.addEventListener("mousedown", (ev) => { dragging = true; moved = false; lastX = ev.clientX; lastY = ev.clientY; });
  window.addEventListener("mousemove", (ev) => {
    if (!dragging) return;
    const dx = ev.clientX - lastX, dy = ev.clientY - lastY;
    if (Math.abs(dx) + Math.abs(dy) > 2) moved = true;
    const dpr = glCanvas.width / Math.max(1, glCanvas.clientWidth);
    STATE.camera.x -= (dx * dpr) / STATE.camera.scale;
    STATE.camera.y -= (dy * dpr) / STATE.camera.scale;
    lastX = ev.clientX; lastY = ev.clientY;
    draw();
  });
  window.addEventListener("mouseup", () => { dragging = false; });
  glCanvas.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const factor = ev.deltaY < 0 ? 1.15 : 0.87;
    STATE.camera.scale = Math.max(0.05, Math.min(8.0, STATE.camera.scale * factor));
    draw();
  }, { passive: false });

  glCanvas.addEventListener("click", (ev) => {
    if (moved) return;
    const rect = glCanvas.getBoundingClientRect();
    const dpr = glCanvas.width / Math.max(1, rect.width);
    const sx = (ev.clientX - rect.left) * dpr;
    const sy = (ev.clientY - rect.top) * dpr;
    const wx = (sx - glCanvas.width * 0.5) / STATE.camera.scale + STATE.camera.x;
    const wy = (sy - glCanvas.height * 0.5) / STATE.camera.scale + STATE.camera.y;
    let best = null, bestD = (22 / STATE.camera.scale) ** 2;
    for (const n of STATE.nodes) {
      const d2 = (n.x - wx) ** 2 + (n.y - wy) ** 2;
      if (d2 < bestD) { bestD = d2; best = n; }
    }
    if (!best) { inspector.hidden = true; return; }
    showInspector(best);
    if (STATE.view === "zoom" && best.expandable && STATE.data && STATE.data.navigation.next_level) {
      STATE.zoomParent = best.id;
      STATE.zoomLevel = STATE.data.navigation.next_level;
      loadCurrentView();
    } else if (STATE.view === "ego" && best.id !== STATE.egoCenter) {
      STATE.egoCenter = best.id;
      STATE.egoRings = 1;
      loadCurrentView();
    }
  });

  function showInspector(n) {
    inspector.hidden = false;
    inspector.innerHTML = `<strong>${esc(n.id)}</strong><div style="color:#9ca3af;margin-top:4px">` +
      `kind: ${esc(n.kind || "")} · substrate: ${esc(n.substrate || "")}` +
      (n.member_count ? `<br>members: ${n.member_count}` : "") +
      (n.ring !== undefined ? `<br>ring: ${n.ring} (${esc(n.direction_role || "")})` : "") +
      (n.change ? `<br>delta: ${esc(n.change)}` : "") + `</div>`;
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  }

  function getFilters() {
    const layers = Array.from(document.querySelectorAll(".flt-layer:checked")).map((c) => c.value);
    return {
      layers,
      min_flow_count: parseInt(document.getElementById("flt-min-flow").value || "0", 10) || 0,
      min_time: document.getElementById("flt-min-time").value.trim() || null,
      max_time: document.getElementById("flt-max-time").value.trim() || null,
    };
  }

  function updateProofBanner(proof) {
    const badge = document.getElementById("proof-badge");
    const detail = document.getElementById("proof-detail");
    const envId = document.getElementById("proof-env-id");
    const isExp = proof && proof.status === "expired";
    badge.className = "proof-badge " + (isExp ? "badge-expired" : "badge-verified");
    badge.textContent = isExp ? "EXPIRED" : "VERIFIED";
    detail.textContent = isExp
      ? "EXPIRED ENVELOPE — historical view only, never treat as current"
      : "VERIFIED DSSEv1 Ed25519 ENVELOPE";
    envId.textContent = (proof && proof.envelope_id) || "";
  }

  function renderSidebar(data) {
    const ctrl = document.getElementById("view-controls");
    const det = document.getElementById("view-details");
    if (!data) return;

    if (data.view === "diff") {
      const s = data.summary;
      ctrl.innerHTML = `<div class="card"><h3>Diff Summary</h3><div class="stat-grid">` +
        `<div class="stat"><div class="k">Added Nodes</div><div class="v">${s.added_nodes}</div></div>` +
        `<div class="stat"><div class="k">Removed Nodes</div><div class="v">${s.removed_nodes}</div></div>` +
        `<div class="stat"><div class="k">Added Edges</div><div class="v">${s.added_edges}</div></div>` +
        `<div class="stat"><div class="k">Changed / Removed</div><div class="v">${s.changed_edges} / ${s.removed_edges}</div></div>` +
        `</div></div>`;
      const items = [
        ...data.delta.added_edges.map((e) => `<li><span class="tag tag-added">added</span>${esc(e.source)} → ${esc(e.target)} (x${e.flow_count})</li>`),
        ...data.delta.removed_edges.map((e) => `<li><span class="tag tag-removed">removed</span>${esc(e.source)} → ${esc(e.target)}</li>`),
        ...data.delta.changed_edges.map((e) => `<li><span class="tag tag-changed">changed</span>${esc(e.source)} → ${esc(e.target)} (${e.flow_delta >= 0 ? "+" : ""}${e.flow_delta})</li>`),
      ];
      det.innerHTML = `<div class="card"><h3>Delta Edges (${items.length})</h3><ul class="list">${items.join("") || "<li>No delta under current filters.</li>"}</ul></div>`;
    } else if (data.view === "ego") {
      const br = data.blast_radius;
      ctrl.innerHTML = `<div class="card"><h3>Ego Center &amp; Rings</h3>` +
        `<div class="input-row"><input id="ego-search" value="${esc(data.center)}" placeholder="Node ID"><button class="btn-primary" id="btn-ego-go">Go</button></div>` +
        `<div class="input-row"><button class="btn-secondary" id="btn-ring-minus">-1 Ring</button><button class="btn-primary" id="btn-ring-plus">+1 Ring (now ${data.rings})</button></div>` +
        `<div class="stat-grid">` +
        `<div class="stat"><div class="k">Total Reached</div><div class="v">${br.total_reached}</div></div>` +
        `<div class="stat"><div class="k">Up / Down</div><div class="v">${br.total_upstream} / ${br.total_downstream}</div></div>` +
        `</div></div>`;
      document.getElementById("btn-ego-go").onclick = () => { STATE.egoCenter = document.getElementById("ego-search").value.trim(); STATE.egoRings = 1; loadCurrentView(); };
      document.getElementById("btn-ring-plus").onclick = () => { STATE.egoRings = Math.min(6, STATE.egoRings + 1); loadCurrentView(); };
      document.getElementById("btn-ring-minus").onclick = () => { STATE.egoRings = Math.max(1, STATE.egoRings - 1); loadCurrentView(); };
      const ringRows = Object.entries(br.by_ring).map(([r, c]) => `<li>Ring ${r}: <strong>${c}</strong> nodes (up ${br.upstream_by_ring[r] || 0}, down ${br.downstream_by_ring[r] || 0})</li>`);
      det.innerHTML = `<div class="card"><h3>Blast Radius by Ring</h3><ul class="list">${ringRows.join("")}</ul></div>`;
    } else if (data.view === "findings") {
      const p = data.pinned_finding;
      ctrl.innerHTML = `<div class="card"><h3>Pinned Finding Evidence</h3>` + (p
        ? `<div><span class="tag tag-${esc(p.severity)}">${esc(p.severity)}</span><strong>${esc(p.finding_type)}</strong></div>` +
          `<div style="margin-top:6px">${esc(p.source)} → ${esc(p.target)}</div>` +
          `<div style="color:#9ca3af;margin-top:4px">${p.observations && p.observations.length ? "Observed x" + p.observations[0].flow_count : esc(p.note || "Declared but unobserved")}</div>`
        : `<div>No findings under current filters.</div>`) + `</div>`;
      const rows = (data.findings || []).map((f) =>
        `<li class="${f.index === data.selected_index ? "selected" : ""}" data-fidx="${f.index}">` +
        `<span class="tag tag-${esc(f.severity)}">${esc(f.severity)}</span>${esc(f.source)} → ${esc(f.target)}</li>`
      );
      det.innerHTML = `<div class="card"><h3>Reconciliation Findings (${rows.length})</h3><ul class="list">${rows.join("") || "<li>None</li>"}</ul></div>`;
      det.querySelectorAll("li[data-fidx]").forEach((li) => {
        li.onclick = () => { STATE.findingIdx = parseInt(li.dataset.fidx, 10); loadCurrentView(); };
      });
    } else if (data.view === "zoom") {
      const s = data.summary, nav = data.navigation;
      ctrl.innerHTML = `<div class="card"><h3>Zoom Level: ${esc(data.level.toUpperCase())}</h3>` +
        `<div class="input-row"><select id="zoom-by"><option value="substrate"${data.group_by==="substrate"?" selected":""}>Group by Substrate</option><option value="namespace"${data.group_by==="namespace"?" selected":""}>Group by Namespace</option></select>` +
        (nav.parent_level ? `<button class="btn-secondary" id="btn-zoom-up">Collapse ↑</button>` : "") + `</div>` +
        `<div class="stat-grid">` +
        `<div class="stat"><div class="k">Groups Shown</div><div class="v">${s.group_nodes}</div></div>` +
        `<div class="stat"><div class="k">Rolled Flows</div><div class="v">${s.total_rolled_flows}</div></div>` +
        `</div><div style="color:#9ca3af;margin-top:6px;font-size:11px">Click any group node on canvas to expand down one level.</div></div>`;
      document.getElementById("zoom-by").onchange = (ev) => { STATE.zoomGroupBy = ev.target.value; STATE.zoomLevel = "estate"; STATE.zoomParent = null; loadCurrentView(); };
      const btnUp = document.getElementById("btn-zoom-up");
      if (btnUp) btnUp.onclick = () => { STATE.zoomLevel = nav.parent_level; STATE.zoomParent = nav.grandparent_group; loadCurrentView(); };
      const rows = (data.graph.nodes || []).slice(0, 60).map((n) =>
        `<li data-gid="${esc(n.id)}"><strong>${esc(n.label)}</strong> · ${n.member_count || 1} nodes</li>`
      );
      det.innerHTML = `<div class="card"><h3>Groups (${data.graph.nodes.length})</h3><ul class="list">${rows.join("")}</ul></div>`;
      det.querySelectorAll("li[data-gid]").forEach((li) => {
        li.onclick = () => {
          if (nav.next_level) { STATE.zoomParent = li.dataset.gid; STATE.zoomLevel = nav.next_level; loadCurrentView(); }
        };
      });
    }
  }

  function applyViewData(data) {
    STATE.data = data;
    STATE.nodes = (data.graph && data.graph.nodes) || [];
    STATE.edges = (data.graph && data.graph.edges) || [];
    updateProofBanner(data.proof);
    renderSidebar(data);
    uploadBuffers();
    fitView();
  }

  function populateEnvelopeSelectors() {
    const card = document.getElementById("scan-selector-card");
    const selA = document.getElementById("sel-env-a");
    const selB = document.getElementById("sel-env-b");
    const rowB = document.getElementById("row-env-b");
    const dlBtn = document.getElementById("btn-dl-env");
    if (!card || !selA || !selB) return;
    card.hidden = false;
    const opts = [
      `<option value="__demo__">Bundled Demo Estate (A vs B)</option>`,
      ...STATE.storedEnvelopes.map((e) =>
        `<option value="${esc(e.id)}">${esc(e.id)} (${e.size_kb} KB)</option>`
      ),
    ].join("");
    selA.innerHTML = opts;
    selB.innerHTML = opts;
    selA.value = STATE.envA;
    selB.value = STATE.envB;
    rowB.style.display = STATE.view === "diff" ? "flex" : "none";
    const found = STATE.storedEnvelopes.find((e) => e.id === STATE.envA);
    if (found && dlBtn) {
      dlBtn.href = found.download_url;
      dlBtn.hidden = false;
    } else if (dlBtn) {
      dlBtn.hidden = true;
    }
  }

  async function initStoredEnvelopes() {
    if (BOOT.initial) return;
    try {
      const resp = await fetch(`${API}/envelopes`);
      if (resp.ok) {
        const j = await resp.json();
        STATE.storedEnvelopes = Array.isArray(j.envelopes) ? j.envelopes : [];
      }
    } catch (_) {}
    const params = new URLSearchParams(window.location.search);
    const reqEnv = params.get("envelope");
    if (reqEnv && STATE.storedEnvelopes.some((e) => e.id === reqEnv)) {
      STATE.envA = reqEnv;
      STATE.envB = reqEnv;
      STATE.view = "zoom";
      document.querySelectorAll(".tab").forEach((b) => {
        b.classList.toggle("active", b.dataset.view === "zoom");
      });
    }
    populateEnvelopeSelectors();
    const selA = document.getElementById("sel-env-a");
    const selB = document.getElementById("sel-env-b");
    if (selA) selA.onchange = () => {
      STATE.envA = selA.value;
      STATE.egoCenter = "";
      STATE.zoomLevel = "estate";
      STATE.zoomParent = null;
      populateEnvelopeSelectors();
      loadCurrentView();
    };
    if (selB) selB.onchange = () => {
      STATE.envB = selB.value;
      loadCurrentView();
    };
  }

  async function loadCurrentView() {
    if (BOOT.initial && BOOT.initial[STATE.view] && !STATE.demoCache) {
      applyViewData(BOOT.initial[STATE.view]);
      return;
    }
    populateEnvelopeSelectors();
    const flt = getFilters();
    try {
      if (!STATE.demoCache) {
        const res = await fetch(`${API}/demo`);
        if (res.ok) STATE.demoCache = await res.json();
      }
      const isDemo = STATE.envA === "__demo__";
      const body = Object.assign({}, flt, {
        use_demo: isDemo,
        envelope_name: isDemo ? "" : STATE.envA,
        envelope_b_name: STATE.envB === "__demo__" ? "" : STATE.envB,
      });
      let endpoint = `${API}/${STATE.view}`;
      if (STATE.view === "ego") {
        body.center_node = STATE.egoCenter || (isDemo && STATE.demoCache ? STATE.demoCache.default_center : "");
        body.rings = STATE.egoRings;
      } else if (STATE.view === "findings") {
        body.selected_index = STATE.findingIdx;
      } else if (STATE.view === "zoom") {
        body.level = STATE.zoomLevel;
        body.parent_group = STATE.zoomParent;
        body.group_by = STATE.zoomGroupBy;
      }
      const resp = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const json = await resp.json();
      if (json.ok && json.result) {
        if (STATE.view === "ego" && json.result.center) STATE.egoCenter = json.result.center;
        applyViewData(json.result);
      }
    } catch (err) {
      hud.textContent = "Error loading view: " + err;
    }
  }

  document.querySelectorAll(".tab").forEach((btn) => {
    btn.onclick = () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      STATE.view = btn.dataset.view;
      loadCurrentView();
    };
  });
  document.getElementById("btn-apply-filters").onclick = () => loadCurrentView();
  document.getElementById("btn-fit").onclick = () => fitView();
  window.addEventListener("resize", resize);

  initWebGL();
  resize();
  initStoredEnvelopes().then(() => loadCurrentView());
})();
"""
