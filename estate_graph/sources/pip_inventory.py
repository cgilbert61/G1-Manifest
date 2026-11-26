"""Declared layer, Python packages: importlib.metadata.

Every installed distribution declares its dependencies in its metadata
(``Requires-Dist``) — written by the packager at build time, like dpkg's
Depends lines. This source turns those declarations into package nodes
and ``package``-layer edges in the shared ``pkg:`` namespace, so a pip
package and the same product installed by a Windows installer land on
the same node.

Marker rule, deliberately different from a hard filter: a requirement
carrying an environment marker (``; python_version < "3.12"``) is still
a declared dependency — it just doesn't apply everywhere. The edge is
kept and labeled ``conditional: true``. Dropping it would understate
the graph; treating it as unconditional would overstate it.

The importlib.metadata read is factored behind ``read_distributions``
so the parser is a pure function tests can feed fabricated records.
"""

from __future__ import annotations

import re

from ..model import LAYER_PACKAGE, Edge, Evidence, ServiceNode
from .win_inventory import normalize_pkg_name, pkg_id

_REQ_NAME = re.compile(r"^([A-Za-z0-9._-]+)")


def read_distributions() -> list[dict]:
    """Thin wrapper over importlib.metadata: raw records out."""
    from importlib import metadata

    records = []
    for dist in metadata.distributions():
        name = (dist.metadata.get("Name") or "").strip()
        if not name:
            continue
        records.append(
            {
                "name": name,
                "version": dist.version or "",
                "requires": list(dist.requires or []),
            }
        )
    return records


def _parse_requirement(req: str) -> tuple[str, bool] | None:
    """Split a Requires-Dist string into (bare name, has_marker)."""
    req = req.strip()
    if not req:
        return None
    head, _, marker = req.partition(";")
    match = _REQ_NAME.match(head.strip())
    if not match:
        return None
    return match.group(1), bool(marker.strip())


def parse_distributions(records: list[dict], now: int = 0):
    """Fabricated-or-live distribution records -> (nodes, package edges)."""
    nodes: dict[str, ServiceNode] = {}
    edges: list[Edge] = []

    def node_for(name: str) -> ServiceNode:
        nid = pkg_id(name)
        if nid not in nodes:
            nodes[nid] = ServiceNode(
                id=nid, kind="package", substrate="pip", labels={}
            )
        return nodes[nid]

    for rec in records:
        name = str(rec.get("name") or "").strip()
        if not name:
            continue
        node = node_for(name)
        node.labels.update(
            {"version": str(rec.get("version") or ""), "source": "pip"}
        )
        own = normalize_pkg_name(name)
        for req in rec.get("requires") or []:
            parsed = _parse_requirement(str(req))
            if not parsed:
                continue
            dep_name, conditional = parsed
            if normalize_pkg_name(dep_name) == own:
                continue
            target = node_for(dep_name)
            edges.append(
                Edge(
                    source=node.id,
                    target=target.id,
                    layer=LAYER_PACKAGE,
                    evidence=Evidence(
                        flow_count=1,
                        first_seen=now,
                        last_seen=now,
                        sources=["pip-metadata"],
                    ),
                    labels={"conditional": True} if conditional else {},
                )
            )
    return sorted(nodes.values(), key=lambda n: n.id), edges


def collect_pip_packages(now: int = 0, records: list[dict] | None = None):
    """Live entry point; ``records`` is injectable for tests."""
    if records is None:
        records = read_distributions()
    return parse_distributions(records, now=now)
