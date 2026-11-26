"""PC software-package dependency source.

Maps the estate-graph design onto a single machine:
  declared layer  = package-manager metadata (dpkg status, pip Requires-Dist)
                    written by the packager at build time, not reconstructed
                    later by an administrator from memory.
  inventory layer = what is actually installed (dpkg + importlib.metadata).

Edges ride their own layer, "package", so they never enter network
reconciliation or shield decisions. Node ids are namespaced: dpkg:<name>,
pip:<name>. Version constraints are stripped to the bare dependency name;
the full specifier is kept in the source package node's labels where the
manager provides it.
"""

from __future__ import annotations

import re

from ..model import LAYER_PACKAGE, Edge, Evidence, ServiceNode

_SPEC_CUT = re.compile(r"[<>=!~;\[ ]")


def _bare_name(spec: str) -> str:
    name = _SPEC_CUT.split(spec.strip(), 1)[0].strip()
    # dpkg alternatives: "a | b" — take the first alternative, note the rest
    name = name.split("|")[0].strip().lower()
    # dpkg arch qualifier: "python3:any" is the package "python3"
    return name.split(":", 1)[0]


def parse_dpkg_status(text: str, now: int = 0):
    """Parse dpkg /var/lib/dpkg/status text into (nodes, edges)."""
    nodes: dict[str, ServiceNode] = {}
    edges: list[Edge] = []
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        key = None
        for line in block.splitlines():
            if line.startswith((" ", "\t")) and key:
                fields[key] += " " + line.strip()
            elif ":" in line:
                key, val = line.split(":", 1)
                fields[key.strip()] = val.strip()
        name = fields.get("Package")
        if not name or fields.get("Status", "").find("installed") < 0:
            continue
        nid = f"dpkg:{name.lower()}"
        nodes[nid] = ServiceNode(
            id=nid, kind="package", substrate="dpkg",
            labels={"version": fields.get("Version", "")},
        )
        deps = fields.get("Depends", "") + ", " + fields.get("Pre-Depends", "")
        for spec in deps.split(","):
            dep = _bare_name(spec) if spec.strip() else ""
            if not dep or dep == name.lower():
                continue
            tid = f"dpkg:{dep}"
            nodes.setdefault(tid, ServiceNode(id=tid, kind="package", substrate="dpkg"))
            edges.append(Edge(source=nid, target=tid, layer=LAYER_PACKAGE,
                              evidence=Evidence(flow_count=1, first_seen=now,
                                                last_seen=now, sources=["dpkg-status"])))
    return list(nodes.values()), edges


def collect_pip(now: int = 0):
    """Read installed pip distributions via importlib.metadata (live system)."""
    from importlib import metadata

    nodes: dict[str, ServiceNode] = {}
    edges: list[Edge] = []
    for dist in metadata.distributions():
        name = (dist.metadata.get("Name") or "").strip()
        if not name:
            continue
        nid = f"pip:{name.lower()}"
        nodes[nid] = ServiceNode(
            id=nid, kind="package", substrate="pip",
            labels={"version": dist.version or ""},
        )
        for req in dist.requires or []:
            if "extra ==" in req:  # optional extra, not a hard dependency
                continue
            dep = _bare_name(req)
            if not dep or dep == name.lower():
                continue
            tid = f"pip:{dep}"
            nodes.setdefault(tid, ServiceNode(id=tid, kind="package", substrate="pip"))
            edges.append(Edge(source=nid, target=tid, layer=LAYER_PACKAGE,
                              evidence=Evidence(flow_count=1, first_seen=now,
                                                last_seen=now, sources=["pip-metadata"])))
    return list(nodes.values()), edges


def collect_pc(now: int = 0, dpkg_status_path: str = "/var/lib/dpkg/status"):
    """Collect this machine's package graph: dpkg (if present) + pip."""
    nodes, edges = [], []
    try:
        with open(dpkg_status_path, encoding="utf-8", errors="replace") as fh:
            n, e = parse_dpkg_status(fh.read(), now=now)
            nodes += n; edges += e
    except OSError:
        pass
    n, e = collect_pip(now=now)
    nodes += n; edges += e
    return nodes, edges
