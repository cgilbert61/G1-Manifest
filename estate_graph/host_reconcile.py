"""Host reconciliation: declared packages vs observed loads.

The network reconciler asks "does the estate do things nobody
declared?" This one asks the same question of a single machine, at the
level the data actually supports:

- ``observed_undeclared`` — a process loaded a library that is neither
  an operating-system library nor attributable to any installed
  package's install tree. That is the unknown-DLL case: a forgotten
  side-loaded component, or somebody else's code. Severity is high
  when the path is outside the system dirs *and* outside Program Files
  — user-writable locations (Temp, Downloads, a home directory) are
  where dropped payloads live. Nothing here is auto-attributed after
  the fact; a human decides what the file is.

- ``declared_unobserved`` — a declared package dependency whose
  install tree contributed no loaded library during the scan.
  Informational only, and deliberately so: absence of a load is not
  rot. Loading is opportunistic — a dependency may load only when a
  feature runs, a plugin activates, or an error path executes, and a
  scan is a single instant. The network reconciler's stale-candidate
  logic does not transfer, because network flows repeat on schedules
  and library loads often don't.

Attribution is the install-prefix heuristic from win_modules: a loaded
file physically inside a package's InstallLocation is attributed to
that package. Shared install dirs blur it; files copied out of their
tree escape it. It is a heuristic, labeled as one.
"""

from __future__ import annotations

from .model import LAYER_OBSERVED_LOAD, LAYER_PACKAGE, DependencyGraph
from .sources.win_modules import KIND_SYSTEM_LIBRARY, normalize_fs_path


def host_reconcile(graph: DependencyGraph) -> dict:
    nodes = {n.id: n for n in graph.nodes}
    load_edges = graph.edges_on_layer(LAYER_OBSERVED_LOAD)
    package_edges = graph.edges_on_layer(LAYER_PACKAGE)

    # Install trees that actually contributed a loaded library.
    attributed_prefixes = {
        normalize_fs_path(n.labels["attributed_to"])
        for n in graph.nodes
        if n.labels.get("attributed_to")
    }

    observed_undeclared = []
    attributed_loads = 0
    for edge in load_edges:
        lib = nodes.get(edge.target)
        if lib is None:
            continue
        if lib.kind == KIND_SYSTEM_LIBRARY or lib.labels.get("attributed_to"):
            attributed_loads += 1
            continue
        path = str(lib.labels.get("path", ""))
        norm = normalize_fs_path(path)
        # System dirs are already excluded by the kind check above.
        # What remains: Program Files (medium — plausibly a component
        # the inventory missed) vs anywhere else (high — user-writable
        # paths are the classic drop location).
        severity = "medium" if "\\program files" in norm else "high"
        observed_undeclared.append(
            {
                "process": edge.source,
                "library": edge.target,
                "path": path,
                "severity": severity,
                "loaders": edge.evidence.flow_count,
                "note": "loaded but attributable to no installed package",
            }
        )
    observed_undeclared.sort(key=lambda f: (f["process"], f["library"]))

    declared_unobserved = []
    for edge in package_edges:
        target = nodes.get(edge.target)
        if target is None:
            continue
        install_location = str(target.labels.get("install_location") or "")
        if not install_location:
            # No install tree on record (e.g. a pip package): the data
            # cannot judge whether its files were loaded. Skip rather
            # than guess.
            continue
        if normalize_fs_path(install_location) in attributed_prefixes:
            continue
        declared_unobserved.append(
            {
                "source": edge.source,
                "target": edge.target,
                "severity": "info",
                "note": "declared dependency; no load observed in scan "
                "window (loading is opportunistic — not evidence of rot)",
            }
        )
    declared_unobserved.sort(key=lambda f: (f["source"], f["target"]))

    return {
        "graph_id": graph.graph_id,
        "summary": {
            "observed_undeclared": len(observed_undeclared),
            "declared_unobserved": len(declared_unobserved),
            "attributed_loads": attributed_loads,
        },
        "observed_undeclared": observed_undeclared,
        "declared_unobserved": declared_unobserved,
    }
