"""Observed layer for a host: the modules processes actually loaded.

Declarations say what a package *may* load. This source records what
running processes *did* load — file-backed modules from each process's
memory map. It is the host analogue of a flow log: observation, with
the same reconcile question pointed at it. A library loaded by a
process but attributable to no installed package and not part of the
operating system is the unknown-DLL finding (see host_reconcile.py).

Snapshot semantics: one scan is one instant, so every edge's
first_seen and last_seen are the scan time and the evidence window is
zero. Repeated scans widen windows; nothing here pretends otherwise.

Path classification and edge aggregation are pure functions of a
``[(process_name, [module_paths]), ...]`` list — one entry per process,
so the same executable running twice appears twice — and are tested
with Windows paths on Linux. The psutil collection is a thin wrapper.
"""

from __future__ import annotations

import hashlib
import re

from ..model import LAYER_OBSERVED_LOAD, Edge, Evidence, ServiceNode

KIND_SYSTEM_LIBRARY = "system-library"
KIND_LIBRARY = "library"

_SYSTEM_DIRS = ("\\windows\\system32", "\\windows\\syswow64")


class ModuleScanUnavailable(Exception):
    """The module source cannot run here (e.g. psutil not installed)."""


def normalize_fs_path(path: str) -> str:
    """One canonical form for path comparison: backslashes, lowercase."""
    return str(path).replace("/", "\\").strip().lower().rstrip("\\")


def _basename(path: str) -> str:
    return re.split(r"[\\/]", str(path))[-1]


def classify_module_path(path: str) -> str:
    """system-library for the OS's own dirs, library for everything else."""
    norm = normalize_fs_path(path)
    if any(d in norm for d in _SYSTEM_DIRS):
        return KIND_SYSTEM_LIBRARY
    return KIND_LIBRARY


def is_under(path: str, prefix: str) -> bool:
    """True when ``path`` is ``prefix`` itself or lives beneath it."""
    p, pre = normalize_fs_path(path), normalize_fs_path(prefix)
    return bool(pre) and (p == pre or p.startswith(pre + "\\"))


def aggregate_module_loads(
    processes: list[tuple[str, list[str]]],
    now: int = 0,
    install_prefixes: list[str] | None = None,
):
    """Aggregate per-process module lists into (nodes, observed edges).

    ``install_prefixes`` are the InstallLocation paths of inventoried
    packages. A library whose path falls under one is labeled
    ``attributed_to`` that prefix — the simple attribution heuristic:
    the file physically lives inside a package's install tree, so the
    package accounts for it. Longest prefix wins. The heuristic's
    limits (shared install dirs, files copied elsewhere) are real and
    are documented in the README rather than hidden here.
    """
    prefixes = sorted(
        {p for p in (install_prefixes or []) if p},
        key=len,
        reverse=True,
    )
    nodes: dict[str, ServiceNode] = {}
    counts: dict[tuple[str, str], int] = {}
    proc_sightings: dict[str, int] = {}

    # Detect filename collisions across distinct directories (e.g. a
    # sideloaded DLL sharing a name with a System32 library). Unique
    # filenames keep clean `lib:<name>` ids; colliding filenames are
    # disambiguated deterministically by a short hash of their path.
    paths_by_name: dict[str, set[str]] = {}
    for _proc_name, module_paths in processes:
        for path in module_paths:
            filename = _basename(path).lower()
            if filename:
                paths_by_name.setdefault(filename, set()).add(
                    normalize_fs_path(path)
                )

    def _lib_id(filename: str, path: str) -> str:
        if len(paths_by_name.get(filename, ())) <= 1:
            return f"lib:{filename}"
        digest = hashlib.sha256(
            normalize_fs_path(path).encode("utf-8")
        ).hexdigest()[:8]
        return f"lib:{filename}#{digest}"

    for proc_name, module_paths in processes:
        exe = _basename(proc_name).lower() or "unknown"
        proc_id = f"proc:{exe}"
        proc_sightings[proc_id] = proc_sightings.get(proc_id, 0) + 1
        seen_here: set[str] = set()
        for path in module_paths:
            filename = _basename(path).lower()
            if not filename:
                continue
            lib_id = _lib_id(filename, path)
            if lib_id not in nodes:
                labels: dict = {"path": str(path)}
                for prefix in prefixes:
                    if is_under(path, prefix):
                        labels["attributed_to"] = prefix
                        break
                nodes[lib_id] = ServiceNode(
                    id=lib_id,
                    kind=classify_module_path(path),
                    substrate="host",
                    labels=labels,
                )
            if lib_id not in seen_here:
                seen_here.add(lib_id)
                key = (proc_id, lib_id)
                counts[key] = counts.get(key, 0) + 1

    for proc_id, n in sorted(proc_sightings.items()):
        nodes[proc_id] = ServiceNode(
            id=proc_id,
            kind="process",
            substrate="host",
            labels={"processes": n},
        )

    edges = [
        Edge(
            source=proc_id,
            target=lib_id,
            layer=LAYER_OBSERVED_LOAD,
            evidence=Evidence(
                flow_count=count,
                first_seen=now,
                last_seen=now,
                sources=["loaded-modules"],
            ),
        )
        for (proc_id, lib_id), count in sorted(counts.items())
    ]
    return sorted(nodes.values(), key=lambda n: n.id), edges


def _looks_file_backed(path: str | None) -> bool:
    if not path:
        return False
    base = _basename(path)
    return ("/" in path or "\\" in path) and "." in base


def collect_loaded_modules(now: int = 0, install_prefixes: list[str] | None = None):
    """Live wrapper over psutil. Raises ModuleScanUnavailable if the
    psutil dependency is missing; per-process access errors skip that
    process (a scanner that dies on the first protected process scans
    nothing)."""
    try:
        import psutil
    except ImportError as exc:
        raise ModuleScanUnavailable("psutil is not installed") from exc

    processes: list[tuple[str, list[str]]] = []
    for proc in psutil.process_iter(["name"]):
        try:
            paths = sorted(
                {m.path for m in proc.memory_maps() if _looks_file_backed(m.path)}
            )
        except Exception:
            continue  # protected/exited process: skip it, keep scanning
        if paths:
            processes.append(((proc.info.get("name") or "unknown"), paths))
    return aggregate_module_loads(
        processes, now=now, install_prefixes=install_prefixes
    )
