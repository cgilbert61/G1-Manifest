"""Windows host scanning: registry inventory, pip inventory, loaded
modules, host reconcile, and the scan-host graph's sign/verify path.

Everything here runs on Linux. The registry parser and the module
aggregation are pure functions fed Windows-shaped fixtures; the one
thing no test can do here is execute a live winreg read — that path is
covered only by the RuntimeError contract below.
"""

import sys

import pytest

from estate_graph.aggregate import aggregate
from estate_graph.host_reconcile import host_reconcile
from estate_graph.model import DependencyGraph, Edge, Evidence, ServiceNode
from estate_graph.sign import generate_keypair, load_private_key, load_public_key, sign_graph
from estate_graph.sources.pip_inventory import parse_distributions
from estate_graph.sources.win_inventory import (
    parse_uninstall_keys,
    read_uninstall_registry,
)
from estate_graph.sources.win_modules import (
    aggregate_module_loads,
    classify_module_path,
)
from estate_graph.verify import verify_envelope

NOW = 1795716000

REGISTRY_RECORDS = [
    {
        "DisplayName": "Contoso Editor",
        "DisplayVersion": "3.1.0",
        "Publisher": "Contoso Ltd",
        "InstallLocation": r"C:\Program Files\Contoso Editor",
        "KeyPath": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\ContosoEditor",
    },
    {
        # Same product, 32-bit hive view: one package, two sources.
        "DisplayName": "Contoso Editor",
        "DisplayVersion": "3.1.0",
        "Publisher": "Contoso Ltd",
        "InstallLocation": r"C:\Program Files\Contoso Editor",
        "KeyPath": r"HKLM\WOW6432Node\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ContosoEditor",
    },
    {
        "DisplayName": "Hidden Helper Component",
        "DisplayVersion": "1.0",
        "SystemComponent": 1,
        "KeyPath": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Helper",
    },
    {
        "DisplayName": "Update for Contoso Editor (KB123)",
        "DisplayVersion": "3.1.1",
        "ParentKeyName": "Contoso Editor",
        "KeyPath": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\KB123",
    },
    {"DisplayVersion": "9.9", "KeyPath": r"HKLM\...\Uninstall\Nameless"},
    {
        "DisplayName": "Microsoft Visual C++ 2019 Redistributable",
        "DisplayVersion": "14.29.30139",
        "Publisher": "Microsoft Corporation",
        "KeyPath": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\VC++",
    },
]

PIP_RECORDS = [
    {
        "name": "WebApp",
        "version": "1.0",
        "requires": [
            "requests (>=2.0)",
            "PyYAML; python_version < '3.12'",
            "pytest; extra == 'test'",
            "typing-extensions[all] (>=4.0)",
        ],
    },
    {
        "name": "requests",
        "version": "2.31.0",
        "requires": ["urllib3 (<3,>=1.21)", "charset_normalizer (<4,>=2)"],
    },
    {"name": "urllib3", "version": "2.0.0", "requires": []},
]

PROCESSES = [
    (
        "ContosoEditor.exe",
        [
            r"C:\Program Files\Contoso Editor\contoso.dll",
            r"C:\Windows\System32\kernel32.dll",
            r"C:\Users\chuck\AppData\Local\Temp\evil.dll",
        ],
    ),
    (
        "ContosoEditor.exe",
        [
            r"C:\Program Files\Contoso Editor\contoso.dll",
            r"C:\Windows\SysWOW64\msvcrt.dll",
        ],
    ),
    ("svchost.exe", [r"C:\Windows\System32\kernel32.dll"]),
]
INSTALL_PREFIXES = [r"C:\Program Files\Contoso Editor"]


# --- registry inventory -------------------------------------------------


def test_registry_parser_dedupes_across_hives():
    nodes = parse_uninstall_keys(REGISTRY_RECORDS)
    contoso = [n for n in nodes if n.id == "pkg:contoso-editor"]
    assert len(contoso) == 1
    assert len(contoso[0].labels["sources"]) == 2


def test_registry_parser_skips_components_updates_and_unnamed():
    ids = {n.id for n in parse_uninstall_keys(REGISTRY_RECORDS)}
    assert ids == {
        "pkg:contoso-editor",
        "pkg:microsoft-visual-c++-2019-redistributable",
    }


def test_registry_parser_keeps_metadata():
    nodes = {n.id: n for n in parse_uninstall_keys(REGISTRY_RECORDS)}
    node = nodes["pkg:contoso-editor"]
    assert node.kind == "package"
    assert node.labels["version"] == "3.1.0"
    assert node.labels["publisher"] == "Contoso Ltd"
    assert node.labels["install_location"] == r"C:\Program Files\Contoso Editor"


@pytest.mark.skipif(sys.platform == "win32", reason="reader works on Windows")
def test_registry_reader_raises_clear_error_off_windows():
    with pytest.raises(RuntimeError, match="only available on Windows"):
        read_uninstall_registry()


# --- pip inventory ------------------------------------------------------


def test_pip_edges_strip_specifiers_and_fold_names():
    _nodes, edges = parse_distributions(PIP_RECORDS, now=NOW)
    pairs = {(e.source, e.target) for e in edges}
    assert ("pkg:webapp", "pkg:requests") in pairs
    assert ("pkg:webapp", "pkg:typing-extensions") in pairs  # extras dropped
    assert ("pkg:requests", "pkg:urllib3") in pairs
    assert ("pkg:requests", "pkg:charset-normalizer") in pairs  # _ folded
    assert all(e.layer == "package" for e in edges)


def test_pip_marker_requirements_are_conditional_not_dropped():
    _nodes, edges = parse_distributions(PIP_RECORDS, now=NOW)
    by_target = {e.target: e for e in edges if e.source == "pkg:webapp"}
    assert by_target["pkg:pyyaml"].labels.get("conditional") is True
    assert by_target["pkg:pytest"].labels.get("conditional") is True
    assert "conditional" not in by_target["pkg:requests"].labels


def test_pip_nodes_carry_version_and_source():
    nodes, _edges = parse_distributions(PIP_RECORDS, now=NOW)
    webapp = {n.id: n for n in nodes}["pkg:webapp"]
    assert webapp.labels["version"] == "1.0"
    assert webapp.labels["source"] == "pip"


# --- loaded modules -----------------------------------------------------


def test_classify_module_path():
    assert classify_module_path(r"C:\Windows\System32\kernel32.dll") == "system-library"
    assert classify_module_path(r"C:\Windows\SysWOW64\msvcrt.dll") == "system-library"
    assert classify_module_path("C:/Windows/System32/drivers/etc.dll") == "system-library"
    assert classify_module_path(r"C:\Program Files\App\app.dll") == "library"
    assert classify_module_path(r"C:\Users\chuck\AppData\Local\Temp\x.dll") == "library"


def test_aggregate_module_loads_counts_processes():
    nodes, edges = aggregate_module_loads(
        PROCESSES, now=NOW, install_prefixes=INSTALL_PREFIXES
    )
    by_id = {n.id: n for n in nodes}
    # Two PIDs of the same exe are one process node with a count of 2.
    assert by_id["proc:contosoeditor.exe"].labels["processes"] == 2
    counts = {(e.source, e.target): e.evidence.flow_count for e in edges}
    assert counts[("proc:contosoeditor.exe", "lib:contoso.dll")] == 2
    assert counts[("proc:contosoeditor.exe", "lib:kernel32.dll")] == 1
    assert counts[("proc:svchost.exe", "lib:kernel32.dll")] == 1
    assert all(e.layer == "observed-load" for e in edges)
    # Attribution: the DLL inside the package's install tree is claimed.
    assert by_id["lib:contoso.dll"].labels["attributed_to"] == INSTALL_PREFIXES[0]
    assert "attributed_to" not in by_id["lib:evil.dll"].labels
    assert by_id["lib:kernel32.dll"].kind == "system-library"


# --- host reconcile -----------------------------------------------------


def _host_graph() -> DependencyGraph:
    nodes = [
        ServiceNode(
            id="pkg:contoso-editor", kind="package", substrate="windows-registry",
            labels={"install_location": r"C:\Program Files\Contoso"},
        ),
        ServiceNode(
            id="pkg:helper", kind="package", substrate="windows-registry",
            labels={"install_location": r"C:\Program Files\Helper"},
        ),
        ServiceNode(id="proc:app.exe", kind="process", substrate="host"),
        ServiceNode(
            id="lib:contoso.dll", kind="library", substrate="host",
            labels={
                "path": r"C:\Program Files\Contoso\contoso.dll",
                "attributed_to": r"C:\Program Files\Contoso",
            },
        ),
        ServiceNode(
            id="lib:evil.dll", kind="library", substrate="host",
            labels={"path": r"C:\Users\chuck\AppData\Local\Temp\evil.dll"},
        ),
        ServiceNode(
            id="lib:stray.dll", kind="library", substrate="host",
            labels={"path": r"C:\Program Files\Other\stray.dll"},
        ),
        ServiceNode(
            id="lib:kernel32.dll", kind="system-library", substrate="host",
            labels={"path": r"C:\Windows\System32\kernel32.dll"},
        ),
    ]

    def ev():
        return Evidence(flow_count=1, first_seen=NOW, last_seen=NOW, sources=["test"])

    edges = [
        Edge(source="pkg:contoso-editor", target="pkg:helper",
             layer="package", evidence=ev()),
        Edge(source="proc:app.exe", target="lib:contoso.dll",
             layer="observed-load", evidence=ev()),
        Edge(source="proc:app.exe", target="lib:evil.dll",
             layer="observed-load", evidence=ev()),
        Edge(source="proc:app.exe", target="lib:stray.dll",
             layer="observed-load", evidence=ev()),
        Edge(source="proc:app.exe", target="lib:kernel32.dll",
             layer="observed-load", evidence=ev()),
    ]
    return DependencyGraph(
        graph_id="host-graph:test", producer="test",
        issued_at=NOW, expires_at=NOW + 86400, nodes=nodes, edges=edges,
    )


def test_host_reconcile_unknown_dll_is_high_severity():
    report = host_reconcile(_host_graph())
    findings = {f["library"]: f for f in report["observed_undeclared"]}
    assert findings["lib:evil.dll"]["severity"] == "high"
    assert findings["lib:stray.dll"]["severity"] == "medium"  # Program Files
    assert "lib:contoso.dll" not in findings  # attributed to its package
    assert "lib:kernel32.dll" not in findings  # operating system


def test_host_reconcile_declared_unobserved_is_informational():
    report = host_reconcile(_host_graph())
    stale = {(f["source"], f["target"]): f for f in report["declared_unobserved"]}
    entry = stale[("pkg:contoso-editor", "pkg:helper")]
    assert entry["severity"] == "info"


# --- scan-host graph through the sign/verify path -----------------------


def test_scan_host_graph_sign_verify_round_trip(tmp_path):
    registry_nodes = parse_uninstall_keys(REGISTRY_RECORDS)
    pip_nodes, pip_edges = parse_distributions(PIP_RECORDS, now=NOW)
    mod_nodes, mod_edges = aggregate_module_loads(
        PROCESSES, now=NOW, install_prefixes=INSTALL_PREFIXES
    )
    graph = aggregate(
        [],
        extra_nodes=registry_nodes + pip_nodes + mod_nodes,
        extra_edges=pip_edges + mod_edges,
        graph_id="host-graph:test",
        producer="estate-graph/scan-host",
        issued_at=NOW,
        ttl_seconds=7 * 86400,
    )
    priv_path, pub_path = generate_keypair(tmp_path)
    envelope = sign_graph(
        graph, load_private_key(priv_path), ttl_seconds=7 * 86400
    )
    verified = verify_envelope(envelope, load_public_key(pub_path), now=NOW + 60)
    assert verified.producer == "estate-graph/scan-host"
    layers = {e.layer for e in verified.edges}
    assert "package" in layers and "observed-load" in layers


def test_scan_host_cli_runs_without_modules(tmp_path):
    from estate_graph.cli import main

    out = tmp_path / "host.json"
    assert main(["scan-host", "--out", str(out), "--no-modules"]) == 0
    import json

    graph = DependencyGraph.from_dict(json.loads(out.read_text()))
    assert graph.producer == "estate-graph/scan-host"
    assert any(n.id.startswith("pkg:") for n in graph.nodes)
