"""Atheris coverage-guided fuzzer for Windows/host inventory & loaded-module attribution."""

import sys

import atheris

with atheris.instrument_imports():
    from estate_graph.aggregate import aggregate
    from estate_graph.host_reconcile import host_reconcile
    from estate_graph.serve import _safe_html_name
    from estate_graph.sources.win_inventory import parse_uninstall_keys
    from estate_graph.sources.win_modules import aggregate_module_loads


def TestOneInput(data: bytes) -> None:  # noqa: N802
    fdp = atheris.FuzzedDataProvider(data)
    name = fdp.ConsumeUnicodeNoSurrogates(64)
    safe = _safe_html_name(name)
    assert safe.endswith(".html") and "/" not in safe and "\\" not in safe and ".." not in safe

    rec = {
        "DisplayName": fdp.ConsumeUnicodeNoSurrogates(48),
        "DisplayVersion": fdp.ConsumeUnicodeNoSurrogates(24),
        "Publisher": fdp.ConsumeUnicodeNoSurrogates(32),
        "InstallLocation": fdp.ConsumeUnicodeNoSurrogates(64),
        "KeyPath": fdp.ConsumeUnicodeNoSurrogates(64),
    }
    reg_nodes = parse_uninstall_keys([rec])
    proc_name = fdp.ConsumeUnicodeNoSurrogates(32) or "app.exe"
    mods = [fdp.ConsumeUnicodeNoSurrogates(64) for _ in range(fdp.ConsumeIntInRange(0, 4))]
    m_nodes, m_edges = aggregate_module_loads(
        [(proc_name, mods)],
        now=1795716000,
        install_prefixes=[n.labels.get("install_location", "") for n in reg_nodes],
    )
    graph = aggregate([], extra_nodes=reg_nodes + m_nodes, extra_edges=m_edges, issued_at=1795716000)
    host_reconcile(graph)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
