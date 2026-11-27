"""Atheris coverage-guided fuzzer for standalone HTML witness rendering."""

import json
import sys

import atheris

with atheris.instrument_imports():
    from estate_graph.aggregate import aggregate
    from estate_graph.model import Edge, Evidence, ServiceNode
    from estate_graph.render import render_html


def TestOneInput(data: bytes) -> None:  # noqa: N802
    fdp = atheris.FuzzedDataProvider(data)
    n1 = fdp.ConsumeUnicodeNoSurrogates(48) or "a"
    n2 = fdp.ConsumeUnicodeNoSurrogates(48) or "b"
    if n1 == n2:
        n2 = n2 + "-2"
    title = fdp.ConsumeUnicodeNoSurrogates(48) or "G1-Manifest"
    graph = aggregate(
        [],
        extra_nodes=[
            ServiceNode(id=n1, kind="service", substrate="fuzz"),
            ServiceNode(id=n2, kind="external", substrate="fuzz"),
        ],
        extra_edges=[
            Edge(
                source=n1,
                target=n2,
                port=443,
                protocol="TCP",
                evidence=Evidence(
                    flow_count=1, first_seen=1795716000, last_seen=1795716000, sources=["fuzz"]
                ),
            )
        ],
        issued_at=1795716000,
    )
    out = render_html(graph, title=title)
    marker = '<script type="application/json" id="graph-data">'
    start = out.index(marker) + len(marker)
    end = out.index("</script>", start)
    blob = out[start:end]
    assert "<" not in blob, "Unescaped '<' leaked into embedded JSON script block!"
    json.loads(blob)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
