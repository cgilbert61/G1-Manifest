from estate_graph.sources.pc import parse_dpkg_status

DPKG = """\
Package: alpha
Status: install ok installed
Version: 1.2.3
Depends: libc6 (>= 2.36), beta | beta-alt, alpha

Package: beta
Status: install ok installed
Version: 0.9
Pre-Depends: dpkg (>= 1.20)

Package: ghost
Status: deinstall ok config-files
Version: 9.9
Depends: alpha
"""


def test_dpkg_declared_edges_and_installed_only():
    nodes, edges = parse_dpkg_status(DPKG, now=100)
    ids = {n.id for n in nodes}
    assert "dpkg:alpha" in ids and "dpkg:beta" in ids
    assert "dpkg:ghost" not in ids  # config-files only: not installed
    pairs = {(e.source, e.target) for e in edges}
    assert ("dpkg:alpha", "dpkg:libc6") in pairs
    assert ("dpkg:alpha", "dpkg:beta") in pairs  # first alternative taken
    assert ("dpkg:beta", "dpkg:dpkg") in pairs
    assert all(e.layer == "package" for e in edges)
    assert all(e.evidence.sources == ["dpkg-status"] for e in edges)
