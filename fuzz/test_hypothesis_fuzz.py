"""Property-based fuzzing suite for G1-Manifest using Hypothesis.

Exercises all untrusted-input boundaries in-process (cross-platform:
Windows, macOS, Linux, and CI):
- DSSEv1 Ed25519 envelope verification (fail-closed, no unhandled errors)
- Telemetry parsers (AWS VPC Flow Logs, Cilium Hubble JSONL, OpenLineage)
- Host inventory & loaded-module aggregation (DLL sideloading invariant)
- Witness HTML/SVG rendering (XSS/script-breakout & byte determinism)
- HTTP view filename sanitization (path traversal prevention)
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from estate_graph.aggregate import aggregate
from estate_graph.host_reconcile import host_reconcile
from estate_graph.model import Edge, Evidence, ServiceNode
from estate_graph.render import render_html
from estate_graph.serve import _safe_html_name
from estate_graph.sign import PAYLOAD_TYPE, sign_graph
from estate_graph.sources.flowlog import parse_flow_logs
from estate_graph.sources.hubble import parse_hubble
from estate_graph.sources.pip_inventory import parse_distributions
from estate_graph.sources.win_inventory import parse_uninstall_keys
from estate_graph.sources.win_modules import (
    KIND_SYSTEM_LIBRARY,
    aggregate_module_loads,
    classify_module_path,
)
from estate_graph.verify import VerificationError, verify_envelope

_PRIV = Ed25519PrivateKey.generate()
_PUB = _PRIV.public_key()

_JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-10**9, max_value=10**9),
    st.text(max_size=64),
)
_JSON_VALUES = st.recursive(
    _JSON_SCALARS,
    lambda children: st.lists(children, max_size=5)
    | st.dictionaries(st.text(max_size=24), children, max_size=5),
    max_leaves=15,
)

_SETTINGS = settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


@_SETTINGS
@given(envelope=_JSON_VALUES)
def test_fuzz_verify_envelope_fails_closed_on_arbitrary_input(envelope):
    """Any arbitrary object must be rejected with VerificationError, never crash."""
    with pytest.raises(VerificationError):
        verify_envelope(envelope, _PUB, now=1795716000)


@_SETTINGS
@given(
    payload_bytes=st.binary(max_size=256),
    sigs=st.lists(
        st.dictionaries(st.text(max_size=16), _JSON_SCALARS, max_size=4),
        max_size=4,
    ),
)
def test_fuzz_verify_envelope_structured_forgeries_rejected(payload_bytes, sigs):
    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signatures": sigs,
    }
    with pytest.raises(VerificationError):
        verify_envelope(envelope, _PUB, now=1795716000)


@_SETTINGS
@given(
    text=st.text(max_size=512),
    ip_map=st.dictionaries(st.text(max_size=20), st.text(max_size=20), max_size=5),
)
def test_fuzz_parse_flow_logs_never_crashes(text, ip_map):
    obs = parse_flow_logs(text, ip_map)
    for item in obs:
        assert item.count >= 1
        assert item.source != item.target


@_SETTINGS
@given(text=st.text(max_size=512))
def test_fuzz_parse_hubble_never_crashes(text):
    obs = parse_hubble(text)
    for item in obs:
        assert item.count >= 1
        assert item.source != item.target


@_SETTINGS
@given(
    records=st.lists(
        st.fixed_dictionaries(
            {},
            optional={
                "DisplayName": _JSON_SCALARS,
                "DisplayVersion": _JSON_SCALARS,
                "Publisher": _JSON_SCALARS,
                "InstallLocation": _JSON_SCALARS,
                "SystemComponent": _JSON_SCALARS,
                "ParentKeyName": _JSON_SCALARS,
                "KeyPath": _JSON_SCALARS,
            },
        ),
        max_size=12,
    )
)
def test_fuzz_parse_uninstall_keys_never_crashes(records):
    nodes = parse_uninstall_keys(records)
    ids = [n.id for n in nodes]
    assert len(ids) == len(set(ids))


@_SETTINGS
@given(
    records=st.lists(
        st.fixed_dictionaries(
            {},
            optional={
                "name": _JSON_SCALARS,
                "version": _JSON_SCALARS,
                "requires": st.lists(st.text(max_size=40), max_size=6),
            },
        ),
        max_size=10,
    )
)
def test_fuzz_parse_distributions_never_crashes(records):
    nodes, edges = parse_distributions(records, now=1795716000)
    node_ids = {n.id for n in nodes}
    for e in edges:
        assert e.source in node_ids and e.target in node_ids
        assert e.source != e.target


@_SETTINGS
@given(
    dll_name=st.from_regex(r"[a-z0-9_-]{1,16}\.dll", fullmatch=True),
    user_dir=st.from_regex(r"C:\\Users\\[a-z]{1,8}\\Temp", fullmatch=True),
)
def test_fuzz_sideloaded_dll_never_masked_by_system_dll(dll_name, user_dir):
    """Invariant: a user-dir DLL sharing a System32 filename must always surface."""
    sys_path = f"C:\\Windows\\System32\\{dll_name}"
    evil_path = f"{user_dir}\\{dll_name}"
    assert classify_module_path(sys_path) == KIND_SYSTEM_LIBRARY
    assert classify_module_path(evil_path) != KIND_SYSTEM_LIBRARY

    nodes, edges = aggregate_module_loads(
        [("notepad.exe", [sys_path]), ("evil.exe", [evil_path])],
        now=1795716000,
    )
    graph = aggregate([], extra_nodes=nodes, extra_edges=edges, issued_at=1795716000)
    report = host_reconcile(graph)
    assert len(report["observed_undeclared"]) == 1
    assert report["observed_undeclared"][0]["severity"] == "high"


@_SETTINGS
@given(
    node_ids=st.lists(
        st.text(
            alphabet=st.characters(blacklist_categories=("Cs",)),
            min_size=1,
            max_size=40,
        ),
        min_size=1,
        max_size=6,
        unique=True,
    ),
    title=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=40),
)
def test_fuzz_render_html_deterministic_and_script_safe(node_ids, title):
    nodes = [ServiceNode(id=nid, kind="service", substrate="fuzz") for nid in node_ids]
    edges = []
    if len(node_ids) >= 2:
        edges.append(
            Edge(
                source=node_ids[0],
                target=node_ids[1],
                port=443,
                protocol="TCP",
                evidence=Evidence(
                    flow_count=1, first_seen=1795716000, last_seen=1795716000, sources=["fuzz"]
                ),
            )
        )
    graph = aggregate([], extra_nodes=nodes, extra_edges=edges, issued_at=1795716000)
    html1 = render_html(graph, title=title)
    html2 = render_html(graph, title=title)
    assert html1 == html2  # byte-for-byte determinism

    # Embedded JSON blob must never contain raw '<' that could break out of <script>
    start = html1.index('<script type="application/json" id="graph-data">')
    end = html1.index("</script>", start)
    blob_str = html1[start + len('<script type="application/json" id="graph-data">') : end]
    assert "<" not in blob_str
    parsed = json.loads(blob_str)
    assert len(parsed["nodes"]) == len(node_ids)


@_SETTINGS
@given(raw=st.text(max_size=120))
def test_fuzz_safe_html_name_prevents_traversal(raw):
    name = _safe_html_name(raw)
    assert name.endswith(".html")
    assert "/" not in name
    assert "\\" not in name
    assert ".." not in name
    assert "\x00" not in name


@_SETTINGS
@given(ttl=st.integers(min_value=1, max_value=365 * 86400))
def test_fuzz_sign_verify_roundtrip(ttl):
    now = 1795716000
    graph = aggregate(
        [],
        extra_nodes=[ServiceNode(id="svc-a"), ServiceNode(id="svc-b")],
        issued_at=now,
        ttl_seconds=ttl,
    )
    env = sign_graph(graph, _PRIV, ttl_seconds=ttl)
    verified = verify_envelope(env, _PUB, now=now + ttl - 1)
    assert verified.canonical_json() == graph.canonical_json()
    with pytest.raises(VerificationError):
        verify_envelope(env, _PUB, now=now + ttl)
