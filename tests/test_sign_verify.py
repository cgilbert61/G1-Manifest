"""Signing, verification (fail closed, distinct failures), arming gate."""

import base64
import json

import pytest

from estate_graph.model import DependencyGraph
from estate_graph.sign import generate_keypair, load_private_key, load_public_key, sign_graph
from estate_graph.verify import (
    BadSignature,
    ExpiredGraph,
    UnsupportedVersion,
    arming_gate,
    service_egress,
    verify_envelope,
)

NOW = 1795716000 + 3600  # inside the demo graph's validity window


@pytest.fixture()
def keys(tmp_path):
    priv, pub = generate_keypair(tmp_path)
    return load_private_key(priv), load_public_key(pub)


def test_sign_verify_round_trip(demo_graph, keys):
    priv, pub = keys
    envelope = sign_graph(demo_graph, priv, ttl_seconds=86400)
    graph = verify_envelope(envelope, pub, now=NOW)
    assert graph.graph_id == demo_graph.graph_id
    assert len(graph.edges) == len(demo_graph.edges)
    assert graph.expires_at == graph.issued_at + 86400


def test_canonical_json_is_stable(demo_graph):
    once = demo_graph.canonical_json()
    clone = DependencyGraph.from_dict(json.loads(once))
    assert clone.canonical_json() == once


def test_verify_rejects_tampered_payload(demo_graph, keys):
    priv, pub = keys
    envelope = sign_graph(demo_graph, priv)
    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload["edges"] = payload["edges"][:-1]  # quietly drop an edge
    tampered = dict(
        envelope,
        payload=base64.b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).decode(),
    )
    with pytest.raises(BadSignature):
        verify_envelope(tampered, pub, now=NOW)


def test_verify_rejects_wrong_key(demo_graph, keys, tmp_path):
    priv, _pub = keys
    envelope = sign_graph(demo_graph, priv)
    _other_priv, other_pub = generate_keypair(tmp_path / "other")
    with pytest.raises(BadSignature):
        verify_envelope(envelope, load_public_key(other_pub), now=NOW)


def test_verify_rejects_expired_graph(demo_graph, keys):
    priv, pub = keys
    envelope = sign_graph(demo_graph, priv, ttl_seconds=60)
    with pytest.raises(ExpiredGraph):
        verify_envelope(envelope, pub, now=demo_graph.issued_at + 3600)


def test_verify_rejects_unsupported_version(demo_graph, keys):
    priv, pub = keys
    data = demo_graph.to_dict()
    data["version"] = "99.0"
    future = DependencyGraph.from_dict(data)
    envelope = sign_graph(future, priv)
    with pytest.raises(UnsupportedVersion):
        verify_envelope(envelope, pub, now=NOW)


def test_service_egress(demo_graph):
    assert service_egress(demo_graph, "checkout-api") == [
        "auth-service",
        "ip:203.0.113.66",
        "payments-api",
        "queue-broker",
    ]


def test_arming_gate_denies_on_undeclared_edge(demo_graph, declared):
    gate = arming_gate(demo_graph, "checkout-api", declared, now=NOW)
    assert gate["decision"] == "deny"
    assert any("203.0.113.66" in r for r in gate["reasons"])


def test_arming_gate_allows_clean_service(demo_graph, declared):
    gate = arming_gate(demo_graph, "payments-api", declared, now=NOW)
    assert gate["decision"] == "allow"


def test_arming_gate_denies_when_graph_expired(demo_graph, declared):
    gate = arming_gate(
        demo_graph, "payments-api", declared, now=demo_graph.expires_at + 1
    )
    assert gate["decision"] == "deny"
    assert any("expired" in r for r in gate["reasons"])
