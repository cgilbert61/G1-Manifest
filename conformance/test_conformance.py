"""Consumer Conformance Test Suite for G1-Manifest.

Validates the non-negotiable consumer contract that Docket, Warrant, and
external verifiers depend on:
1. Canonical JSON determinism across repeated serializations.
2. DSSEv1 PAE Ed25519 signing and fail-closed verification.
3. Strict expiry rejection (expired means expired).
4. Schema version enforcement (unknown versions rejected).
5. Arming gate fails closed when any observed egress is undeclared.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from estate_graph.cli import DEMO_ISSUED_AT, build_graph
from estate_graph.sign import (
    PAYLOAD_TYPE,
    generate_keypair,
    load_private_key,
    load_public_key,
    sign_graph,
)
from estate_graph.verify import (
    BadSignature,
    ExpiredGraph,
    UnsupportedVersion,
    arming_gate,
    verify_envelope,
)

DEMO_DIR = Path(__file__).resolve().parent.parent / "examples" / "demo_estate"


def _demo_bundle(tmp_path):
    graph, declared = build_graph(
        DEMO_DIR / "declared_model.json",
        [DEMO_DIR / "vpc_flow_logs.txt"],
        [DEMO_DIR / "hubble.jsonl"],
        [DEMO_DIR / "lineage.json"],
        issued_at=DEMO_ISSUED_AT,
    )
    priv_path, pub_path = generate_keypair(tmp_path)
    priv = load_private_key(priv_path)
    pub = load_public_key(pub_path)
    envelope = sign_graph(graph, priv, ttl_seconds=86400)
    return graph, declared, envelope, priv, pub


def test_conformance_dsse_roundtrip_and_determinism(tmp_path):
    graph, _declared, envelope, _priv, pub = _demo_bundle(tmp_path)
    assert envelope["payloadType"] == PAYLOAD_TYPE
    verified = verify_envelope(envelope, pub, now=DEMO_ISSUED_AT + 60)
    assert verified.canonical_json() == graph.canonical_json()


def test_conformance_fail_closed_on_expiry(tmp_path):
    _graph, _declared, envelope, _priv, pub = _demo_bundle(tmp_path)
    with pytest.raises(ExpiredGraph):
        verify_envelope(envelope, pub, now=DEMO_ISSUED_AT + 86400)


def test_conformance_fail_closed_on_tamper(tmp_path):
    _graph, _declared, envelope, _priv, pub = _demo_bundle(tmp_path)
    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload["sequence"] = 999
    tampered = dict(
        envelope,
        payload=base64.b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii"),
    )
    with pytest.raises(BadSignature):
        verify_envelope(tampered, pub, now=DEMO_ISSUED_AT + 60)


def test_conformance_fail_closed_on_unknown_version(tmp_path):
    graph, _declared, _env, priv, pub = _demo_bundle(tmp_path)
    graph.version = "99.0"
    envelope = sign_graph(graph, priv, ttl_seconds=86400)
    with pytest.raises(UnsupportedVersion):
        verify_envelope(envelope, pub, now=DEMO_ISSUED_AT + 60)


def test_conformance_arming_gate_denies_undeclared_and_allows_clean(tmp_path):
    graph, declared, envelope, _priv, pub = _demo_bundle(tmp_path)
    verified = verify_envelope(envelope, pub, now=DEMO_ISSUED_AT + 60)
    assert (
        arming_gate(verified, "checkout-api", declared, now=DEMO_ISSUED_AT + 60)[
            "decision"
        ]
        == "deny"
    )
    assert (
        arming_gate(verified, "payments-api", declared, now=DEMO_ISSUED_AT + 60)[
            "decision"
        ]
        == "allow"
    )
