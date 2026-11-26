"""Consumer-side verification — the piece Docket or Warrant would call.

Fail closed, and say which way you failed: a bad signature, an expired
graph, and an unknown schema version are different events and raise
different exceptions. A consumer that cannot verify gets no graph at
all — there is no "use it anyway" path.
"""

from __future__ import annotations

import base64
import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .model import SUPPORTED_VERSIONS, DependencyGraph
from .sign import PAYLOAD_TYPE, _pae, keyid_for
from .sources.declared import DeclaredModel


class VerificationError(Exception):
    """Base class for all envelope verification failures."""


class BadSignature(VerificationError):
    pass


class ExpiredGraph(VerificationError):
    pass


class UnsupportedVersion(VerificationError):
    pass


class MalformedEnvelope(VerificationError):
    pass


def verify_envelope(
    envelope: dict,
    public_key: Ed25519PublicKey,
    now: int | None = None,
) -> DependencyGraph:
    """Verify signature, payload type, schema version, and expiry.

    Returns the graph only when every check passes.
    """
    now = int(now if now is not None else time.time())
    if not isinstance(envelope, dict) or "payload" not in envelope:
        raise MalformedEnvelope("envelope is missing its payload")
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise UnsupportedVersion(
            f"unexpected payloadType: {envelope.get('payloadType')!r}"
        )
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
    except Exception as exc:
        raise MalformedEnvelope(f"payload is not valid base64: {exc}") from exc

    expected_keyid = keyid_for(public_key)
    signatures = envelope.get("signatures", [])
    if not isinstance(signatures, list):
        raise MalformedEnvelope("envelope signatures must be a list")
    verified = False
    for entry in signatures:
        if not isinstance(entry, dict):
            continue
        if entry.get("keyid") not in (None, expected_keyid):
            continue
        sig_b64 = entry.get("sig")
        if not isinstance(sig_b64, str):
            continue
        try:
            public_key.verify(
                base64.b64decode(sig_b64), _pae(PAYLOAD_TYPE, payload)
            )
            verified = True
            break
        except Exception:
            continue
    if not verified:
        raise BadSignature("no signature verifies under the supplied key")

    try:
        graph = DependencyGraph.from_dict(json.loads(payload.decode("utf-8")))
    except Exception as exc:
        raise MalformedEnvelope(f"payload is not a valid graph: {exc}") from exc
    if graph.version not in SUPPORTED_VERSIONS:
        raise UnsupportedVersion(
            f"graph schema version {graph.version!r} is not supported"
        )
    if graph.is_expired(now):
        raise ExpiredGraph(
            f"graph {graph.graph_id} expired at {graph.expires_at} (now {now})"
        )
    return graph


def service_egress(graph: DependencyGraph, service_id: str) -> list[str]:
    """The verified egress set for one service: sorted network targets."""
    return sorted(
        {e.target for e in graph.network_edges() if e.source == service_id}
    )


def arming_gate(
    graph: DependencyGraph,
    service_id: str,
    declared: DeclaredModel,
    now: int | None = None,
) -> dict:
    """May a surgical shield arm for this service on this graph?

    Allow requires: the graph is unexpired, the service is known, and
    every observed egress of the service is in the signed-off declared
    set. An observed-but-undeclared flow denies the gate — not because
    the flow is necessarily bad, but because nobody has signed it yet.
    Nothing auto-promotes.
    """
    now = int(now if now is not None else time.time())
    reasons: list[str] = []
    if graph.is_expired(now):
        reasons.append(f"graph expired at {graph.expires_at}")
        return {"decision": "deny", "service": service_id, "reasons": reasons}
    if graph.node(service_id) is None:
        reasons.append(f"service {service_id!r} is not in the graph")
        return {"decision": "deny", "service": service_id, "reasons": reasons}
    approved = declared.targets_of(service_id)
    undeclared = [
        t for t in service_egress(graph, service_id) if t not in approved
    ]
    for target in undeclared:
        reasons.append(
            f"observed egress to {target!r} is not in the signed-off "
            "declared set; a human must review and sign before arming"
        )
    if reasons:
        return {"decision": "deny", "service": service_id, "reasons": reasons}
    return {
        "decision": "allow",
        "service": service_id,
        "reasons": ["all observed egress is in the signed-off declared set"],
    }
