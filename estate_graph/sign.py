"""Signing: DSSE-style envelope around the canonical graph JSON.

The envelope is the product. Producers sign the evidence they learned;
consumers (Docket, Warrant, anything else) verify the envelope and never
have to trust the producer's say-so. The signature covers the DSSE PAE
(pre-auth encoding) of payload type + payload, exactly as DSSE specifies,
so any conforming DSSE verifier can check it.

Keys are plain Ed25519 PEM files, generated and loaded via the CLI.
The private key never leaves the producer; the graph's TTL is set at
signing time: expires_at = issued_at + ttl_seconds.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .model import DependencyGraph

PAYLOAD_TYPE = "application/vnd.g1163rt.estate-graph+json"
DEFAULT_TTL_SECONDS = 86400


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-auth encoding: DSSEv1 <len> <type> <len> <payload>."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)


def keyid_for(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def generate_keypair(out_dir: str | Path) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    priv_path = out / "private.pem"
    pub_path = out / "public.pem"
    priv_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    if os.name == "posix":
        os.chmod(priv_path, 0o600)
    pub_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv_path, pub_path


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path} is not an Ed25519 public key")
    return key


def sign_graph(
    graph: DependencyGraph,
    private_key: Ed25519PrivateKey,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> dict:
    """Apply the TTL and return the DSSE envelope as a plain dict."""
    graph.expires_at = graph.issued_at + ttl_seconds
    payload = graph.canonical_json()
    signature = private_key.sign(_pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "keyid": keyid_for(private_key.public_key()),
                "sig": base64.b64encode(signature).decode("ascii"),
            }
        ],
    }


def envelope_to_json(envelope: dict) -> str:
    return json.dumps(envelope, indent=2, sort_keys=True) + "\n"
