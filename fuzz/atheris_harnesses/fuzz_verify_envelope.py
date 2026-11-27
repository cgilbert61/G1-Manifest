"""Atheris coverage-guided fuzzer for DSSEv1 envelope verification."""

import base64
import json
import sys

import atheris
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

with atheris.instrument_imports():
    from estate_graph.sign import PAYLOAD_TYPE
    from estate_graph.verify import VerificationError, verify_envelope

_PUB = Ed25519PrivateKey.generate().public_key()


def TestOneInput(data: bytes) -> None:  # noqa: N802
    fdp = atheris.FuzzedDataProvider(data)
    mode = fdp.ConsumeIntInRange(0, 2)
    if mode == 0:
        try:
            obj = json.loads(fdp.ConsumeUnicodeNoSurrogates(256))
        except Exception:
            return
    elif mode == 1:
        obj = {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(fdp.ConsumeBytes(256)).decode("ascii"),
            "signatures": [
                {
                    "keyid": fdp.ConsumeUnicodeNoSurrogates(24),
                    "sig": base64.b64encode(fdp.ConsumeBytes(64)).decode("ascii"),
                }
            ],
        }
    else:
        obj = {
            "payloadType": fdp.ConsumeUnicodeNoSurrogates(64),
            "payload": fdp.ConsumeUnicodeNoSurrogates(128),
            "signatures": fdp.ConsumeUnicodeNoSurrogates(32),
        }

    try:
        verify_envelope(obj, _PUB, now=1795716000)
        raise AssertionError("Fuzzed untrusted envelope unexpectedly verified!")
    except VerificationError:
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
