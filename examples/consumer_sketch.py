#!/usr/bin/env python3
"""Consumer sketch — NOT production code.

Shows the shape of how a consumer (Warrant-style) would use an estate
graph envelope: receive it, verify it, and ask the arming gate about a
service before letting a surgical shield arm. In production the envelope
arrives from the producer over whatever channel the estate already has;
here we mint one from the demo estate so the sketch runs standalone.

Usage: python examples/consumer_sketch.py [envelope.json public.pem]
"""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from estate_graph.cli import DEMO_ISSUED_AT, build_graph
from estate_graph.sign import generate_keypair, load_private_key, load_public_key, sign_graph
from estate_graph.sources.declared import load_declared
from estate_graph.verify import VerificationError, arming_gate, service_egress, verify_envelope

DEMO = Path(__file__).resolve().parent / "demo_estate"


def main() -> int:
    if len(sys.argv) == 3:
        envelope = json.loads(Path(sys.argv[1]).read_text())
        public_key = load_public_key(sys.argv[2])
        now = None  # verify against the real clock
    else:
        graph, _ = build_graph(
            DEMO / "declared_model.json",
            [DEMO / "vpc_flow_logs.txt"],
            [DEMO / "hubble.jsonl"],
            [DEMO / "lineage.json"],
            issued_at=DEMO_ISSUED_AT,
        )
        with tempfile.TemporaryDirectory() as tmp:
            priv, pub = generate_keypair(tmp)
            envelope = sign_graph(graph, load_private_key(priv))
            public_key = load_public_key(pub)
        now = DEMO_ISSUED_AT + 3600

    # 1. Verify first. No verification, no graph — fail closed.
    try:
        graph = verify_envelope(envelope, public_key, now=now)
    except VerificationError as exc:
        print(f"envelope rejected ({type(exc).__name__}): {exc}")
        return 1
    print(f"envelope verified: {graph.graph_id} from {graph.producer}")

    # 2. Ask the gate per service, against the signed-off declared set.
    declared = load_declared(DEMO / "declared_model.json")
    for service in ("checkout-api", "payments-api"):
        gate = arming_gate(graph, service, declared, now=now)
        print(f"{service}: egress={service_egress(graph, service)}")
        print(f"  arming gate: {gate['decision'].upper()}")
        for reason in gate["reasons"]:
            print(f"    - {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
