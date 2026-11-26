"""Graph this machine's own software packages into a signed estate graph.

Run:  python examples/pc_self_graph.py [out_dir]
Emits graph JSON + a signed envelope + a short summary, using the same
DSSE/Ed25519 envelope and fail-closed verification as the network graph.
Answers, with evidence: what is installed, what depends on what, and —
via reverse lookup — what breaks if a given package is removed.
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from estate_graph.aggregate import aggregate
from estate_graph.sign import generate_keypair, load_private_key, load_public_key, sign_graph, envelope_to_json
from estate_graph.sources.pc import collect_pc
from estate_graph.verify import verify_envelope


def main() -> int:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/pc-graph-out")
    out.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    nodes, edges = collect_pc(now=now)
    graph = aggregate([], extra_edges=edges, extra_nodes=nodes,
                      graph_id="pc-self-graph", producer="g1-estate-graph-pc",
                      issued_at=now)
    (out / "pc-graph.json").write_text(json.dumps(graph.to_dict(), indent=2, sort_keys=True) + "\n")
    priv, pub = generate_keypair(str(out / "keys"))
    envelope = sign_graph(graph, load_private_key(str(priv)))
    (out / "pc-graph.envelope.json").write_text(envelope_to_json(envelope))
    verified = verify_envelope(envelope, load_public_key(str(pub)), now=now + 60)

    pkg_edges = [e for e in verified.edges if e.layer == "package"]
    dependents: dict[str, int] = {}
    for e in pkg_edges:
        dependents[e.target] = dependents.get(e.target, 0) + 1
    top = sorted(dependents.items(), key=lambda kv: -kv[1])[:10]
    summary = {
        "nodes": len(verified.nodes),
        "package_edges": len(pkg_edges),
        "substrates": sorted({n.substrate for n in verified.nodes}),
        "most_depended_on": [{"package": k, "dependents": v} for k, v in top],
        "signed_and_verified": True,
        "expires_at": verified.expires_at,
    }
    (out / "pc-graph-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
