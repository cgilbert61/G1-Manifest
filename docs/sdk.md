# G1-Manifest Python SDK Guide

Consumers (**G1-Warrant**, **G1-Docket**, or custom services) integrate by verifying signed envelopes fail-closed:

```python
import json
from estate_graph.sign import load_public_key
from estate_graph.sources.declared import load_declared
from estate_graph.verify import VerificationError, arming_gate, verify_envelope

envelope = json.loads(open("estate.envelope.json", encoding="utf-8").read())
pub = load_public_key("keys/public.pem")
declared = load_declared("declared_model.json")

try:
    graph = verify_envelope(envelope, pub)
except VerificationError as exc:
    raise SystemExit(f"Fail closed: {exc}")

gate = arming_gate(graph, "checkout-api", declared)
print(gate["decision"], gate["reasons"])
```
