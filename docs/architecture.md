# G1-Manifest Architecture

G1-Manifest is a standalone, evidence-driven dependency graph producer and verifier in the G1163RT Security Labs suite. It composes with **G1-Docket** and **G1-Warrant** strictly through signed, expiring DSSEv1 Ed25519 artifacts — never shared runtime code.

## Core Pipeline

1. **Observe (`estate_graph/sources/`)** — Ingests read-only telemetry: AWS VPC Flow Logs, Cilium Hubble JSONL, Warrant-shaped declared estate models, OpenLineage RunEvents, Windows Uninstall Registry, `pip` metadata, and live loaded process libraries.
2. **Learn (`estate_graph/aggregate.py`)** — Deterministically merges observations into a canonical `DependencyGraph` (`nodes` + `edges`) where every edge carries empirical `Evidence` (`flow_count`, `first_seen`, `last_seen`, `sources`). Rare flows are preserved and flagged `low_frequency`.
3. **Reconcile (`estate_graph/reconcile.py`, `host_reconcile.py`)** — Diffs observed evidence against declared claims into three buckets (`confirmed`, `observed_undeclared`, `declared_unobserved`). Nothing observed ever auto-promotes into an allowlist.
4. **Sign & Verify (`estate_graph/sign.py`, `verify.py`)** — Emits DSSEv1 Ed25519 envelopes (`application/vnd.g1163rt.estate-graph+json`) with explicit TTLs. Consumers verify fail-closed on bad signatures, unsupported schema versions, or expiry, and gate surgical shields via `arming_gate()`.
5. **Witness & Serve (`estate_graph/render.py`, `serve.py`)** — Renders deterministic, offline-safe HTML witness pages with static evidence tables and SVG layered graphs, and optionally serves them with a lightweight dashboard and 1-click Windows/macOS workstation scanners.
