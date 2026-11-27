# G1-Manifest Interactive WebGL Explorer — Acceptance Report

This report records empirical acceptance runs for the separate interactive WebGL
Explorer (`estate_graph/explorer.py`, `/explorer`, `/api/explorer/*`, and
`g1-manifest explore`).

The static witness-page renderer (`estate_graph/render.py`), core schema
(`estate_graph/model.py`), signing/verification (`sign.py`, `verify.py`),
aggregation (`aggregate.py`), and reconciliation (`reconcile.py`) are unchanged.

Every claim below carries an explicit evidence tier: `executed`, `code-read`,
or `not reproduced`.

---

## 1. Full Test Suite (Existing + New Explorer Tests)

- **Command:** `python -m pytest -v tests/ conformance/`
- **Result:** `111 passed, 1 skipped in 17.61s` (the single skip is the
  off-Windows registry reader test when run on Windows, unchanged from baseline)
- **Explorer tests included:** `tests/test_explorer.py` (10 tests covering Diff,
  Ego, Findings-First, Zoom Levels, filters, expired envelopes, tampered-envelope
  refusal, HTTP API, CLI `explore`, and 10,000-node synthetic estate)
- **Evidence tier:** `executed`

---

## 2. Demo Estate Acceptance Runs (All 4 Views + 1-Change Diff Proof)

- **Command:** `python benchmarks/explorer_acceptance.py`
- **Envelope A (baseline):** `estate-graph:seq1:8c1365360987` (9 nodes, 8 edges)
- **Envelope B (+1 planted change):** `estate-graph:seq2:ea879622b0e8` (10 nodes, 9 edges; adds node `fraud-scorer` and edge `checkout-api -> fraud-scorer:443`)
- **Evidence tier:** `executed`

| View | Result Summary | Nodes Rendered | Timing (ms) | Proof Status |
| :--- | :--- | :---: | :---: | :---: |
| **1. Diff View** | Exact delta: `+1` node (`fraud-scorer`), `+1` edge (`checkout-api -> fraud-scorer`), `0` removed, `0` changed | 2 (`checkout-api`, `fraud-scorer`) | `0.88 ms` | `VERIFIED` |
| **2. Ego View** | Center `checkout-api`, `rings=1`, blast radius `5` (downstream `5`, upstream `0`) | 6 | `0.11 ms` | `VERIFIED` |
| **3. Findings-First** | `3` findings (`observed_undeclared` + `declared_unobserved`), focused subgraph around finding `0` with evidence pinned | 6 | `0.11 ms` | `VERIFIED` |
| **4. Zoom Levels** | `estate` roll-up by `substrate`: `4` group nodes, `2` flow-weighted rolled edges | 4 | `0.07 ms` | `VERIFIED` |

---

## 3. Large Synthetic Estate Acceptance Runs (10,000 Nodes / 20,001 Edges)

- **Command:** `python benchmarks/explorer_acceptance.py`
- **Envelope A:** `synthetic-10k-estate:seq1:fe1b14029eca` (10,000 nodes, 20,000 edges across 4 substrates & 5 namespaces)
- **Envelope B (+1 planted edge):** `synthetic-10k-estate:seq2:845c533a7526` (10,000 nodes, 20,001 edges; adds `svc-00000 -> svc-05000:9443`)
- **Synthetic generation + signing (both envelopes):** `541.15 ms`
- **Evidence tier:** `executed`

| View | Result Summary | Nodes Rendered | Edges Rendered | Timing (ms) | Proof Status |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **1. Diff View** | Verified both 10k-node DSSEv1 Ed25519 envelopes; exact delta `+1` edge, `0` removed, `0` changed | 2 | 1 | `812.58 ms` | `VERIFIED` |
| **2. Ego View** | Center `svc-00000`, `rings=1`, blast radius `5` (downstream `3`, upstream `2`) | 6 | 5 | `15.65 ms` | `VERIFIED` |
| **3. Findings-First** | Reconciled 10k nodes / 20k edges (`10,001` findings), focused subgraph around finding `0` | 9 | 7 | `2006.36 ms` | `VERIFIED` |
| **4. Zoom Levels** | `estate` roll-up by `substrate`: `4` group nodes, `4` rolled edges, `490,000` summed flows | 4 | 4 | `41.31 ms` | `VERIFIED` |

---

## 4. Negative & Expiry Checks

| Check | Result | Evidence Tier |
| :--- | :--- | :---: |
| **Expired envelope in Diff View** | Opens with `proof.status == "expired"`, `EXPIRED` badge rendered | `executed` |
| **Expired envelope in Ego View** | Opens with `proof.status == "expired"`, `EXPIRED` badge rendered | `executed` |
| **Expired envelope in Findings-First View** | Opens with `proof.status == "expired"`, `EXPIRED` badge rendered | `executed` |
| **Expired envelope in Zoom Levels View** | Opens with `proof.status == "expired"`, `EXPIRED` badge rendered | `executed` |
| **Tampered envelope refusal** | Refused outright with `BadSignature` in Python API, HTTP API (`400`), and CLI (`exit 1`) | `executed` |
| **Untouched core files** | `git diff estate_graph/render.py estate_graph/model.py estate_graph/sign.py estate_graph/verify.py estate_graph/aggregate.py estate_graph/reconcile.py` is empty | `executed` |
| **WebGL hardware frame rate on physical GPU** | WebGL shader pipeline (`gl.LINES` + `gl.POINTS` + orthographic pan/zoom + 120-label 2D overlay + Canvas2D fallback) implemented in `estate_graph/explorer.py`; browser GPU frame-rate profiling on a 10,000-node raw scene is not separately profiled here because all 4 views bound the rendered subgraph | `code-read` |
