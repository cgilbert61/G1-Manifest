# G1-Manifest Scale Baseline (`SCALE.md`)

Empirical measurements produced by `python benchmarks/scale_baseline.py` using `time.perf_counter()` and Python `tracemalloc`. Good or bad, the exact numbers ship.

## Item 0 — Pre-Ingestor Baseline (2026-11-27)

Command: `python benchmarks/scale_baseline.py` (Python 3.13.9, Windows x86_64)

### Summary Sizes

| Synthetic Estate | Nodes | Edges | Confirmed | Observed Undeclared | Canonical JSON | DSSE Envelope | Standalone HTML |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Control (5,000 edges)** | 125 | 5,000 | 4,500 | 500 | 1.14 MiB (`1,199,172 B`) | 1.53 MiB (`1,599,152 B`) | 5.98 MiB (`6,267,131 B`) |
| **Scale (50,000 edges)** | 285 | 50,000 | 45,000 | 5,000 | 11.37 MiB (`11,920,142 B`) | 15.16 MiB (`15,893,780 B`) | 59.03 MiB (`61,899,575 B`) |

### Stage Wall Time & Peak Traced Memory

| Stage | 5,000 Edges Wall | 5,000 Edges Peak Mem | 50,000 Edges Wall | 50,000 Edges Peak Mem | Scaling Observation |
| :--- | ---: | ---: | ---: | ---: | :--- |
| `aggregate` | `79.98 ms` | `2.79 MB` | `902.97 ms` | `28.74 MB` | Linear (~11.3x for 10x edges); well under 1s at 50k edges |
| `reconcile` | `42.85 ms` | `3.54 MB` | `480.85 ms` | `35.57 MB` | Linear (~11.2x); well under 0.5s at 50k edges |
| `sign` (Ed25519 + canonical JSON) | `363.67 ms` | `4.36 MB` | `4,013.88 ms` | `41.70 MB` | Linear (~11.0x); dominated by `json.dumps(sort_keys=True)` |
| `verify` (Ed25519 + parse) | `197.97 ms` | `7.44 MB` | `2,025.50 ms` | `74.03 MB` | Linear (~10.2x); 2.0s for 15.2 MiB envelope |
| `render` (SVG + static HTML) | `1,636.15 ms` | `27.61 MB` | `16,014.82 ms` | `273.59 MB` | Completes in Python, but emits a **59 MiB** HTML file (100k SVG paths + 50k table rows) — practical browser limit is a few hundred nodes / ~2,000 edges |

### Baseline Verdict
- **Core attestation pipeline (`aggregate → reconcile → sign → verify`):** Scales linearly to 50,000 edges in **7.42 s** total wall time and **74 MB** peak traced memory. No redesign of `aggregate.py`, `sign.py`, or `verify.py` is required before building collectors.
- **Witness renderer (`render.py`):** Works as designed for service-neighborhood and workstation graphs (tens to a few hundred nodes), and hits practical HTML/browser size limits (~59 MiB) at 50,000 edges. Large estates should render filtered subgraphs rather than the full 50k-edge graph in a single HTML file.
