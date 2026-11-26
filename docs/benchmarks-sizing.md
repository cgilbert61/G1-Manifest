# G1-Manifest Benchmarks & Sizing

Run the empirical benchmark locally:

```bash
python benchmarks/bench_graph.py
```

The deterministic layered SVG layout (`estate_graph/render.py`) runs in linear-to-near-linear time over ranked nodes and edges with 4 barycenter sweeps, remaining comfortable up to several hundred nodes per witness page. For larger estates, filter to a service neighborhood or blast-radius slice before rendering.
