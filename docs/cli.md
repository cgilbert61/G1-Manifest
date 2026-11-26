# G1-Manifest CLI Reference

Installed entrypoints: `g1-manifest` and `estate-graph` (equivalent; also runnable as `python -m estate_graph.cli`).

## Subcommands

| Subcommand | Description |
| :--- | :--- |
| `keygen --out-dir DIR` | Generate Ed25519 `private.pem` (`0600` on POSIX) and `public.pem` |
| `build --declared MODEL [--flowlogs ...] [--hubble ...] [--lineage ...] --out GRAPH` | Build canonical dependency graph JSON |
| `sign --graph GRAPH --key PRIV [--ttl SEC] --out ENV` | Sign graph into expiring DSSEv1 envelope |
| `reconcile --declared MODEL --graph GRAPH` | Diff learned graph against declared model |
| `verify --envelope ENV --pub PUB` | Verify DSSE signature, schema version, and expiry (fail-closed) |
| `render (--graph G \| --envelope E --pub PUB) [--declared M] --out VIEW.html` | Render standalone HTML witness page |
| `scan-host --out GRAPH [--ttl DAYS] [--no-modules]` | Scan local host packages and loaded libraries |
| `serve --dir VIEWS [--host 0.0.0.0] [--port 8080] [--demo]` | Run lightweight HTML witness dashboard and ingest API |
| `demo` | Run bundled synthetic estate end-to-end |
| `--check-mode` | Print installed version, schema version, and runtime mode |
