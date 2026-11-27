"""Command line interface.

Subcommands: keygen, build, sign, reconcile, verify, render, demo,
scan-host. Run as ``python -m estate_graph.cli <subcommand> ...``.
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from .aggregate import aggregate
from .host_reconcile import host_reconcile
from .model import DependencyGraph, iso_utc
from .reconcile import reconcile
from .render import render_html
from .sign import (
    DEFAULT_TTL_SECONDS,
    envelope_to_json,
    generate_keypair,
    keyid_for,
    load_private_key,
    load_public_key,
    sign_graph,
)
from .sources.declared import load_declared
from .sources.flowlog import load_flow_logs
from .sources.hubble import load_hubble
from .sources.lineage import load_lineage
from .verify import (
    ExpiredGraph,
    VerificationError,
    arming_gate,
    verify_envelope,
)

def _demo_dir() -> Path:
    for base in (Path(__file__).resolve().parent.parent, Path.cwd()):
        candidate = base / "examples" / "demo_estate"
        if candidate.is_dir():
            return candidate
    return Path(__file__).resolve().parent.parent / "examples" / "demo_estate"


DEMO_DIR = _demo_dir()
# Fixed clock for the demo so its output is stable whenever it runs.
DEMO_ISSUED_AT = 1795716000  # 2026-11-26T18:00:00Z


def build_graph(
    declared_path,
    flowlog_paths=(),
    hubble_paths=(),
    lineage_paths=(),
    issued_at=None,
):
    """Shared build path for the `build` and `demo` subcommands."""
    declared = load_declared(declared_path)
    observations = []
    for path in flowlog_paths:
        observations += load_flow_logs(path, declared.ip_to_service)
    for path in hubble_paths:
        observations += load_hubble(path)
    lineage_edges, lineage_nodes = [], []
    for path in lineage_paths:
        edges, nodes = load_lineage(path)
        lineage_edges += edges
        lineage_nodes += nodes
    graph = aggregate(
        observations,
        declared_nodes=declared.nodes,
        extra_edges=lineage_edges,
        extra_nodes=lineage_nodes,
        issued_at=issued_at,
    )
    return graph, declared


def _write_json(obj, path):
    Path(path).write_text(
        json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def cmd_keygen(args) -> int:
    priv, pub = generate_keypair(args.out_dir)
    print(f"private key: {priv}")
    print(f"public key:  {pub}")
    return 0


def cmd_build(args) -> int:
    graph, _declared = build_graph(
        args.declared, args.flowlogs or [], args.hubble or [], args.lineage or []
    )
    _write_json(graph.to_dict(), args.out)
    print(
        f"graph {graph.graph_id}: {len(graph.nodes)} nodes, "
        f"{len(graph.edges)} edges -> {args.out}"
    )
    return 0


def cmd_sign(args) -> int:
    graph = DependencyGraph.from_dict(
        json.loads(Path(args.graph).read_text(encoding="utf-8"))
    )
    envelope = sign_graph(graph, load_private_key(args.key), ttl_seconds=args.ttl)
    Path(args.out).write_text(envelope_to_json(envelope), encoding="utf-8")
    print(
        f"signed graph {graph.graph_id}; expires "
        f"{iso_utc(graph.expires_at)} -> {args.out}"
    )
    return 0


def cmd_reconcile(args) -> int:
    declared = load_declared(args.declared)
    graph = DependencyGraph.from_dict(
        json.loads(Path(args.graph).read_text(encoding="utf-8"))
    )
    print(json.dumps(reconcile(graph, declared), indent=2, sort_keys=True))
    return 0


def cmd_verify(args) -> int:
    envelope = json.loads(Path(args.envelope).read_text(encoding="utf-8"))
    try:
        graph = verify_envelope(envelope, load_public_key(args.pub))
    except VerificationError as exc:
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(
        f"OK: graph {graph.graph_id} v{graph.version} seq {graph.sequence} "
        f"from {graph.producer}: {len(graph.nodes)} nodes, "
        f"{len(graph.edges)} edges, expires {iso_utc(graph.expires_at)}"
    )
    return 0


def cmd_render(args) -> int:
    """Render a graph (or a verified envelope) as an HTML witness page.

    An envelope is verified before it is witnessed: a valid, unexpired
    envelope renders with a VERIFIED badge; an expired one still renders
    — its papers have lapsed, and the page says so in red — but a forged
    envelope is refused outright. A forged graph gets no witness.
    """
    if bool(args.graph) == bool(args.envelope):
        print(
            "FAIL: give exactly one of --graph or --envelope",
            file=sys.stderr,
        )
        return 2
    declared = load_declared(args.declared) if args.declared else None
    if args.envelope:
        if not args.pub:
            print(
                "FAIL: --pub is required with --envelope", file=sys.stderr
            )
            return 2
        pub = load_public_key(args.pub)
        envelope = json.loads(Path(args.envelope).read_text(encoding="utf-8"))
        keyid = keyid_for(pub)
        try:
            graph = verify_envelope(envelope, pub)
            verification = {
                "status": "verified",
                "keyid": keyid,
                "detail": "Signature valid and the graph is within its "
                "validity window.",
            }
        except ExpiredGraph:
            # verify_envelope checks the signature before expiry, so
            # reaching ExpiredGraph means the signature was valid; only
            # the papers have lapsed. Decode the payload and witness it
            # as expired — visibly, never silently.
            graph = DependencyGraph.from_dict(
                json.loads(base64.b64decode(envelope["payload"]))
            )
            verification = {
                "status": "expired",
                "keyid": keyid,
                "detail": "Signature valid, but this graph expired at "
                f"{iso_utc(graph.expires_at)}. Do not act on it.",
            }
        except VerificationError as exc:
            print(
                f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr
            )
            return 1
    else:
        graph = DependencyGraph.from_dict(
            json.loads(Path(args.graph).read_text(encoding="utf-8"))
        )
        verification = {
            "status": "unsigned",
            "keyid": None,
            "detail": "Rendered from a raw graph file; no envelope was "
            "verified for this page.",
        }
    report = reconcile(graph, declared) if declared is not None else None
    Path(args.out).write_text(
        render_html(graph, reconcile_report=report, verification=verification),
        encoding="utf-8",
    )
    print(
        f"rendered graph {graph.graph_id} "
        f"[{verification['status']}] -> {args.out}"
    )
    return 0


def cmd_scan_host(args) -> int:
    """Scan this host: declared packages + observed loaded modules.

    Three layers, each reported honestly: pip metadata always runs;
    the Windows registry runs only on Windows; module observation
    runs unless --no-modules or psutil is unavailable. A skipped
    source prints its reason — a scan that hides its blind spots is
    worse than a smaller scan that names them.
    """
    from .sources.pip_inventory import collect_pip_packages
    from .sources.win_modules import ModuleScanUnavailable

    now = int(time.time())
    nodes, edges = [], []

    pip_nodes, pip_edges = collect_pip_packages(now=now)
    nodes += pip_nodes
    edges += pip_edges
    print(f"pip source: {len(pip_nodes)} packages, {len(pip_edges)} declared edges")

    if sys.platform == "win32":
        from .sources.win_inventory import collect_registry_packages

        try:
            registry_nodes = collect_registry_packages()
            nodes += registry_nodes
            print(f"registry source: {len(registry_nodes)} packages")
        except RuntimeError as exc:
            print(f"registry source: skipped ({exc})")
    else:
        print("registry source: skipped (not Windows)")

    if args.no_modules:
        print("module source: skipped (--no-modules)")
    else:
        from .sources.win_modules import collect_loaded_modules

        install_prefixes = [
            n.labels["install_location"]
            for n in nodes
            if n.labels.get("install_location")
        ]
        try:
            mod_nodes, mod_edges = collect_loaded_modules(
                now=now, install_prefixes=install_prefixes
            )
            nodes += mod_nodes
            edges += mod_edges
            print(
                f"module source: {len(mod_edges)} observed loads "
                f"across {sum(1 for n in mod_nodes if n.kind == 'process')} "
                "processes"
            )
        except ModuleScanUnavailable as exc:
            print(f"module source: skipped ({exc})")
        except Exception as exc:  # a broken source must not kill the scan
            print(f"module source: skipped ({type(exc).__name__}: {exc})")

    graph = aggregate(
        [],
        extra_nodes=nodes,
        extra_edges=edges,
        graph_id=f"host-graph:{socket.gethostname()}",
        producer="estate-graph/scan-host",
        issued_at=now,
        ttl_seconds=args.ttl * 86400,
    )
    _write_json(graph.to_dict(), args.out)

    kinds = Counter(n.kind for n in graph.nodes)
    layers = Counter(e.layer for e in graph.edges)
    findings = host_reconcile(graph)
    print(
        f"graph {graph.graph_id}: {len(graph.nodes)} nodes "
        f"({', '.join(f'{k}={v}' for k, v in sorted(kinds.items()))}), "
        f"{len(graph.edges)} edges "
        f"({', '.join(f'{k}={v}' for k, v in sorted(layers.items()))})"
    )
    print(
        "host findings: "
        f"{findings['summary']['observed_undeclared']} observed-undeclared, "
        f"{findings['summary']['declared_unobserved']} declared-unobserved "
        f"(informational) -> {args.out}"
    )
    for finding in findings["observed_undeclared"]:
        print(
            f"  FINDING [{finding['severity']}] {finding['process']} loaded "
            f"{finding['library']} from {finding['path']}"
        )
    return 0


def cmd_demo(_args) -> int:
    print("== build: declared model + VPC flow logs + Hubble + OpenLineage ==")
    graph, declared = build_graph(
        DEMO_DIR / "declared_model.json",
        [DEMO_DIR / "vpc_flow_logs.txt"],
        [DEMO_DIR / "hubble.jsonl"],
        [DEMO_DIR / "lineage.json"],
        issued_at=DEMO_ISSUED_AT,
    )
    print(f"nodes: {', '.join(n.id for n in graph.nodes)}")
    for edge in graph.edges:
        ev = edge.evidence
        print(
            f"  [{edge.layer}] {edge.source} -> {edge.target}"
            f"{':' + str(edge.port) if edge.port else ''} "
            f"x{ev.flow_count} via {','.join(ev.sources)}"
            f"{' (low frequency)' if edge.low_frequency else ''}"
        )

    print("\n== reconcile: learned vs declared ==")
    report = reconcile(graph, declared)
    print(f"summary: {report['summary']}")
    for finding in report["observed_undeclared"]:
        obs = finding["observations"][0]
        print(
            f"  FINDING [{finding['severity']}] {finding['source']} -> "
            f"{finding['target']} observed x{obs['flow_count']}, first seen "
            f"{iso_utc(obs['first_seen'])} — declared nowhere"
        )
    for stale in report["declared_unobserved"]:
        print(
            f"  STALE [{stale['severity']}] {stale['source']} -> "
            f"{stale['target']} declared but never observed"
        )

    print("\n== sign + verify ==")
    with tempfile.TemporaryDirectory() as tmp:
        _priv_path, pub_path = generate_keypair(tmp)
        envelope = sign_graph(
            graph, load_private_key(_priv_path), ttl_seconds=86400
        )
        verified = verify_envelope(
            envelope, load_public_key(pub_path), now=DEMO_ISSUED_AT + 3600
        )
        print(
            f"verified OK: {verified.graph_id}, expires "
            f"{iso_utc(verified.expires_at)}"
        )

        print("\n== tamper attempt ==")
        payload = json.loads(base64.b64decode(envelope["payload"]))
        payload["producer"] = "mallory"
        tampered = dict(
            envelope,
            payload=base64.b64encode(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).decode(),
        )
        try:
            verify_envelope(
                tampered, load_public_key(pub_path), now=DEMO_ISSUED_AT + 3600
            )
            print("  !! tampered envelope VERIFIED — this must never happen")
            return 1
        except VerificationError as exc:
            print(f"  rejected as expected: {type(exc).__name__}: {exc}")

        print("\n== witness page ==")
        view_path = DEMO_DIR / "demo_view.html"
        view_path.write_text(
            render_html(
                verified,
                reconcile_report=report,
                verification={
                    "status": "verified",
                    "keyid": envelope["signatures"][0]["keyid"],
                    "detail": "Signature valid and the graph is within "
                    "its validity window.",
                },
            ),
            encoding="utf-8",
        )
        print(f"  rendered -> {view_path}")

    print("\n== arming gate (consumer view) ==")
    for service in ("checkout-api", "payments-api"):
        gate = arming_gate(graph, service, declared, now=DEMO_ISSUED_AT + 3600)
        print(f"  {service}: {gate['decision'].upper()} — {gate['reasons'][0]}")
    return 0


def _render_demo_view(out_path: Path) -> None:
    graph, declared = build_graph(
        DEMO_DIR / "declared_model.json",
        [DEMO_DIR / "vpc_flow_logs.txt"],
        [DEMO_DIR / "hubble.jsonl"],
        [DEMO_DIR / "lineage.json"],
        issued_at=DEMO_ISSUED_AT,
    )
    report = reconcile(graph, declared)
    with tempfile.TemporaryDirectory() as tmp:
        priv_path, pub_path = generate_keypair(tmp)
        envelope = sign_graph(
            graph, load_private_key(priv_path), ttl_seconds=86400
        )
        verified = verify_envelope(
            envelope, load_public_key(pub_path), now=DEMO_ISSUED_AT + 3600
        )
        out_path.write_text(
            render_html(
                verified,
                reconcile_report=report,
                verification={
                    "status": "verified",
                    "keyid": envelope["signatures"][0]["keyid"],
                    "detail": "Signature valid and the graph is within "
                    "its validity window.",
                },
            ),
            encoding="utf-8",
        )


def cmd_serve(args) -> int:
    from .serve import serve_views

    views_dir = Path(args.dir)
    views_dir.mkdir(parents=True, exist_ok=True)
    if args.demo:
        demo_out = views_dir / "demo_view.html"
        _render_demo_view(demo_out)
        print(f"rendered demo witness -> {demo_out}", flush=True)

    server = serve_views(
        views_dir,
        host=args.host,
        port=args.port,
        require_auth=not getattr(args, "no_auth", False),
    )
    print(
        f"G1 Manifest witness viewer listening on http://{args.host}:{args.port} "
        f"(serving {views_dir.resolve()})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def cmd_ingest(args) -> int:
    from .ingestors.runner import build_runner_from_config

    runner, startables = build_runner_from_config(args.config)
    for item in startables:
        item.start()
    try:
        reports = runner.run(max_cycles=args.cycles)
        print(json.dumps(reports[-1] if reports else {}, indent=2))
    except KeyboardInterrupt:
        pass
    finally:
        for item in startables:
            item.stop()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="g1-manifest")
    parser.add_argument(
        "--check-mode",
        action="store_true",
        help="print installed version, schema version, and exit",
    )
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("keygen", help="generate an Ed25519 keypair")
    p.add_argument("--out-dir", required=True)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("build", help="build a graph from evidence sources")
    p.add_argument("--declared", required=True)
    p.add_argument("--flowlogs", nargs="*", default=[])
    p.add_argument("--hubble", nargs="*", default=[])
    p.add_argument("--lineage", nargs="*", default=[])
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("sign", help="sign a graph into a DSSE envelope")
    p.add_argument("--graph", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("reconcile", help="diff a graph against the declared model")
    p.add_argument("--declared", required=True)
    p.add_argument("--graph", required=True)
    p.set_defaults(func=cmd_reconcile)

    p = sub.add_parser("verify", help="verify an envelope against a public key")
    p.add_argument("--envelope", required=True)
    p.add_argument("--pub", required=True)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser(
        "render", help="render a graph or envelope as an HTML witness page"
    )
    p.add_argument("--graph", help="raw graph JSON (renders UNSIGNED)")
    p.add_argument("--envelope", help="DSSE envelope JSON (verified first)")
    p.add_argument("--pub", help="public key PEM (required with --envelope)")
    p.add_argument(
        "--declared", help="declared model JSON (adds reconcile findings)"
    )
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_render)

    p = sub.add_parser("demo", help="run the bundled demo estate end-to-end")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("scan-host", help="scan this host's packages and loaded modules")
    p.add_argument("--out", required=True)
    p.add_argument("--ttl", type=int, default=7, help="graph TTL in days")
    p.add_argument(
        "--no-modules",
        action="store_true",
        help="skip observed loaded-module collection",
    )
    p.set_defaults(func=cmd_scan_host)

    p = sub.add_parser(
        "serve", help="serve rendered HTML witness pages over HTTP (MFA gated)"
    )
    p.add_argument("--dir", default="views", help="directory of .html witness pages")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument(
        "--demo",
        action="store_true",
        help="render the bundled demo estate witness page into --dir on startup",
    )
    p.add_argument(
        "--no-auth",
        action="store_true",
        help="disable the operator MFA login portal (unauthenticated LAN mode)",
    )
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser(
        "ingest",
        help="run configured live telemetry collectors and continuously re-issue signed envelopes",
    )
    p.add_argument("--config", required=True, help="path to ingestor JSON config file")
    p.add_argument(
        "--cycles",
        type=int,
        default=0,
        help="number of cycles to run (0 = continuous)",
    )
    p.set_defaults(func=cmd_ingest)

    args = parser.parse_args(argv)
    if args.check_mode:
        from . import SCHEMA_VERSION, __version__

        print(
            json.dumps(
                {
                    "project": "G1-Manifest",
                    "version": __version__,
                    "schema_version": SCHEMA_VERSION,
                    "mode": "ready",
                },
                indent=2,
            )
        )
        return 0
    if not args.command:
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
