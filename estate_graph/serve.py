"""Lightweight HTTP server for G1 Manifest witness pages and scan workflows.

Serves rendered ``.html`` witness pages from ``views_dir`` along with a
self-contained dashboard at ``/`` that lets operators run estate scans,
host scans, demo scans, and envelope/graph renders directly from the
browser — using stdlib only and keeping every generated witness page a
standalone, read-only HTML file.
"""

from __future__ import annotations

import base64
import html
import json
import re
import socket
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .aggregate import aggregate
from .host_reconcile import host_reconcile
from .model import DependencyGraph, ServiceNode, iso_utc
from .reconcile import reconcile
from .render import logo_data_uri, render_html
from .sign import (
    DEFAULT_TTL_SECONDS,
    generate_keypair,
    keyid_for,
    load_private_key,
    load_public_key,
    sign_graph,
)
from .sources.declared import parse_declared
from .sources.flowlog import parse_flow_logs
from .sources.hubble import parse_hubble
from .sources.lineage import parse_lineage
from .sources.pip_inventory import parse_distributions
from .sources.win_inventory import parse_uninstall_keys, pkg_id
from .sources.win_modules import aggregate_module_loads
from .verify import ExpiredGraph, VerificationError, verify_envelope

MAX_BODY_BYTES = 25 * 1024 * 1024  # 25 MB
_SAFE_STEM = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_html_name(raw: str, default: str = "estate_view") -> str:
    stem = (raw or "").strip()
    if stem.lower().endswith(".html"):
        stem = stem[:-5]
    stem = _SAFE_STEM.sub("-", stem).strip(".-")
    if not stem:
        stem = default
    return f"{stem}.html"


def _ensure_keys(keys_dir: Path) -> tuple[Path, Path]:
    priv = keys_dir / "private.pem"
    pub = keys_dir / "public.pem"
    if not priv.is_file() or not pub.is_file():
        return generate_keypair(keys_dir)
    return priv, pub


def list_views(views_dir: Path) -> list[Path]:
    if not views_dir.is_dir():
        return []
    return sorted(
        p for p in views_dir.iterdir() if p.is_file() and p.suffix.lower() == ".html"
    )


def _views_metadata(views_dir: Path) -> list[dict]:
    items = []
    for path in list_views(views_dir):
        stat = path.stat()
        items.append(
            {
                "name": path.name,
                "url": f"/{path.name}",
                "size_kb": max(1, round(stat.st_size / 1024)),
                "updated": datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        )
    return items


def render_index(views_dir: Path, keys_dir: Path | None = None) -> str:
    views = _views_metadata(views_dir)
    keyid = "not generated yet"
    if keys_dir is not None and (keys_dir / "public.pem").is_file():
        try:
            keyid = keyid_for(load_public_key(keys_dir / "public.pem"))
        except Exception:
            keyid = "unavailable"

    rows: list[str] = []
    for item in views:
        name = html.escape(item["name"])
        rows.append(
            f'<li><a href="/{name}"><strong>{name}</strong></a> '
            f'<span class="meta">{item["size_kb"]} KB · updated {item["updated"]}</span></li>'
        )
    views_html = (
        '<ul class="views" id="views-list">' + "".join(rows) + "</ul>"
        if rows
        else '<ul class="views" id="views-list"></ul>'
        '<p id="views-empty">No rendered witness pages yet.</p>'
    )

    logo_uri = logo_data_uri()
    logo_img = (
        f'<img class="brand-logo" src="{logo_uri}" alt="G1 Logo">'
        if logo_uri
        else ""
    )

    return (
        "<!DOCTYPE html>"
        '<html lang="en"><head><meta charset="utf-8">'
        "<title>G1-Manifest — G1163RT Security Labs</title>"
        "<style>" + _INDEX_CSS + "</style></head><body>"
        '<header class="band">'
        '<div class="brand">'
        f"{logo_img}"
        '<div class="brand-text">'
        "<h1>G1-Manifest</h1>"
        '<div class="brand-sub">G1163RT Security Labs</div>'
        "</div></div>"
        "<p>Learned, signed, expiring dependency graphs · evidence over declaration</p>"
        '<div class="key-bar">'
        f'<span>Signing key: <code id="keyid">{html.escape(keyid)}</code></span>'
        '<a class="btn-link" href="/api/keys/public.pem" download="public.pem">Download public.pem</a>'
        '<button type="button" class="btn-secondary" id="btn-rotate-key">Rotate Keypair</button>'
        "</div>"
        "</header>"
        '<main class="grid">'
        '<div class="col">'
        '<section class="panel">'
        f'<h2>Available Witness Pages (<span id="views-count">{len(views)}</span>)</h2>'
        f"{views_html}"
        '<div class="quick-actions">'
        '<button type="button" class="btn-secondary" id="btn-demo">Run Demo Estate Scan</button>'
        '<button type="button" class="btn-secondary" id="btn-host">Run Container Host Scan</button>'
        "</div>"
        '<div id="quick-status" class="status-box" hidden></div>'
        "</section>"
        '<section class="panel">'
        "<h2>Render / Verify Existing Graph or Envelope</h2>"
        "<p class=\"hint\">Upload a raw <code>graph.json</code> (e.g. from Windows "
        "<code>scan-host</code>) or a signed DSSE <code>envelope.json</code> + "
        "<code>public.pem</code> to verify and publish it as an HTML witness page.</p>"
        '<form id="form-render" class="form">'
        '<label>Artifact JSON (<code>graph.json</code> or <code>envelope.json</code>) *'
        '<input type="file" id="r-artifact" accept=".json" required></label>'
        '<label>Public Key PEM (required for envelopes; optional to use server key)'
        '<input type="file" id="r-pub" accept=".pem,.pub,.txt"></label>'
        '<label>Declared Model JSON (optional, adds reconcile findings)'
        '<input type="file" id="r-declared" accept=".json"></label>'
        '<div class="row">'
        '<label>View Name<input type="text" id="r-name" value="uploaded_view" placeholder="uploaded_view"></label>'
        '<label class="check"><input type="checkbox" id="r-use-server-key"> Verify with server key</label>'
        "</div>"
        '<button type="submit" class="btn-primary">Verify &amp; Render</button>'
        "</form>"
        '<div id="render-status" class="status-box" hidden></div>'
        "</section>"
        "</div>"
        '<div class="col">'
        '<section class="panel">'
        "<h2>Run Estate Scan</h2>"
        "<p class=\"hint\">Ingest a declared model plus observed telemetry files "
        "(AWS VPC Flow Logs, Cilium Hubble JSONL, OpenLineage JSON), reconcile "
        "evidence against declarations, sign a DSSE envelope, and render a witness page.</p>"
        '<form id="form-estate" class="form">'
        '<label>Declared Model JSON (<code>declared_model.json</code>) *'
        '<input type="file" id="e-declared" accept=".json" required></label>'
        '<label>AWS VPC Flow Logs (<code>.txt</code> / <code>.log</code>, optional)'
        '<input type="file" id="e-flowlogs" accept=".txt,.log" multiple></label>'
        '<label>Cilium Hubble JSONL (<code>.jsonl</code>, optional)'
        '<input type="file" id="e-hubble" accept=".jsonl,.json,.log" multiple></label>'
        '<label>OpenLineage JSON (<code>.json</code>, optional)'
        '<input type="file" id="e-lineage" accept=".json" multiple></label>'
        '<div class="row">'
        '<label>View Name<input type="text" id="e-name" value="estate_view" placeholder="estate_view"></label>'
        '<label>TTL (seconds)<input type="number" id="e-ttl" value="86400" min="60"></label>'
        "</div>"
        '<label class="check"><input type="checkbox" id="e-sign" checked> '
        "Sign with server Ed25519 key and verify (VERIFIED badge)</label>"
        '<button type="submit" class="btn-primary">Run Estate Scan</button>'
        "</form>"
        '<div id="estate-status" class="status-box" hidden></div>'
        "</section>"
        '<section class="panel">'
        "<h2>Windows &amp; macOS Workstation Scan (No Command Line)</h2>"
        "<p class=\"hint\">Download the 1-click scanner for your workstation and "
        "double-click it. It collects installed apps/packages and loaded libraries "
        "using built-in OS tools (no Python required), sends the snapshot here for "
        "Ed25519 signing and reconciliation, and automatically opens your graph in "
        "the browser.</p>"
        '<div class="quick-actions">'
        '<a class="btn-primary" href="/api/agent/windows.cmd" download="g1-manifest-scan-windows.cmd">'
        "Download Windows Scanner (.cmd)</a>"
        '<a class="btn-secondary" href="/api/agent/macos.command" download="g1-manifest-scan-macos.command">'
        "Download macOS Scanner (.command)</a>"
        "</div>"
        "<p class=\"hint\" style=\"margin-top:10px;margin-bottom:0;\">"
        "New workstation graphs also appear automatically in <strong>Available Witness Pages</strong>.</p>"
        "</section>"
        "</div>"
        "</main>"
        "<script>" + _INDEX_JS + "</script>"
        "</body></html>"
    )


def _run_estate_scan(body: dict, views_dir: Path, keys_dir: Path) -> dict:
    declared_text = body.get("declared")
    if not declared_text or not isinstance(declared_text, str):
        raise ValueError("declared model JSON is required")
    try:
        declared = parse_declared(json.loads(declared_text))
    except Exception as exc:
        raise ValueError(f"invalid declared model JSON: {exc}") from exc

    observations = []
    for text in body.get("flowlogs") or []:
        if text:
            observations += parse_flow_logs(str(text), declared.ip_to_service)
    for text in body.get("hubble") or []:
        if text:
            observations += parse_hubble(str(text))

    lineage_edges, lineage_nodes = [], []
    for text in body.get("lineage") or []:
        if text:
            try:
                edges, nodes = parse_lineage(json.loads(str(text)))
            except Exception as exc:
                raise ValueError(f"invalid lineage JSON: {exc}") from exc
            lineage_edges += edges
            lineage_nodes += nodes

    ttl = int(body.get("ttl") or DEFAULT_TTL_SECONDS)
    if ttl <= 0:
        raise ValueError("ttl must be a positive integer")

    now = int(time.time())
    graph = aggregate(
        observations,
        declared_nodes=declared.nodes,
        extra_edges=lineage_edges,
        extra_nodes=lineage_nodes,
        issued_at=now,
        ttl_seconds=ttl,
    )
    report = reconcile(graph, declared)

    should_sign = bool(body.get("sign", True))
    if should_sign:
        priv_path, pub_path = _ensure_keys(keys_dir)
        envelope = sign_graph(graph, load_private_key(priv_path), ttl_seconds=ttl)
        pub = load_public_key(pub_path)
        verified = verify_envelope(envelope, pub, now=now)
        verification = {
            "status": "verified",
            "keyid": keyid_for(pub),
            "detail": "Signature valid and the graph is within its validity window.",
        }
        render_target = verified
    else:
        verification = {
            "status": "unsigned",
            "keyid": None,
            "detail": "Rendered from an unsigned estate scan; no envelope was verified.",
        }
        render_target = graph

    filename = _safe_html_name(str(body.get("name") or "estate_view"), "estate_view")
    out_path = views_dir / filename
    out_path.write_text(
        render_html(render_target, reconcile_report=report, verification=verification),
        encoding="utf-8",
    )
    return {
        "ok": True,
        "view": filename,
        "url": f"/{filename}",
        "status": verification["status"],
        "keyid": verification["keyid"],
        "nodes": len(render_target.nodes),
        "edges": len(render_target.edges),
        "summary": report["summary"],
        "views": _views_metadata(views_dir),
    }


def _run_host_scan(body: dict, views_dir: Path, keys_dir: Path) -> dict:
    from .sources.pip_inventory import collect_pip_packages
    from .sources.win_modules import ModuleScanUnavailable, collect_loaded_modules

    now = int(time.time())
    nodes, edges = [], []
    pip_nodes, pip_edges = collect_pip_packages(now=now)
    nodes += pip_nodes
    edges += pip_edges

    modules_note = "collected"
    try:
        mod_nodes, mod_edges = collect_loaded_modules(now=now)
        nodes += mod_nodes
        edges += mod_edges
    except ModuleScanUnavailable as exc:
        modules_note = f"skipped ({exc})"
    except Exception as exc:
        modules_note = f"skipped ({type(exc).__name__}: {exc})"

    ttl_days = int(body.get("ttl_days") or 7)
    ttl_seconds = max(60, ttl_days * 86400)
    graph = aggregate(
        [],
        extra_nodes=nodes,
        extra_edges=edges,
        graph_id=f"host-graph:{socket.gethostname()}",
        producer="estate-graph/scan-host",
        issued_at=now,
        ttl_seconds=ttl_seconds,
    )
    findings = host_reconcile(graph)
    priv_path, pub_path = _ensure_keys(keys_dir)
    envelope = sign_graph(graph, load_private_key(priv_path), ttl_seconds=ttl_seconds)
    pub = load_public_key(pub_path)
    verified = verify_envelope(envelope, pub, now=now)
    verification = {
        "status": "verified",
        "keyid": keyid_for(pub),
        "detail": "Signature valid and the graph is within its validity window.",
    }

    filename = _safe_html_name(str(body.get("name") or "host_view"), "host_view")
    out_path = views_dir / filename
    out_path.write_text(
        render_html(
            verified,
            verification=verification,
            title=f"G1 Manifest — Host Graph ({socket.gethostname()})",
        ),
        encoding="utf-8",
    )
    return {
        "ok": True,
        "view": filename,
        "url": f"/{filename}",
        "status": "verified",
        "keyid": verification["keyid"],
        "nodes": len(verified.nodes),
        "edges": len(verified.edges),
        "modules": modules_note,
        "host_summary": findings["summary"],
        "views": _views_metadata(views_dir),
    }


def _run_demo_scan(views_dir: Path) -> dict:
    from .cli import _render_demo_view

    filename = "demo_view.html"
    _render_demo_view(views_dir / filename)
    return {
        "ok": True,
        "view": filename,
        "url": f"/{filename}",
        "status": "verified",
        "views": _views_metadata(views_dir),
    }


def _host_report_for_render(findings: dict, now: int) -> dict:
    """Adapt host_reconcile output into render_html's reconcile_report shape."""
    summary = findings.get("summary", {})
    undeclared = [
        {
            "source": f["process"],
            "target": f["library"],
            "severity": f.get("severity", "high"),
            "observations": [
                {
                    "flow_count": f.get("loaders", 1),
                    "first_seen": now,
                }
            ],
        }
        for f in findings.get("observed_undeclared", [])
    ]
    unobserved = [
        {
            "source": f["source"],
            "target": f["target"],
            "severity": f.get("severity", "info"),
        }
        for f in findings.get("declared_unobserved", [])
    ]
    return {
        "summary": {
            "confirmed": summary.get("attributed_loads", 0),
            "observed_undeclared": len(undeclared),
            "declared_unobserved": len(unobserved),
        },
        "confirmed": [],
        "observed_undeclared": undeclared,
        "declared_unobserved": unobserved,
    }


def _run_ingest_host(body: dict, views_dir: Path, keys_dir: Path) -> dict:
    """Ingest a Windows/macOS workstation snapshot, sign, reconcile, and render."""
    now = int(time.time())
    hostname = str(body.get("hostname") or "workstation").strip() or "workstation"
    platform = str(body.get("platform") or "workstation").strip().lower()

    nodes: list[ServiceNode] = []
    edges = []

    reg_records = body.get("registry_records") or []
    if isinstance(reg_records, dict):
        reg_records = [reg_records]
    if reg_records:
        nodes += parse_uninstall_keys(reg_records)

    app_records = body.get("app_records") or []
    if isinstance(app_records, dict):
        app_records = [app_records]
    for rec in app_records:
        if not isinstance(rec, dict):
            continue
        name = str(rec.get("name") or "").strip()
        if not name:
            continue
        nodes.append(
            ServiceNode(
                id=pkg_id(name),
                kind="package",
                substrate=str(rec.get("source") or f"{platform}-apps"),
                labels={
                    "version": str(rec.get("version") or ""),
                    "publisher": str(rec.get("publisher") or ""),
                    "install_location": str(rec.get("install_location") or ""),
                },
            )
        )

    pip_records = body.get("pip_records") or []
    if pip_records:
        p_nodes, p_edges = parse_distributions(pip_records, now=now)
        nodes += p_nodes
        edges += p_edges

    raw_procs = body.get("processes") or []
    if isinstance(raw_procs, dict):
        raw_procs = [raw_procs]
    proc_tuples: list[tuple[str, list[str]]] = []
    for item in raw_procs:
        if isinstance(item, dict):
            pname = str(item.get("name") or "unknown")
            mods = item.get("modules") or []
            if isinstance(mods, str):
                mods = [mods]
            proc_tuples.append((pname, [str(m) for m in mods if m]))
        elif isinstance(item, (list, tuple)) and len(item) == 2:
            mods = item[1] or []
            if isinstance(mods, str):
                mods = [mods]
            proc_tuples.append((str(item[0]), [str(m) for m in mods if m]))

    if proc_tuples:
        install_prefixes = [
            n.labels["install_location"]
            for n in nodes
            if n.labels.get("install_location")
        ]
        m_nodes, m_edges = aggregate_module_loads(
            proc_tuples, now=now, install_prefixes=install_prefixes
        )
        nodes += m_nodes
        edges += m_edges

    if not nodes and not edges:
        raise ValueError("workstation snapshot contained no packages or processes")

    ttl_days = int(body.get("ttl_days") or 7)
    ttl_seconds = max(60, ttl_days * 86400)
    graph = aggregate(
        [],
        extra_nodes=nodes,
        extra_edges=edges,
        graph_id=f"host-graph:{hostname}",
        producer=f"estate-graph/workstation-{platform}",
        issued_at=now,
        ttl_seconds=ttl_seconds,
    )
    findings = host_reconcile(graph)
    priv_path, pub_path = _ensure_keys(keys_dir)
    envelope = sign_graph(graph, load_private_key(priv_path), ttl_seconds=ttl_seconds)
    pub = load_public_key(pub_path)
    verified = verify_envelope(envelope, pub, now=now)
    verification = {
        "status": "verified",
        "keyid": keyid_for(pub),
        "detail": f"Workstation ({platform}) snapshot signed and verified.",
    }

    default_name = f"{hostname}_{platform}_view"
    filename = _safe_html_name(str(body.get("name") or default_name), default_name)
    out_path = views_dir / filename
    out_path.write_text(
        render_html(
            verified,
            reconcile_report=_host_report_for_render(findings, now),
            verification=verification,
            title=f"G1-Manifest — {hostname} ({platform})",
        ),
        encoding="utf-8",
    )
    return {
        "ok": True,
        "view": filename,
        "url": f"/{filename}",
        "status": "verified",
        "keyid": verification["keyid"],
        "nodes": len(verified.nodes),
        "edges": len(verified.edges),
        "host_summary": findings["summary"],
        "views": _views_metadata(views_dir),
    }


def _windows_scanner_cmd(server_url: str) -> bytes:
    """Self-contained double-clickable Windows scanner (.cmd, no Python needed)."""
    ps_script = (
        f"$server = '{server_url}'; "
        "$ErrorActionPreference = 'SilentlyContinue'; "
        "Write-Host 'G1-Manifest: Scanning Windows registry and loaded modules...' -ForegroundColor Cyan; "
        "$roots = @("
        "  @('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'HKLM'),"
        "  @('HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'HKLM\\WOW6432Node'),"
        "  @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'HKCU')"
        "); "
        "$reg = New-Object System.Collections.ArrayList; "
        "foreach ($r in $roots) { "
        "  if (Test-Path $r[0]) { "
        "    Get-ChildItem $r[0] | ForEach-Object { "
        "      $p = Get-ItemProperty $_.PSPath; "
        "      if ($p.DisplayName) { "
        "        [void]$reg.Add(@{ "
        "          DisplayName = [string]$p.DisplayName; "
        "          DisplayVersion = [string]$p.DisplayVersion; "
        "          Publisher = [string]$p.Publisher; "
        "          InstallLocation = [string]$p.InstallLocation; "
        "          SystemComponent = $p.SystemComponent; "
        "          ParentKeyName = [string]$p.ParentKeyName; "
        "          KeyPath = ($r[1] + '\\' + $_.PSChildName) "
        "        }) "
        "      } "
        "    } "
        "  } "
        "}; "
        "$procs = New-Object System.Collections.ArrayList; "
        "Get-Process | ForEach-Object { "
        "  try { "
        "    $mods = @($_.Modules | Where-Object { $_.FileName } | ForEach-Object { $_.FileName } | Select-Object -Unique); "
        "    if ($mods.Count -gt 0) { "
        "      [void]$procs.Add(@{ name = ($_.ProcessName + '.exe'); modules = $mods }) "
        "    } "
        "  } catch {} "
        "}; "
        "$payload = @{ hostname = $env:COMPUTERNAME; platform = 'windows'; registry_records = $reg; processes = $procs } | ConvertTo-Json -Depth 6 -Compress; "
        "Write-Host ('Uploading ' + $reg.Count + ' installed apps and ' + $procs.Count + ' processes to ' + $server + '...') -ForegroundColor Cyan; "
        "$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload); "
        "$res = Invoke-RestMethod -Method Post -Uri ($server + '/api/ingest/host') -ContentType 'application/json; charset=utf-8' -Body $bytes; "
        "if ($res.ok) { "
        "  $viewUrl = $server + $res.url; "
        "  Write-Host ('Done! Opening ' + $viewUrl) -ForegroundColor Green; "
        "  Start-Process $viewUrl "
        "} else { "
        "  Write-Host ('Error: ' + $res.error) -ForegroundColor Red; Read-Host 'Press Enter to close' "
        "}"
    )
    b64 = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    cmd = (
        "@echo off\r\n"
        "title G1-Manifest Windows Workstation Scanner\r\n"
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {b64}\r\n"
    )
    return cmd.encode("ascii")


def _macos_scanner_command(server_url: str) -> bytes:
    """Self-contained double-clickable macOS scanner (.command)."""
    script = f"""#!/bin/bash
set -euo pipefail
SERVER="{server_url}"
echo "G1-Manifest: Scanning macOS applications and running processes..."
PAYLOAD=$(/usr/bin/python3 - <<'PY'
import json, os, plistlib, socket, subprocess
from pathlib import Path

apps = []
for app_dir in sorted(Path("/Applications").glob("*.app")):
    plist = app_dir / "Contents" / "Info.plist"
    name = app_dir.stem
    version = ""
    publisher = ""
    if plist.is_file():
        try:
            with plist.open("rb") as fh:
                info = plistlib.load(fh)
            name = str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or name)
            version = str(info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "")
            publisher = str(info.get("CFBundleIdentifier") or "")
        except Exception:
            pass
    apps.append({{
        "name": name,
        "version": version,
        "publisher": publisher,
        "install_location": str(app_dir),
        "source": "macos-applications",
    }})

try:
    brew = subprocess.check_output(["brew", "list", "--versions"], text=True, stderr=subprocess.DEVNULL)
    for line in brew.splitlines():
        parts = line.split()
        if parts:
            apps.append({{
                "name": parts[0],
                "version": parts[1] if len(parts) > 1 else "",
                "publisher": "Homebrew",
                "install_location": f"/opt/homebrew/Cellar/{{parts[0]}}",
                "source": "homebrew",
            }})
except Exception:
    pass

procs = []
try:
    out = subprocess.check_output(["ps", "-axo", "comm="], text=True, stderr=subprocess.DEVNULL)
    seen = set()
    for line in out.splitlines():
        exe = line.strip()
        if exe and exe.startswith("/") and exe not in seen:
            seen.add(exe)
            procs.append({{"name": os.path.basename(exe), "modules": [exe]}})
except Exception:
    pass

print(json.dumps({{
    "hostname": socket.gethostname(),
    "platform": "macos",
    "app_records": apps,
    "processes": procs,
}}))
PY
)
RESP=$(curl -sS -X POST "$SERVER/api/ingest/host" -H "Content-Type: application/json" -d "$PAYLOAD")
VIEW_URL=$(/usr/bin/python3 -c 'import json, sys; d=json.loads(sys.argv[1]); print(d.get("url",""))' "$RESP")
if [ -n "$VIEW_URL" ]; then
  echo "Done! Opening $SERVER$VIEW_URL"
  open "$SERVER$VIEW_URL"
else
  echo "Scan failed: $RESP"
  read -r -p "Press Enter to close..."
fi
"""
    return script.encode("utf-8")


def _run_render_artifact(body: dict, views_dir: Path, keys_dir: Path) -> dict:
    artifact_text = body.get("artifact")
    if not artifact_text or not isinstance(artifact_text, str):
        raise ValueError("artifact JSON is required")
    try:
        data = json.loads(artifact_text)
    except Exception as exc:
        raise ValueError(f"invalid artifact JSON: {exc}") from exc

    declared = None
    if body.get("declared"):
        try:
            declared = parse_declared(json.loads(str(body["declared"])))
        except Exception as exc:
            raise ValueError(f"invalid declared model JSON: {exc}") from exc

    is_envelope = isinstance(data, dict) and "payload" in data and "payloadType" in data
    if is_envelope:
        pub_pem = body.get("pub_pem")
        if pub_pem:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            key = serialization.load_pem_public_key(str(pub_pem).encode("utf-8"))
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("supplied public key is not an Ed25519 key")
            pub = key
        elif body.get("use_server_key"):
            _priv, pub_path = _ensure_keys(keys_dir)
            pub = load_public_key(pub_path)
        else:
            raise ValueError(
                "public key PEM is required to verify a DSSE envelope "
                "(or check 'Verify with server key')"
            )
        kid = keyid_for(pub)
        try:
            graph = verify_envelope(data, pub)
            verification = {
                "status": "verified",
                "keyid": kid,
                "detail": "Signature valid and the graph is within its validity window.",
            }
        except ExpiredGraph:
            graph = DependencyGraph.from_dict(
                json.loads(base64.b64decode(data["payload"]))
            )
            verification = {
                "status": "expired",
                "keyid": kid,
                "detail": "Signature valid, but this graph expired at "
                f"{iso_utc(graph.expires_at)}. Do not act on it.",
            }
        except VerificationError as exc:
            raise ValueError(f"{type(exc).__name__}: {exc}") from exc
    else:
        try:
            graph = DependencyGraph.from_dict(data)
        except Exception as exc:
            raise ValueError(f"not a valid graph or envelope JSON: {exc}") from exc
        verification = {
            "status": "unsigned",
            "keyid": None,
            "detail": "Rendered from a raw graph file; no envelope was verified for this page.",
        }

    report = reconcile(graph, declared) if declared is not None else None
    filename = _safe_html_name(str(body.get("name") or "uploaded_view"), "uploaded_view")
    out_path = views_dir / filename
    out_path.write_text(
        render_html(graph, reconcile_report=report, verification=verification),
        encoding="utf-8",
    )
    return {
        "ok": True,
        "view": filename,
        "url": f"/{filename}",
        "status": verification["status"],
        "keyid": verification["keyid"],
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "summary": report["summary"] if report else None,
        "views": _views_metadata(views_dir),
    }


def make_handler(views_dir: Path, keys_dir: Path | None = None):
    root = views_dir.resolve()
    kdir = (keys_dir or (root.parent / "keys")).resolve()

    class WitnessHandler(BaseHTTPRequestHandler):
        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status: int, obj: dict) -> None:
            self._send(status, "application/json", json.dumps(obj).encode("utf-8"))

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length > MAX_BODY_BYTES:
                raise ValueError(f"payload exceeds {MAX_BODY_BYTES // (1024 * 1024)} MB limit")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                raise ValueError(f"invalid JSON request body: {exc}") from exc
            if not isinstance(parsed, dict):
                raise ValueError("JSON request body must be an object")
            return parsed

        def do_GET(self) -> None:  # noqa: N802
            path = unquote(urlsplit(self.path).path)
            if path in ("/", "/index.html"):
                self._send(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    render_index(root, kdir).encode("utf-8"),
                )
                return
            if path == "/health":
                self._send_json(
                    HTTPStatus.OK, {"status": "ok", "views": len(list_views(root))}
                )
                return
            if path == "/api/views":
                self._send_json(HTTPStatus.OK, {"views": _views_metadata(root)})
                return
            if path == "/api/keys/public.pem":
                _priv, pub_path = _ensure_keys(kdir)
                self._send(
                    HTTPStatus.OK,
                    "application/x-pem-file",
                    pub_path.read_bytes(),
                )
                return
            if path == "/api/agent/windows.cmd":
                host_hdr = self.headers.get("Host") or "127.0.0.1:8088"
                body = _windows_scanner_cmd(f"http://{host_hdr}")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="g1-manifest-scan-windows.cmd"',
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/api/agent/macos.command":
                host_hdr = self.headers.get("Host") or "127.0.0.1:8088"
                body = _macos_scanner_command(f"http://{host_hdr}")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="g1-manifest-scan-macos.command"',
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(body)
                return

            rel = path.lstrip("/")
            if not rel or "/" in rel or "\\" in rel or not rel.lower().endswith(".html"):
                self._send(
                    HTTPStatus.NOT_FOUND,
                    "text/plain; charset=utf-8",
                    b"Not Found\n",
                )
                return
            target = (root / rel).resolve()
            if target.parent != root or not target.is_file():
                self._send(
                    HTTPStatus.NOT_FOUND,
                    "text/plain; charset=utf-8",
                    b"Not Found\n",
                )
                return
            self._send(
                HTTPStatus.OK,
                "text/html; charset=utf-8",
                target.read_bytes(),
            )

        def do_POST(self) -> None:  # noqa: N802
            path = unquote(urlsplit(self.path).path)
            try:
                body = self._read_json()
                if path == "/api/scan/estate":
                    res = _run_estate_scan(body, root, kdir)
                elif path == "/api/scan/host":
                    res = _run_host_scan(body, root, kdir)
                elif path == "/api/scan/demo":
                    res = _run_demo_scan(root)
                elif path == "/api/ingest/host":
                    res = _run_ingest_host(body, root, kdir)
                elif path == "/api/render":
                    res = _run_render_artifact(body, root, kdir)
                elif path == "/api/keys/rotate":
                    _priv, pub_path = generate_keypair(kdir)
                    res = {
                        "ok": True,
                        "keyid": keyid_for(load_public_key(pub_path)),
                    }
                else:
                    self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not Found"})
                    return
                self._send_json(HTTPStatus.OK, res)
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"ok": False, "error": f"{type(exc).__name__}: {exc}"},
                )

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            print(f"[g1-manifest] {self.address_string()} - {format % args}", flush=True)

    return WitnessHandler


def serve_views(
    views_dir: str | Path,
    host: str = "0.0.0.0",
    port: int = 8080,
    keys_dir: str | Path | None = None,
) -> ThreadingHTTPServer:
    root = Path(views_dir)
    root.mkdir(parents=True, exist_ok=True)
    kdir = Path(keys_dir) if keys_dir is not None else root.parent / "keys"
    return ThreadingHTTPServer((host, port), make_handler(root, kdir))


_INDEX_CSS = """
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, "Segoe UI", Roboto, Helvetica,
  Arial, sans-serif; background: #f7f9fb; color: #1d2733; }
.band { background: #ffffff; border-bottom: 1px solid #d8e0e8;
  padding: 16px 24px 14px; }
.brand { display: flex; align-items: center; gap: 14px; margin-bottom: 8px; }
.brand-logo { width: 48px; height: 48px; object-fit: contain; flex: 0 0 auto; }
.brand-text h1 { margin: 0; font-size: 22px; font-weight: 700; line-height: 1.15;
  letter-spacing: -0.01em; }
.brand-sub { margin-top: 2px; font-size: 13px; font-weight: 500; color: #43536a;
  letter-spacing: 0.02em; }
.band p { margin: 0; font-size: 13px; color: #43536a; }
.key-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 14px;
  margin-top: 10px; font-size: 12.5px; color: #43536a; }
.grid { max-width: 1180px; margin: 18px auto; padding: 0 16px 24px;
  display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
  gap: 16px; align-items: start; }
.col { display: flex; flex-direction: column; gap: 16px; }
.panel { background: #ffffff; border: 1px solid #d8e0e8; border-radius: 8px;
  padding: 16px 18px; font-size: 13.5px; line-height: 1.45; }
.panel h2 { margin: 0 0 10px; font-size: 15.5px; }
.hint { margin: 0 0 12px; font-size: 12.5px; color: #43536a; }
.views { list-style: none; margin: 0; padding: 0; }
.views li { display: flex; justify-content: space-between; align-items: baseline;
  padding: 9px 0; border-bottom: 1px solid #e3e9ef; gap: 12px; }
.views li:last-child { border-bottom: none; }
.views a { color: #1b5e91; text-decoration: none; font-size: 14px; }
.views a:hover { text-decoration: underline; }
.meta { font-size: 12px; color: #43536a; white-space: nowrap; }
.quick-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
.form { display: flex; flex-direction: column; gap: 10px; }
.form label { display: flex; flex-direction: column; gap: 4px;
  font-size: 12.5px; font-weight: 600; color: #2b3a4b; }
.form input[type="text"], .form input[type="number"], .form input[type="file"] {
  font-size: 13px; padding: 6px 8px; border: 1px solid #cbd5e1;
  border-radius: 5px; background: #fbfcfd; color: #1d2733; }
.form .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; align-items: end; }
.form label.check { flex-direction: row; align-items: center; gap: 8px;
  font-weight: 500; cursor: pointer; }
.btn-primary, .btn-secondary, .btn-link {
  display: inline-block; padding: 7px 13px; border-radius: 5px; font-size: 13px;
  font-weight: 600; cursor: pointer; text-decoration: none; border: 1px solid; }
.btn-primary { background: #1b5e91; border-color: #164c75; color: #ffffff; }
.btn-primary:hover { background: #164c75; }
.btn-primary:disabled { opacity: 0.6; cursor: wait; }
.btn-secondary, .btn-link { background: #f1f5f9; border-color: #cbd5e1; color: #1d2733; }
.btn-secondary:hover, .btn-link:hover { background: #e2e8f0; }
.status-box { margin-top: 12px; padding: 10px 12px; border-radius: 6px;
  font-size: 12.5px; border: 1px solid; }
.status-ok { background: #e2f0e3; border-color: #4a7d4f; color: #1e4620; }
.status-err { background: #fbe3e1; border-color: #b03a2e; color: #7c211a; }
.status-box a { color: inherit; font-weight: 700; }
code { background: #eef2f6; padding: 1px 4px; border-radius: 3px; font-size: 12px; }
pre.cmd { margin: 0; padding: 10px 12px; background: #1d2733; color: #f1f5f9;
  border-radius: 6px; font-size: 12px; overflow-x: auto; }
"""

_INDEX_JS = """
function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function showStatus(el, ok, htmlMsg) {
  el.hidden = false;
  el.className = 'status-box ' + (ok ? 'status-ok' : 'status-err');
  el.innerHTML = htmlMsg;
}
function refreshViews(views) {
  if (!Array.isArray(views)) return;
  const list = document.getElementById('views-list');
  const count = document.getElementById('views-count');
  const empty = document.getElementById('views-empty');
  count.textContent = String(views.length);
  if (empty) empty.hidden = views.length > 0;
  list.innerHTML = views.map(v =>
    '<li><a href="' + esc(v.url) + '"><strong>' + esc(v.name) + '</strong></a> ' +
    '<span class="meta">' + esc(v.size_kb) + ' KB · updated ' + esc(v.updated) + '</span></li>'
  ).join('');
}
async function readFileText(input) {
  if (!input.files || !input.files.length) return null;
  return await input.files[0].text();
}
async function readAllFilesText(input) {
  if (!input.files || !input.files.length) return [];
  const out = [];
  for (const f of input.files) out.push(await f.text());
  return out;
}
async function postJson(url, payload) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await resp.json();
  if (!resp.ok || !data.ok) throw new Error(data.error || ('HTTP ' + resp.status));
  return data;
}

document.getElementById('form-estate').addEventListener('submit', async e => {
  e.preventDefault();
  const box = document.getElementById('estate-status');
  const btn = e.target.querySelector('button[type="submit"]');
  btn.disabled = true;
  try {
    const declared = await readFileText(document.getElementById('e-declared'));
    if (!declared) throw new Error('Please choose a declared model JSON file.');
    const res = await postJson('/api/scan/estate', {
      declared,
      flowlogs: await readAllFilesText(document.getElementById('e-flowlogs')),
      hubble: await readAllFilesText(document.getElementById('e-hubble')),
      lineage: await readAllFilesText(document.getElementById('e-lineage')),
      name: document.getElementById('e-name').value,
      ttl: Number(document.getElementById('e-ttl').value || 86400),
      sign: document.getElementById('e-sign').checked,
    });
    if (res.keyid) document.getElementById('keyid').textContent = res.keyid;
    refreshViews(res.views);
    const s = res.summary || {};
    showStatus(box, true,
      'Rendered <strong>' + esc(res.view) + '</strong> [' + esc(res.status.toUpperCase()) + '] — ' +
      esc(res.nodes) + ' nodes, ' + esc(res.edges) + ' edges (' +
      esc(s.confirmed || 0) + ' confirmed, ' + esc(s.observed_undeclared || 0) +
      ' undeclared, ' + esc(s.declared_unobserved || 0) + ' unobserved). ' +
      '<a href="' + esc(res.url) + '">Open witness page &rarr;</a>');
  } catch (err) {
    showStatus(box, false, esc(err.message));
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('form-render').addEventListener('submit', async e => {
  e.preventDefault();
  const box = document.getElementById('render-status');
  const btn = e.target.querySelector('button[type="submit"]');
  btn.disabled = true;
  try {
    const artifact = await readFileText(document.getElementById('r-artifact'));
    if (!artifact) throw new Error('Please choose a graph or envelope JSON file.');
    const res = await postJson('/api/render', {
      artifact,
      pub_pem: await readFileText(document.getElementById('r-pub')),
      declared: await readFileText(document.getElementById('r-declared')),
      name: document.getElementById('r-name').value,
      use_server_key: document.getElementById('r-use-server-key').checked,
    });
    refreshViews(res.views);
    showStatus(box, true,
      'Rendered <strong>' + esc(res.view) + '</strong> [' + esc(res.status.toUpperCase()) + '] — ' +
      esc(res.nodes) + ' nodes, ' + esc(res.edges) + ' edges. ' +
      '<a href="' + esc(res.url) + '">Open witness page &rarr;</a>');
  } catch (err) {
    showStatus(box, false, esc(err.message));
  } finally {
    btn.disabled = false;
  }
});

document.getElementById('btn-demo').addEventListener('click', async () => {
  const box = document.getElementById('quick-status');
  try {
    const res = await postJson('/api/scan/demo', {});
    refreshViews(res.views);
    showStatus(box, true,
      'Demo estate scan complete. <a href="' + esc(res.url) + '">Open demo_view.html &rarr;</a>');
  } catch (err) {
    showStatus(box, false, esc(err.message));
  }
});

document.getElementById('btn-host').addEventListener('click', async () => {
  const box = document.getElementById('quick-status');
  try {
    const res = await postJson('/api/scan/host', {});
    if (res.keyid) document.getElementById('keyid').textContent = res.keyid;
    refreshViews(res.views);
    showStatus(box, true,
      'Container host scan complete (' + esc(res.nodes) + ' nodes, ' + esc(res.edges) +
      ' edges). <a href="' + esc(res.url) + '">Open ' + esc(res.view) + ' &rarr;</a>');
  } catch (err) {
    showStatus(box, false, esc(err.message));
  }
});

document.getElementById('btn-rotate-key').addEventListener('click', async () => {
  const box = document.getElementById('quick-status');
  try {
    const res = await postJson('/api/keys/rotate', {});
    document.getElementById('keyid').textContent = res.keyid;
    showStatus(box, true, 'Rotated Ed25519 keypair. New keyid: <code>' + esc(res.keyid) + '</code>');
  } catch (err) {
    showStatus(box, false, esc(err.message));
  }
});

setInterval(async () => {
  if (document.hidden) return;
  try {
    const resp = await fetch('/api/views');
    if (resp.ok) {
      const data = await resp.json();
      refreshViews(data.views);
    }
  } catch (_) {}
}, 5000);
"""
