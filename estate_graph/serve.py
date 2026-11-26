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
import os
import re
import socket
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .aggregate import aggregate
from .auth import SESSION_COOKIE_NAME, SESSION_TTL_SECONDS, ManifestAuthManager
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


def render_index(
    views_dir: Path,
    keys_dir: Path | None = None,
    principal: dict | None = None,
) -> str:
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

    op_controls = (
        '<button type="button" class="btn-secondary" id="btn-theme-toggle">'
        "Dark</button>"
    )
    if principal:
        email_s = html.escape(str(principal.get("email") or ""))
        role_s = html.escape(str(principal.get("role") or "OPERATOR"))
        op_controls = (
            '<span class="op-pill">'
            '<span class="op-dot"></span>'
            f"<strong>{email_s}</strong>"
            f'<span class="op-role">{role_s}</span>'
            "</span>"
            + op_controls
            + '<a class="btn-danger-outline" href="/logout">Sign Out</a>'
        )

    return (
        "<!DOCTYPE html>"
        '<html lang="en"><head><meta charset="utf-8">'
        "<title>G1-Manifest — G1163RT Security Labs</title>"
        "<script>" + _THEME_BOOT_JS + "</script>"
        "<style>" + _INDEX_CSS + "</style></head><body>"
        '<header class="band">'
        '<div class="band-top">'
        '<div class="brand">'
        f"{logo_img}"
        '<div class="brand-text">'
        "<h1>G1-Manifest</h1>"
        '<div class="brand-sub">G1163RT Security Labs · Dependency Graph Control Plane</div>'
        "</div></div>"
        f'<div class="op-bar">{op_controls}</div>'
        "</div>"
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


def _windows_scanner_cmd(server_url: str, ingest_token: str = "") -> bytes:
    """Self-contained double-clickable Windows scanner (.cmd, no Python needed)."""
    hdr_stmt = (
        f"$hdrs = @{{ 'X-Manifest-Ingest-Token' = '{ingest_token}' }}; "
        if ingest_token
        else "$hdrs = @{}; "
    )
    ps_script = (
        f"$server = '{server_url}'; "
        + hdr_stmt
        + "$ErrorActionPreference = 'SilentlyContinue'; "
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
        "$res = Invoke-RestMethod -Method Post -Uri ($server + '/api/ingest/host') -Headers $hdrs -ContentType 'application/json; charset=utf-8' -Body $bytes; "
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


def _macos_scanner_command(server_url: str, ingest_token: str = "") -> bytes:
    """Self-contained double-clickable macOS scanner (.command)."""
    tok_arg = f' -H "X-Manifest-Ingest-Token: {ingest_token}"' if ingest_token else ""
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
RESP=$(curl -sS -X POST "$SERVER/api/ingest/host"{tok_arg} -H "Content-Type: application/json" -d "$PAYLOAD")
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


def render_login_portal(auth_mgr: ManifestAuthManager, next_url: str = "/") -> str:
    """Render the G1-Manifest Institutional MFA Login Portal (matching G1-Warrant & G1-Docket)."""
    logo_uri = logo_data_uri()
    logo_img = (
        f'<img class="login-logo" src="{logo_uri}" alt="G1-Manifest Logo">'
        if logo_uri
        else ""
    )
    safe_next = next_url if next_url.startswith("/") and not next_url.startswith("//") else "/"
    demo_cards: list[str] = []
    if auth_mgr.demo_enabled:
        for idx, acct in enumerate(auth_mgr.demo_accounts):
            email_e = html.escape(acct["email"])
            role_e = html.escape(acct["role"])
            name_e = html.escape(acct["display_name"])
            pw_e = html.escape(acct["passphrase"])
            mfa_e = html.escape(acct["mfa_code"])
            demo_cards.append(
                f'<button type="button" class="demo-row" data-demo-idx="{idx}">'
                '<div class="demo-row-top">'
                f'<span class="demo-email">{email_e}</span>'
                f'<span class="badge-neutral">{role_e}</span>'
                "</div>"
                f'<div class="demo-name">{name_e}</div>'
                f'<div class="demo-secret">Passphrase: <code>{pw_e}</code> · TOTP: <code>{mfa_e}</code></div>'
                "</button>"
            )

    if auth_mgr.demo_enabled:
        left_panel = (
            '<div class="demo-card">'
            '<div class="demo-card-hdr">'
            "<div><h3>Sandbox Demo Accounts</h3>"
            "<p>Click any account to populate credentials (disabled in production posture).</p></div>"
            '<span class="badge-warn">SANDBOX MODE</span>'
            "</div>"
            '<div class="demo-list">' + "".join(demo_cards) + "</div>"
            "</div>"
        )
        quick_btn = (
            '<button type="button" class="btn-primary" id="btn-dev-login">'
            "DEV ADMIN LOGIN</button>"
        )
    else:
        left_panel = (
            '<div class="demo-card">'
            '<div class="demo-card-hdr">'
            "<div><h3>Production Posture Active</h3>"
            "<p>Sandbox demo accounts and quick-login are disabled. Authenticate with an "
            "enrolled operator account from <code>MANIFEST_CONSOLE_USERS_JSON</code>.</p></div>"
            '<span class="badge-ok">LOCKED</span>'
            "</div></div>"
        )
        quick_btn = ""

    push_section = ""
    if not auth_mgr.airgap_mode:
        push_section = (
            '<div class="push-divider"><span>OR FEDERATED HARDWARE PUSH</span></div>'
            '<div class="push-grid">'
            '<button type="button" class="btn-secondary" id="btn-push-duo">Cisco Duo Push</button>'
            '<button type="button" class="btn-secondary" id="btn-push-okta">Okta FastPass</button>'
            "</div>"
            '<div id="push-box" class="push-box" hidden></div>'
        )

    boot_cfg = json.dumps(
        {
            "next_url": safe_next,
            "demo_enabled": auth_mgr.demo_enabled,
            "demo_accounts": auth_mgr.demo_accounts if auth_mgr.demo_enabled else [],
        }
    )

    return (
        "<!DOCTYPE html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>G1-Manifest — Operator Sign In | G1163RT Security Labs</title>"
        "<script>" + _THEME_BOOT_JS + "</script>"
        "<style>" + _INDEX_CSS + _LOGIN_CSS + "</style></head><body>"
        '<header class="login-topbar">'
        '<div class="login-brand">'
        f"{logo_img}"
        "<div>"
        '<div class="login-brand-row"><strong>G1-MANIFEST</strong>'
        '<span class="badge-neutral">v0.1.0</span></div>'
        '<div class="login-sub">G1163RT Security Labs // Zero-Trust MFA Ingress Gate</div>'
        "</div></div>"
        '<div class="login-actions">'
        f"{quick_btn}"
        '<button type="button" class="btn-secondary" id="btn-theme-toggle">Dark</button>'
        "</div></header>"
        '<main class="login-grid">'
        '<section class="login-left">'
        '<div class="badge-ok">DSSEv1 ED25519 &amp; EVIDENCE RECONCILIATION ENFORCED</div>'
        "<h1>SecOps Administrative &amp; MFA Portal</h1>"
        "<p class=\"login-lead\">Authenticate with a PBKDF2-HMAC-SHA256 operator principal "
        "and 6-digit RFC 6238 TOTP or Federated Push challenge to access the G1-Manifest "
        "Dependency Graph &amp; Witness Control Plane.</p>"
        f"{left_panel}"
        "</section>"
        '<section class="login-right">'
        '<div class="login-card">'
        '<div class="login-card-hdr">'
        "<h2>Operator Authentication</h2>"
        "<p>100,000-round salted PBKDF2-HMAC-SHA256 + 6-digit TOTP / Push verification</p>"
        "</div>"
        '<div id="login-alert" class="status-box" hidden></div>'
        '<form id="form-login" class="form">'
        '<label for="login-email">Operator Principal (Email or ID)'
        '<input type="text" id="login-email" value="ops@g1163rt.ai" autocomplete="username" required></label>'
        '<label for="login-password">Operator Passphrase'
        '<input type="password" id="login-password" placeholder="Enter operator passphrase" autocomplete="current-password" required></label>'
        '<div class="mfa-row">'
        '<label for="login-mfa">6-Digit TOTP Authenticator Code'
        '<input type="text" id="login-mfa" inputmode="numeric" maxlength="6" placeholder="000000" autocomplete="one-time-code"></label>'
        '<button type="button" class="btn-secondary" id="btn-autofill-mfa">Auto-Fill TOTP</button>'
        "</div>"
        '<button type="submit" class="btn-primary btn-full" id="btn-login-submit">'
        "Authenticate &amp; Open Console</button>"
        "</form>"
        f"{push_section}"
        "</div></section></main>"
        f"<script>window.__G1_LOGIN_CFG={boot_cfg};" + _LOGIN_JS + "</script>"
        "</body></html>"
    )


def _resolve_require_auth(require_auth: bool | None) -> bool:
    if require_auth is not None:
        return bool(require_auth)
    env_val = os.environ.get("MANIFEST_REQUIRE_AUTH", "").strip().lower()
    return env_val in ("1", "true", "yes")


def make_handler(
    views_dir: Path,
    keys_dir: Path | None = None,
    *,
    require_auth: bool | None = None,
    auth_manager: ManifestAuthManager | None = None,
):
    root = views_dir.resolve()
    kdir = (keys_dir or (root.parent / "keys")).resolve()
    enforce_auth = _resolve_require_auth(require_auth)
    auth_mgr = auth_manager or ManifestAuthManager()

    class WitnessHandler(BaseHTTPRequestHandler):
        def _send(
            self,
            status: int,
            content_type: str,
            body: bytes,
            extra_headers: list[tuple[str, str]] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            for k, v in extra_headers or []:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _redirect(
            self, location: str, extra_headers: list[tuple[str, str]] | None = None
        ) -> None:
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-cache")
            for k, v in extra_headers or []:
                self.send_header(k, v)
            self.end_headers()

        def _send_json(
            self,
            status: int,
            obj: dict,
            extra_headers: list[tuple[str, str]] | None = None,
        ) -> None:
            self._send(
                status,
                "application/json",
                json.dumps(obj).encode("utf-8"),
                extra_headers=extra_headers,
            )

        def _session_cookie_header(self, principal: dict) -> tuple[str, str]:
            tok = auth_mgr.encode_session_token(principal)
            cookie = (
                f"{SESSION_COOKIE_NAME}={tok}; Path=/; Max-Age={SESSION_TTL_SECONDS}; "
                "HttpOnly; SameSite=Lax"
            )
            return ("Set-Cookie", cookie)

        def _clear_cookie_header(self) -> tuple[str, str]:
            return (
                "Set-Cookie",
                f"{SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            )

        def _current_principal(self) -> dict | None:
            return auth_mgr.extract_request_principal(self.headers)

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
            parsed_url = urlsplit(self.path)
            path = unquote(parsed_url.path)
            principal = self._current_principal()

            if path == "/health":
                self._send_json(
                    HTTPStatus.OK, {"status": "ok", "views": len(list_views(root))}
                )
                return

            if path == "/api/keys/public.pem":
                _priv, pub_path = _ensure_keys(kdir)
                self._send(
                    HTTPStatus.OK,
                    "application/x-pem-file",
                    pub_path.read_bytes(),
                )
                return

            if path == "/api/auth/status":
                self._send_json(
                    HTTPStatus.OK,
                    {"authenticated": principal is not None, "principal": principal},
                )
                return

            if path == "/api/auth/mfa-providers":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "airgap_mode": auth_mgr.airgap_mode,
                        "demo_accounts_enabled": auth_mgr.demo_enabled,
                        "demo_accounts": auth_mgr.demo_accounts if auth_mgr.demo_enabled else [],
                    },
                )
                return

            if path == "/logout":
                self._redirect("/login", extra_headers=[self._clear_cookie_header()])
                return

            if path == "/login":
                if principal is not None:
                    self._redirect("/")
                    return
                qs = parse_qs(parsed_url.query)
                next_url = (qs.get("next") or ["/"])[0]
                self._send(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    render_login_portal(auth_mgr, next_url=next_url).encode("utf-8"),
                )
                return

            if path in ("/", "/index.html"):
                if enforce_auth and principal is None:
                    self._send(
                        HTTPStatus.OK,
                        "text/html; charset=utf-8",
                        render_login_portal(auth_mgr, next_url="/").encode("utf-8"),
                    )
                    return
                self._send(
                    HTTPStatus.OK,
                    "text/html; charset=utf-8",
                    render_index(root, kdir, principal=principal).encode("utf-8"),
                )
                return

            if enforce_auth and principal is None:
                if path.startswith("/api/"):
                    self._send_json(
                        HTTPStatus.UNAUTHORIZED,
                        {"ok": False, "error": "AUTHENTICATION_REQUIRED"},
                    )
                else:
                    self._redirect(f"/login?next={quote(path)}")
                return

            if path == "/api/views":
                self._send_json(HTTPStatus.OK, {"views": _views_metadata(root)})
                return
            if path == "/api/agent/windows.cmd":
                host_hdr = self.headers.get("Host") or "127.0.0.1:8088"
                ing_tok = (
                    auth_mgr.issue_ingest_token(principal["email"])
                    if (enforce_auth and principal)
                    else ""
                )
                body = _windows_scanner_cmd(f"http://{host_hdr}", ingest_token=ing_tok)
                self._send(
                    HTTPStatus.OK,
                    "application/octet-stream",
                    body,
                    extra_headers=[
                        (
                            "Content-Disposition",
                            'attachment; filename="g1-manifest-scan-windows.cmd"',
                        )
                    ],
                )
                return
            if path == "/api/agent/macos.command":
                host_hdr = self.headers.get("Host") or "127.0.0.1:8088"
                ing_tok = (
                    auth_mgr.issue_ingest_token(principal["email"])
                    if (enforce_auth and principal)
                    else ""
                )
                body = _macos_scanner_command(f"http://{host_hdr}", ingest_token=ing_tok)
                self._send(
                    HTTPStatus.OK,
                    "application/octet-stream",
                    body,
                    extra_headers=[
                        (
                            "Content-Disposition",
                            'attachment; filename="g1-manifest-scan-macos.command"',
                        )
                    ],
                )
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

                # Authentication & MFA routes
                if path == "/api/auth/login":
                    principal, err = auth_mgr.authenticate_password_mfa(
                        str(body.get("email") or ""),
                        str(body.get("password") or ""),
                        str(body.get("mfa_code") or ""),
                    )
                    if err or principal is None:
                        self._send_json(
                            HTTPStatus.UNAUTHORIZED,
                            {"ok": False, "authenticated": False, "error": err or "AUTH_FAILED"},
                        )
                        return
                    self._send_json(
                        HTTPStatus.OK,
                        {"ok": True, "authenticated": True, "principal": principal},
                        extra_headers=[self._session_cookie_header(principal)],
                    )
                    return

                if path == "/api/auth/push-challenge":
                    ch, err = auth_mgr.create_push_challenge(
                        str(body.get("email") or ""),
                        str(body.get("password") or ""),
                        str(body.get("provider") or ""),
                    )
                    if err or ch is None:
                        self._send_json(
                            HTTPStatus.UNAUTHORIZED,
                            {"ok": False, "error": err or "PUSH_DISPATCH_FAILED"},
                        )
                        return
                    self._send_json(HTTPStatus.OK, {"ok": True, **ch})
                    return

                if path == "/api/auth/push-verify":
                    principal, err = auth_mgr.verify_push_challenge(
                        str(body.get("challenge_id") or ""),
                        str(body.get("match_number") or ""),
                    )
                    if err or principal is None:
                        self._send_json(
                            HTTPStatus.UNAUTHORIZED,
                            {"ok": False, "authenticated": False, "error": err or "PUSH_VERIFY_FAILED"},
                        )
                        return
                    self._send_json(
                        HTTPStatus.OK,
                        {"ok": True, "authenticated": True, "principal": principal},
                        extra_headers=[self._session_cookie_header(principal)],
                    )
                    return

                if path == "/api/auth/dev-quick-login":
                    principal, err = auth_mgr.dev_quick_login(
                        str(body.get("email") or "ops@g1163rt.ai")
                    )
                    if err or principal is None:
                        code = (
                            HTTPStatus.FORBIDDEN
                            if err == "DEMO_QUICK_LOGIN_DISABLED_IN_PRODUCTION"
                            else HTTPStatus.NOT_FOUND
                        )
                        self._send_json(
                            code,
                            {"ok": False, "authenticated": False, "error": err or "QUICK_LOGIN_FAILED"},
                        )
                        return
                    self._send_json(
                        HTTPStatus.OK,
                        {"ok": True, "authenticated": True, "principal": principal},
                        extra_headers=[self._session_cookie_header(principal)],
                    )
                    return

                if path == "/api/auth/logout":
                    self._send_json(
                        HTTPStatus.OK,
                        {"ok": True, "authenticated": False},
                        extra_headers=[self._clear_cookie_header()],
                    )
                    return

                # Enforce session / ingest-token auth on operational mutations
                if enforce_auth:
                    principal = self._current_principal()
                    ing_hdr = (self.headers.get("X-Manifest-Ingest-Token") or "").strip()
                    if path == "/api/ingest/host" and auth_mgr.verify_ingest_token(ing_hdr):
                        pass
                    elif principal is None:
                        self._send_json(
                            HTTPStatus.UNAUTHORIZED,
                            {"ok": False, "error": "AUTHENTICATION_REQUIRED: sign in at /login"},
                        )
                        return
                    elif str(principal.get("role") or "").upper() == "AUDITOR":
                        self._send_json(
                            HTTPStatus.FORBIDDEN,
                            {"ok": False, "error": "AUDITOR_READ_ONLY_ROLE: read-only auditors cannot run scans or rotate keys"},
                        )
                        return

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
    *,
    require_auth: bool | None = None,
) -> ThreadingHTTPServer:
    root = Path(views_dir)
    root.mkdir(parents=True, exist_ok=True)
    kdir = Path(keys_dir) if keys_dir is not None else root.parent / "keys"
    return ThreadingHTTPServer(
        (host, port), make_handler(root, kdir, require_auth=require_auth)
    )


_THEME_BOOT_JS = """
(function () {
  try {
    if (localStorage.getItem('g1_theme') === 'dark') {
      document.documentElement.classList.add('dark');
    }
  } catch (_) {}
})();
function g1BindThemeToggle() {
  var btn = document.getElementById('btn-theme-toggle');
  if (!btn) return;
  function sync() {
    btn.textContent = document.documentElement.classList.contains('dark') ? 'Light' : 'Dark';
  }
  sync();
  btn.addEventListener('click', function () {
    var dark = document.documentElement.classList.toggle('dark');
    try { localStorage.setItem('g1_theme', dark ? 'dark' : 'light'); } catch (_) {}
    sync();
  });
}
"""

_INDEX_CSS = """
:root {
  --bg: #f7f9fb;
  --surface: #ffffff;
  --surface-subtle: #f1f5f9;
  --border: #d8e0e8;
  --border-sub: #e3e9ef;
  --text: #0f172a;
  --muted: #475569;
  --primary: #1e293b;
  --primary-hover: #0f172a;
  --primary-text: #ffffff;
  --link: #1b5e91;
}
html.dark {
  color-scheme: dark;
  --bg: #020617;
  --surface: #0f172a;
  --surface-subtle: #1e293b;
  --border: #1e293b;
  --border-sub: #1e293b;
  --text: #f1f5f9;
  --muted: #94a3b8;
  --primary: #e2e8f0;
  --primary-hover: #ffffff;
  --primary-text: #0f172a;
  --link: #7dd3fc;
}
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
  Helvetica, Arial, sans-serif; background: var(--bg); color: var(--text); }
.band { background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 16px 24px 14px; }
.band-top { display: flex; flex-wrap: wrap; align-items: center;
  justify-content: space-between; gap: 12px; margin-bottom: 8px; }
.brand { display: flex; align-items: center; gap: 14px; }
.brand-logo { width: 44px; height: 44px; object-fit: contain; flex: 0 0 auto;
  background: #ffffff; border: 1px solid var(--border); border-radius: 4px; padding: 2px; }
.brand-text h1 { margin: 0; font-size: 21px; font-weight: 600; line-height: 1.15;
  letter-spacing: -0.02em; color: var(--text); }
.brand-sub { margin-top: 2px; font-size: 12.5px; font-weight: 500; color: var(--muted);
  letter-spacing: 0.02em; }
.op-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.op-pill { display: inline-flex; align-items: center; gap: 7px; padding: 5px 10px;
  border-radius: 4px; background: var(--surface-subtle); border: 1px solid var(--border);
  font-size: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.op-dot { width: 7px; height: 7px; border-radius: 50%; background: #16a34a; }
.op-role { font-size: 10.5px; color: var(--muted); padding-left: 4px;
  border-left: 1px solid var(--border); }
.band p { margin: 0; font-size: 13px; color: var(--muted); }
.key-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 14px;
  margin-top: 10px; font-size: 12.5px; color: var(--muted); }
.grid { max-width: 1180px; margin: 18px auto; padding: 0 16px 24px;
  display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
  gap: 16px; align-items: start; }
.col { display: flex; flex-direction: column; gap: 16px; }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
  padding: 16px 18px; font-size: 13.5px; line-height: 1.5; }
.panel h2 { margin: 0 0 10px; font-size: 15.5px; font-weight: 600; letter-spacing: -0.015em; }
.hint { margin: 0 0 12px; font-size: 12.5px; color: var(--muted); }
.views { list-style: none; margin: 0; padding: 0; }
.views li { display: flex; justify-content: space-between; align-items: baseline;
  padding: 9px 0; border-bottom: 1px solid var(--border-sub); gap: 12px; }
.views li:last-child { border-bottom: none; }
.views a { color: var(--link); text-decoration: none; font-size: 14px; }
.views a:hover { text-decoration: underline; }
.meta { font-size: 12px; color: var(--muted); white-space: nowrap; }
.quick-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
.form { display: flex; flex-direction: column; gap: 11px; }
.form label { display: flex; flex-direction: column; gap: 4px;
  font-size: 12px; font-weight: 600; color: var(--text); }
.form input[type="text"], .form input[type="password"],
.form input[type="number"], .form input[type="file"] {
  font-size: 13px; padding: 7px 10px; border: 1px solid var(--border);
  border-radius: 4px; background: var(--bg); color: var(--text);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.form .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; align-items: end; }
.form label.check { flex-direction: row; align-items: center; gap: 8px;
  font-weight: 500; cursor: pointer; }
.btn-primary, .btn-secondary, .btn-link, .btn-danger-outline {
  display: inline-flex; align-items: center; justify-content: center;
  padding: 7px 13px; border-radius: 4px; font-size: 12.5px;
  font-weight: 600; cursor: pointer; text-decoration: none; border: 1px solid; }
.btn-primary { background: var(--primary); border-color: var(--primary); color: var(--primary-text); }
.btn-primary:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
.btn-primary:disabled { opacity: 0.6; cursor: wait; }
.btn-secondary, .btn-link { background: var(--surface); border-color: var(--border); color: var(--text); }
.btn-secondary:hover, .btn-link:hover { background: var(--surface-subtle); }
.btn-danger-outline { background: var(--surface); border-color: #fecaca; color: #991b1b; }
.btn-danger-outline:hover { background: #fef2f2; border-color: #dc2626; }
html.dark .btn-danger-outline { border-color: #7f1d1d; color: #fca5a5; }
html.dark .btn-danger-outline:hover { background: rgba(127, 29, 29, 0.35); }
.status-box { margin-top: 12px; padding: 10px 12px; border-radius: 4px;
  font-size: 12.5px; border: 1px solid; }
.status-ok { background: #f0fdf4; border-color: #bbf7d0; color: #166534; }
.status-err { background: #fef2f2; border-color: #fecaca; color: #991b1b; }
html.dark .status-ok { background: rgba(20, 83, 45, 0.4); border-color: #166534; color: #bbf7d0; }
html.dark .status-err { background: rgba(127, 29, 29, 0.4); border-color: #991b1b; color: #fecaca; }
.status-box a { color: inherit; font-weight: 700; }
code { background: var(--surface-subtle); padding: 1px 5px; border-radius: 3px;
  font-size: 12px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
pre.cmd { margin: 0; padding: 10px 12px; background: #0f172a; color: #f1f5f9;
  border-radius: 4px; font-size: 12px; overflow-x: auto; }
"""

_LOGIN_CSS = """
.login-topbar { background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.login-brand { display: flex; align-items: center; gap: 12px; }
.login-logo { width: 36px; height: 36px; object-fit: contain; background: #ffffff;
  border: 1px solid var(--border); border-radius: 4px; padding: 2px; }
.login-brand-row { display: flex; align-items: center; gap: 8px; font-size: 14px; }
.login-sub { font-size: 11px; color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin-top: 2px; }
.login-actions { display: flex; align-items: center; gap: 8px; }
.login-grid { max-width: 1100px; margin: 0 auto; padding: 36px 24px;
  display: grid; grid-template-columns: 5fr 7fr; gap: 32px; align-items: start; }
@media (max-width: 900px) { .login-grid { grid-template-columns: 1fr; } }
.login-left h1 { margin: 10px 0 8px; font-size: 24px; font-weight: 600;
  letter-spacing: -0.02em; }
.login-lead { margin: 0 0 20px; font-size: 13.5px; line-height: 1.6; color: var(--muted); }
.badge-ok, .badge-warn, .badge-neutral { display: inline-block; padding: 2px 8px;
  border-radius: 4px; font-size: 10.5px; font-weight: 600; letter-spacing: 0.03em;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; border: 1px solid; }
.badge-ok { background: #f0fdf4; color: #166534; border-color: #bbf7d0; }
.badge-warn { background: #fffbeb; color: #92400e; border-color: #fde68a; }
.badge-neutral { background: var(--surface-subtle); color: var(--text); border-color: var(--border); }
html.dark .badge-ok { background: rgba(20, 83, 45, 0.4); color: #bbf7d0; border-color: #166534; }
html.dark .badge-warn { background: rgba(120, 53, 15, 0.4); color: #fde68a; border-color: #92400e; }
.demo-card, .login-card { background: var(--surface); border: 1px solid var(--border);
  border-radius: 6px; overflow: hidden; }
.demo-card-hdr { padding: 12px 16px; background: var(--surface-subtle);
  border-bottom: 1px solid var(--border); display: flex; align-items: center;
  justify-content: space-between; gap: 10px; }
.demo-card-hdr h3 { margin: 0; font-size: 11.5px; text-transform: uppercase;
  letter-spacing: 0.04em; }
.demo-card-hdr p { margin: 2px 0 0; font-size: 11.5px; color: var(--muted); }
.demo-list { display: flex; flex-direction: column; }
.demo-row { width: 100%; text-align: left; background: transparent; border: none;
  border-bottom: 1px solid var(--border-sub); padding: 11px 16px; cursor: pointer;
  color: var(--text); font-family: inherit; }
.demo-row:last-child { border-bottom: none; }
.demo-row:hover { background: var(--surface-subtle); }
.demo-row-top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.demo-email { font-size: 12.5px; font-weight: 600;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.demo-name { font-size: 11.5px; color: var(--muted); margin-top: 2px; }
.demo-secret { font-size: 11px; color: var(--muted); margin-top: 4px; }
.login-card { padding: 26px 28px; }
.login-card-hdr { border-bottom: 1px solid var(--border); padding-bottom: 14px; margin-bottom: 16px; }
.login-card-hdr h2 { margin: 0 0 4px; font-size: 18px; font-weight: 600; letter-spacing: -0.02em; }
.login-card-hdr p { margin: 0; font-size: 12.5px; color: var(--muted); }
.mfa-row { display: grid; grid-template-columns: 1fr auto; gap: 10px; align-items: end; }
.btn-full { width: 100%; padding: 10px 14px; margin-top: 4px; }
.push-divider { margin: 18px 0 12px; text-align: center; border-bottom: 1px solid var(--border);
  line-height: 0.1em; }
.push-divider span { background: var(--surface); padding: 0 10px; font-size: 10.5px;
  font-weight: 600; letter-spacing: 0.05em; color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.push-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.push-box { margin-top: 12px; padding: 12px 14px; background: var(--surface-subtle);
  border: 1px solid var(--border); border-radius: 4px; font-size: 12.5px; }
"""

_LOGIN_JS = """
g1BindThemeToggle();
(function () {
  var cfg = window.__G1_LOGIN_CFG || { next_url: '/', demo_accounts: [] };
  var emailEl = document.getElementById('login-email');
  var pwEl = document.getElementById('login-password');
  var mfaEl = document.getElementById('login-mfa');
  var alertEl = document.getElementById('login-alert');
  var pushBox = document.getElementById('push-box');
  var activeChallenge = null;

  function showAlert(ok, text) {
    alertEl.hidden = false;
    alertEl.className = 'status-box ' + (ok ? 'status-ok' : 'status-err');
    alertEl.textContent = text;
  }

  document.querySelectorAll('.demo-row').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var idx = Number(btn.getAttribute('data-demo-idx') || '0');
      var acct = (cfg.demo_accounts || [])[idx];
      if (!acct) return;
      emailEl.value = acct.email;
      pwEl.value = acct.passphrase;
      mfaEl.value = acct.mfa_code;
      showAlert(true, 'Loaded demo credentials for ' + acct.email + ' (' + acct.role + '). Click Authenticate & Open Console.');
    });
  });

  var autoBtn = document.getElementById('btn-autofill-mfa');
  if (autoBtn) {
    autoBtn.addEventListener('click', function () {
      var target = (emailEl.value || '').trim().toLowerCase();
      var list = cfg.demo_accounts || [];
      var match = list.find(function (a) { return a.email.toLowerCase() === target; }) || list[0];
      if (!match) {
        showAlert(false, 'Auto-fill is available only for sandbox demo accounts.');
        return;
      }
      emailEl.value = match.email;
      if (!pwEl.value) pwEl.value = match.passphrase;
      mfaEl.value = match.mfa_code;
      showAlert(true, 'Populated sandbox TOTP code (' + match.mfa_code + ') for ' + match.email + '.');
    });
  }

  var devBtn = document.getElementById('btn-dev-login');
  if (devBtn) {
    devBtn.addEventListener('click', async function () {
      devBtn.disabled = true;
      try {
        var r = await fetch('/api/auth/dev-quick-login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: (emailEl.value || '').trim() || 'ops@g1163rt.ai' })
        });
        var d = await r.json();
        if (!r.ok || !d.authenticated) throw new Error(d.error || ('HTTP ' + r.status));
        window.location.href = cfg.next_url || '/';
      } catch (e) {
        showAlert(false, e.message || 'Quick login failed');
        devBtn.disabled = false;
      }
    });
  }

  document.getElementById('form-login').addEventListener('submit', async function (e) {
    e.preventDefault();
    var btn = document.getElementById('btn-login-submit');
    btn.disabled = true;
    try {
      var r = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: emailEl.value.trim(),
          password: pwEl.value,
          mfa_code: mfaEl.value.trim()
        })
      });
      var d = await r.json();
      if (!r.ok || !d.authenticated) throw new Error(d.error || ('HTTP ' + r.status));
      window.location.href = cfg.next_url || '/';
    } catch (err) {
      showAlert(false, err.message || 'Authentication failed');
      btn.disabled = false;
    }
  });

  async function dispatchPush(provider) {
    var pw = pwEl.value;
    if (!pw) {
      var m = (cfg.demo_accounts || []).find(function (a) {
        return a.email.toLowerCase() === emailEl.value.trim().toLowerCase();
      });
      if (m) {
        pw = m.passphrase;
        pwEl.value = pw;
      } else {
        showAlert(false, 'Enter your operator passphrase before dispatching a federated push.');
        return;
      }
    }
    try {
      var r = await fetch('/api/auth/push-challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: emailEl.value.trim(), password: pw, provider: provider })
      });
      var d = await r.json();
      if (!r.ok || !d.challenge_id) throw new Error(d.error || ('HTTP ' + r.status));
      activeChallenge = d;
      pushBox.hidden = false;
      pushBox.innerHTML =
        '<div><strong>' + d.provider_title + '</strong> dispatched to <code>' + d.device + '</code> (' + d.endpoint + ').</div>' +
        '<div style="margin:6px 0;">Confirm number match: <strong style="font-size:15px;">' + d.match_number + '</strong></div>' +
        '<button type="button" class="btn-primary" id="btn-approve-push">Simulate Hardware Approval (' + d.match_number + ')</button>';
      document.getElementById('btn-approve-push').addEventListener('click', async function () {
        var vr = await fetch('/api/auth/push-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ challenge_id: activeChallenge.challenge_id, match_number: activeChallenge.match_number })
        });
        var vd = await vr.json();
        if (!vr.ok || !vd.authenticated) {
          showAlert(false, vd.error || 'Push verification failed');
          return;
        }
        window.location.href = cfg.next_url || '/';
      });
    } catch (err) {
      showAlert(false, err.message || 'Push dispatch failed');
    }
  }

  var duoBtn = document.getElementById('btn-push-duo');
  var oktaBtn = document.getElementById('btn-push-okta');
  if (duoBtn) duoBtn.addEventListener('click', function () { dispatchPush('duo'); });
  if (oktaBtn) oktaBtn.addEventListener('click', function () { dispatchPush('okta'); });
})();
"""

_INDEX_JS = """
g1BindThemeToggle();
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
