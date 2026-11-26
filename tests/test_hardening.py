"""Regression tests for hardening and edge-case fixes."""

import base64
import json

import pytest

from estate_graph.aggregate import aggregate
from estate_graph.host_reconcile import host_reconcile
from estate_graph.model import Edge, Evidence
from estate_graph.sign import PAYLOAD_TYPE, generate_keypair, load_public_key
from estate_graph.sources.flowlog import parse_flow_logs
from estate_graph.sources.win_modules import aggregate_module_loads
from estate_graph.verify import BadSignature, MalformedEnvelope, verify_envelope

NOW = 1795716000


def test_sideloaded_dll_same_filename_not_hidden_by_system_dll():
    """A sideloaded DLL sharing a filename with a System32 DLL must stay distinct."""
    processes = [
        ("notepad.exe", [r"C:\Windows\System32\version.dll"]),
        ("evil.exe", [r"C:\Users\chuck\AppData\Local\Temp\version.dll"]),
    ]
    nodes, edges = aggregate_module_loads(processes, now=NOW)
    graph = aggregate([], extra_nodes=nodes, extra_edges=edges, issued_at=NOW)
    report = host_reconcile(graph)

    lib_nodes = [n for n in graph.nodes if n.id.startswith("lib:version.dll#")]
    assert len(lib_nodes) == 2
    assert {n.kind for n in lib_nodes} == {"system-library", "library"}

    findings = report["observed_undeclared"]
    assert len(findings) == 1
    assert findings[0]["process"] == "proc:evil.exe"
    assert findings[0]["severity"] == "high"
    assert findings[0]["path"].endswith(r"Temp\version.dll")


def test_evidence_merge_ignores_zero_first_seen():
    ev_a = Evidence(flow_count=2, first_seen=1700000000, last_seen=1700000100, sources=["a"])
    ev_b = Evidence(flow_count=1, first_seen=0, last_seen=1700000200, sources=["b"])
    merged = ev_a.merge(ev_b)
    assert merged.first_seen == 1700000000
    assert merged.last_seen == 1700000200
    assert merged.flow_count == 3

    merged_rev = ev_b.merge(ev_a)
    assert merged_rev.first_seen == 1700000000


def test_flowlog_handles_dash_port_and_dash_end():
    text = (
        "version account-id interface-id srcaddr dstaddr srcport dstport "
        "protocol packets bytes start end action log-status\n"
        "2 111111111111 eni-1 10.0.0.1 10.0.0.2 - - 1 2 168 1700000000 1700000060 ACCEPT OK\n"
        "2 111111111111 eni-1 10.0.0.1 10.0.0.2 12345 443 6 2 168 1700000000 - ACCEPT OK\n"
    )
    obs = parse_flow_logs(text, {"10.0.0.1": "svc-a", "10.0.0.2": "svc-b"})
    assert len(obs) == 1
    assert obs[0].port is None
    assert obs[0].protocol == "ICMP"


def test_verify_envelope_rejects_malformed_signatures(tmp_path):
    _priv, pub = generate_keypair(tmp_path)
    pub_key = load_public_key(pub)
    payload = base64.b64encode(json.dumps({"graph_id": "g"}).encode()).decode()

    with pytest.raises(MalformedEnvelope):
        verify_envelope(
            {"payloadType": PAYLOAD_TYPE, "payload": payload, "signatures": "not-a-list"},
            pub_key,
        )

    with pytest.raises(BadSignature):
        verify_envelope(
            {"payloadType": PAYLOAD_TYPE, "payload": payload, "signatures": ["bad", {"keyid": None}]},
            pub_key,
        )


def test_aggregate_does_not_mutate_extra_edges_and_sorts_by_protocol():
    e1 = Edge(
        source="a",
        target="b",
        port=53,
        protocol="UDP",
        evidence=Evidence(flow_count=1, first_seen=10, last_seen=10, sources=["s1"]),
    )
    e2 = Edge(
        source="a",
        target="b",
        port=53,
        protocol="UDP",
        evidence=Evidence(flow_count=2, first_seen=20, last_seen=20, sources=["s2"]),
    )
    e3 = Edge(
        source="a",
        target="b",
        port=53,
        protocol="TCP",
        evidence=Evidence(flow_count=1, first_seen=15, last_seen=15, sources=["s1"]),
    )
    graph = aggregate([], extra_edges=[e1, e2, e3], issued_at=NOW)
    assert e1.evidence.flow_count == 1  # caller edge not mutated
    assert [e.protocol for e in graph.edges] == ["TCP", "UDP"]


def test_serve_views_index_health_and_traversal_block(tmp_path):
    import threading
    import urllib.error
    import urllib.request

    from estate_graph.serve import serve_views

    (tmp_path / "demo_view.html").write_text("<h1>Witness</h1>", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("nope", encoding="utf-8")

    server = serve_views(tmp_path, host="127.0.0.1", port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health") as resp:
            assert resp.status == 200
            assert json.loads(resp.read()) == {"status": "ok", "views": 1}

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "demo_view.html" in body
            assert "secret.txt" not in body

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/demo_view.html") as resp:
            assert resp.status == 200
            assert resp.read().decode("utf-8") == "<h1>Witness</h1>"

        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/secret.txt")
        assert exc.value.code == 404
    finally:
        server.shutdown()
        server.server_close()


def test_serve_api_estate_scan_render_and_keys(tmp_path):
    import threading
    import urllib.request
    from pathlib import Path

    from estate_graph.serve import serve_views

    demo_dir = Path(__file__).resolve().parent.parent / "examples" / "demo_estate"
    views_dir = tmp_path / "views"
    keys_dir = tmp_path / "keys"
    server = serve_views(views_dir, host="127.0.0.1", port=0, keys_dir=keys_dir)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def post(path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            return json.loads(resp.read())

    try:
        res = post(
            "/api/scan/estate",
            {
                "declared": (demo_dir / "declared_model.json").read_text(encoding="utf-8"),
                "flowlogs": [(demo_dir / "vpc_flow_logs.txt").read_text(encoding="utf-8")],
                "hubble": [(demo_dir / "hubble.jsonl").read_text(encoding="utf-8")],
                "lineage": [(demo_dir / "lineage.json").read_text(encoding="utf-8")],
                "name": "my_estate",
                "sign": True,
            },
        )
        assert res["ok"] is True
        assert res["view"] == "my_estate.html"
        assert res["status"] == "verified"
        assert res["summary"]["observed_undeclared"] == 1

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/my_estate.html") as resp:
            page = resp.read().decode("utf-8")
            assert "VERIFIED" in page
            assert "FINDING [high]" in page
            assert "checkout-api" in page

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/keys/public.pem") as resp:
            pem = resp.read().decode("utf-8")
            assert "BEGIN PUBLIC KEY" in pem

        rot = post("/api/keys/rotate", {})
        assert rot["ok"] is True and len(rot["keyid"]) == 16

        demo_res = post("/api/scan/demo", {})
        assert demo_res["ok"] is True and demo_res["view"] == "demo_view.html"

        win_res = post(
            "/api/ingest/host",
            {
                "hostname": "CHUCK-WIN",
                "platform": "windows",
                "registry_records": [
                    {
                        "DisplayName": "Contoso Editor",
                        "DisplayVersion": "3.1",
                        "Publisher": "Contoso",
                        "InstallLocation": r"C:\Program Files\Contoso",
                        "KeyPath": r"HKLM\Contoso",
                    }
                ],
                "processes": [
                    {
                        "name": "Contoso.exe",
                        "modules": [
                            r"C:\Program Files\Contoso\contoso.dll",
                            r"C:\Users\chuck\AppData\Local\Temp\dropped.dll",
                        ],
                    }
                ],
            },
        )
        assert win_res["ok"] is True
        assert win_res["view"] == "CHUCK-WIN_windows_view.html"
        assert win_res["host_summary"]["observed_undeclared"] == 1

        mac_res = post(
            "/api/ingest/host",
            {
                "hostname": "CHUCK-MAC",
                "platform": "macos",
                "app_records": [
                    {
                        "name": "Safari",
                        "version": "18.0",
                        "publisher": "com.apple.Safari",
                        "install_location": "/Applications/Safari.app",
                        "source": "macos-applications",
                    }
                ],
                "processes": [{"name": "Safari", "modules": ["/Applications/Safari.app/Contents/MacOS/Safari"]}],
            },
        )
        assert mac_res["ok"] is True
        assert mac_res["view"] == "CHUCK-MAC_macos_view.html"

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/agent/windows.cmd") as resp:
            cmd_bytes = resp.read().decode("ascii")
            assert "-EncodedCommand" in cmd_bytes

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/agent/macos.command") as resp:
            sh_text = resp.read().decode("utf-8")
            assert "#!/bin/bash" in sh_text
            assert "/api/ingest/host" in sh_text
    finally:
        server.shutdown()
        server.server_close()


