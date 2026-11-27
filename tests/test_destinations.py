"""Tests and proof runs for Downstream Destinations (Items 1–4)."""

from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from estate_graph.cli import DEMO_DIR, DEMO_ISSUED_AT, build_graph
from estate_graph.destinations import (
    ADAPTER_CLASSES,
    DestinationConfigStore,
    DestinationStateStore,
    ExportEngine,
    create_adapter,
)
from estate_graph.model import Edge, Evidence, ServiceNode
from estate_graph.sign import generate_keypair, load_private_key, load_public_key, sign_graph
from estate_graph.verify import BadSignature, ExpiredGraph

NOW = DEMO_ISSUED_AT


def _signed_demo(tmp_path, *, ttl_seconds: int = 86400):
    graph, declared = build_graph(
        DEMO_DIR / "declared_model.json",
        [DEMO_DIR / "vpc_flow_logs.txt"],
        [DEMO_DIR / "hubble.jsonl"],
        [DEMO_DIR / "lineage.json"],
        issued_at=NOW,
    )
    priv_path, pub_path = generate_keypair(tmp_path / "keys")
    priv = load_private_key(priv_path)
    pub = load_public_key(pub_path)
    envelope = sign_graph(graph, priv, ttl_seconds=ttl_seconds)
    return graph, declared, envelope, priv, pub


@pytest.mark.parametrize("system", sorted(ADAPTER_CLASSES.keys()))
def test_all_13_downstream_adapters_preserve_envelope_id_and_expiry(tmp_path, system):
    _graph, declared, envelope, _priv, pub = _signed_demo(tmp_path)
    captured: list[tuple[str, dict, dict]] = []

    def fake_send(url: str, raw: bytes, headers: dict):
        captured.append((url, json.loads(raw.decode("utf-8")), headers))
        return 200, '{"ok": true}'

    adapter = create_adapter(
        {
            "id": f"dest-{system}",
            "system": system,
            "endpoint": "https://downstream.example",
            "credential_ref": "TEST_DEST_CRED",
            "send_mode": "full",
            "enabled": True,
        },
        http_send=fake_send,
    )
    engine = ExportEngine(DestinationStateStore(tmp_path / "state.json"))
    res = engine.export_envelope(envelope, pub, [adapter], declared=declared, now=NOW + 60)

    assert res["ok"] is True
    assert len(res["results"]) == 1
    assert res["results"][0]["ok"] is True
    assert res["results"][0]["accepted"] > 0
    assert len(captured) >= 1
    for _url, body, _hdrs in captured:
        assert body["envelope_id"] == res["envelope_id"]
        assert body["expires_at"] == NOW + 86400


def test_export_modes_full_delta_and_findings_only(tmp_path):
    graph, declared, env1, priv, pub = _signed_demo(tmp_path)
    sent_payloads: list[dict] = []

    def fake_send(url, raw, headers):
        sent_payloads.append(json.loads(raw.decode("utf-8")))
        return 200, "ok"

    state = DestinationStateStore(tmp_path / "delta_state.json")
    engine = ExportEngine(state)

    delta_adapter = create_adapter(
        {"id": "wh-delta", "system": "webhook", "endpoint": "https://wh.local", "send_mode": "delta"},
        http_send=fake_send,
    )
    # 1st delta send -> sends full initial set
    r1 = engine.export_envelope(env1, pub, [delta_adapter], declared=declared, now=NOW + 60)
    assert r1["results"][0]["ok"] is True
    assert len(sent_payloads[-1]["edges"]) == len(graph.edges)

    # 2nd delta send with identical graph -> 0 new nodes/edges/findings
    r2 = engine.export_envelope(env1, pub, [delta_adapter], declared=declared, now=NOW + 120)
    assert r2["results"][0]["ok"] is True
    assert len(sent_payloads[-1]["nodes"]) == 0
    assert len(sent_payloads[-1]["edges"]) == 0
    assert len(sent_payloads[-1]["findings"]) == 0

    # Add a new edge, bump sequence, re-sign -> delta sends only the new edge
    graph.sequence = 2
    graph.nodes.append(ServiceNode(id="new-svc", kind="service", substrate="aws"))
    graph.edges.append(
        Edge(
            source="checkout-api",
            target="new-svc",
            port=443,
            protocol="TCP",
            evidence=Evidence(flow_count=1, first_seen=NOW + 200, last_seen=NOW + 200, sources=["test"]),
        )
    )
    env2 = sign_graph(graph, priv, ttl_seconds=86400)
    r3 = engine.export_envelope(env2, pub, [delta_adapter], declared=declared, now=NOW + 250)
    assert r3["results"][0]["ok"] is True
    assert [n["id"] for n in sent_payloads[-1]["nodes"]] == ["new-svc"]
    assert len(sent_payloads[-1]["edges"]) == 1

    # findings_only mode -> sends findings only, zero nodes/edges
    findings_adapter = create_adapter(
        {"id": "wh-find", "system": "webhook", "endpoint": "https://wh.local", "send_mode": "findings_only"},
        http_send=fake_send,
    )
    engine.export_envelope(env1, pub, [findings_adapter], declared=declared, now=NOW + 60)
    assert sent_payloads[-1]["nodes"] == []
    assert sent_payloads[-1]["edges"] == []
    assert len(sent_payloads[-1]["findings"]) >= 1


def test_negative_proof_expired_and_tampered_graphs_never_export(tmp_path):
    _graph, declared, envelope, _priv, pub = _signed_demo(tmp_path, ttl_seconds=3600)
    called = []

    def fail_if_called(url, raw, headers):
        called.append(url)
        return 200, "ok"

    adapter = create_adapter(
        {"id": "wh", "system": "webhook", "endpoint": "https://wh.local", "send_mode": "full"},
        http_send=fail_if_called,
    )
    engine = ExportEngine()

    # Expired graph -> refused before any HTTP call
    with pytest.raises(ExpiredGraph):
        engine.export_envelope(envelope, pub, [adapter], declared=declared, now=NOW + 3600)
    assert called == []

    # Tampered graph -> refused before any HTTP call
    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload["producer"] = "mallory"
    tampered = dict(
        envelope,
        payload=base64.b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).decode(),
    )
    with pytest.raises(BadSignature):
        engine.export_envelope(tampered, pub, [adapter], declared=declared, now=NOW + 60)
    assert called == []


def test_per_destination_failure_isolation_and_credential_ref_enforcement(tmp_path):
    _graph, declared, envelope, _priv, pub = _signed_demo(tmp_path)

    def broken_send(url, raw, headers):
        raise ConnectionError("downstream unavailable")

    def ok_send(url, raw, headers):
        return 200, "ok"

    bad = create_adapter(
        {"id": "dead-dest", "system": "datadog", "endpoint": "https://dd.local"},
        http_send=broken_send,
    )
    good = create_adapter(
        {"id": "good-dest", "system": "webhook", "endpoint": "https://wh.local"},
        http_send=ok_send,
    )
    res = ExportEngine().export_envelope(envelope, pub, [bad, good], declared=declared, now=NOW + 60)
    assert res["ok"] is False
    by_id = {r["destination_id"]: r for r in res["results"]}
    assert by_id["dead-dest"]["ok"] is False
    assert "ConnectionError" in by_id["dead-dest"]["error"]
    assert by_id["good-dest"]["ok"] is True
    assert by_id["good-dest"]["accepted"] > 0

    # Raw secrets forbidden in DestinationConfigStore
    cfg_store = DestinationConfigStore(tmp_path / "dests.json")
    with pytest.raises(ValueError, match="raw credential field"):
        cfg_store.upsert(
            {
                "name": "bad",
                "system": "servicenow",
                "endpoint": "https://sn.local",
                "password": "leaked-secret",
            }
        )


def test_ui_end_to_end_destination_config_send_and_audit_log(tmp_path):
    """Item 4 UI Proof: configure a destination through the UI API, send a
    verified graph to a real loopback HTTP receiver, confirm receipt and audit log.
    """
    from estate_graph.serve import serve_views

    received: list[dict] = []

    class SinkHandler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length", "0") or "0")
            received.append(json.loads(self.rfile.read(n).decode("utf-8")))
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, format, *args):  # noqa: A002
            return

    sink = ThreadingHTTPServer(("127.0.0.1", 0), SinkHandler)
    sink_port = sink.server_address[1]
    threading.Thread(target=sink.serve_forever, daemon=True).start()

    ui = serve_views(
        tmp_path / "views",
        host="127.0.0.1",
        port=0,
        keys_dir=tmp_path / "keys",
        require_auth=False,
    )
    ui_port = ui.server_address[1]
    threading.Thread(target=ui.serve_forever, daemon=True).start()

    try:
        # 1. Configure destination through the UI API
        cfg_req = urllib.request.Request(
            f"http://127.0.0.1:{ui_port}/api/destinations",
            data=json.dumps(
                {
                    "id": "live-webhook-1",
                    "name": "Local Proof Receiver",
                    "system": "webhook",
                    "endpoint": f"http://127.0.0.1:{sink_port}/ingest",
                    "credential_ref": "DEMO_WEBHOOK_TOKEN",
                    "send_mode": "full",
                    "schedule": "manual",
                    "enabled": True,
                    "target_view": "Local Receiver Log",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(cfg_req, timeout=5) as resp:
            cfg_res = json.loads(resp.read())
            assert cfg_res["ok"] is True
            assert cfg_res["audit_entry"]["action"] == "create"

        # 2. Send verified graph through the UI API
        send_req = urllib.request.Request(
            f"http://127.0.0.1:{ui_port}/api/destinations/send",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(send_req, timeout=5) as resp:
            send_res = json.loads(resp.read())
            assert send_res["ok"] is True
            assert send_res["results"][0]["accepted"] > 0

        # 3. Confirm real HTTP receiver got the verified graph with envelope_id & expires_at
        assert len(received) == 1
        assert received[0]["envelope_id"] == send_res["envelope_id"]
        assert received[0]["expires_at"] == send_res["expires_at"]
        assert len(received[0]["nodes"]) > 0
        assert len(received[0]["edges"]) > 0

        # 4. Confirm configuration change appears in the audit log
        with urllib.request.urlopen(f"http://127.0.0.1:{ui_port}/api/destinations/audit") as resp:
            audit_res = json.loads(resp.read())
            assert any(
                a["destination_id"] == "live-webhook-1" and a["action"] == "create"
                for a in audit_res["audit"]
            )
    finally:
        ui.shutdown()
        ui.server_close()
        sink.shutdown()
        sink.server_close()
