"""Comprehensive tests for Items 1–6: ingestor contract, standards flow parsers,
cloud collectors, Cisco & ServiceNow adapters, and the continuous live runner.
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import socket
import time
import urllib.request

import pytest

from estate_graph.aggregate import aggregate
from estate_graph.ingestors.cisco import CiscoCollector
from estate_graph.ingestors.cloud import (
    AWSVPCFlowCloudWatchCollector,
    AWSVPCFlowS3Collector,
    AzureNSGFlowCollector,
    GCPVPCFlowCollector,
    HubbleLiveCollector,
)
from estate_graph.ingestors.contract import (
    CheckpointStore,
    CollectorResult,
    CollectorStats,
    IdentityResolver,
)
from estate_graph.ingestors.openlineage_http import OpenLineageHTTPCollector
from estate_graph.ingestors.runner import IngestRunner
from estate_graph.ingestors.servicenow import ServiceNowCMDBCollector
from estate_graph.ingestors.skeleton import SkeletonCollector, parse_skeleton_records
from estate_graph.ingestors.udp_flow import NetFlowUDPCollector, SFlowUDPCollector
from estate_graph.reconcile import reconcile
from estate_graph.sign import generate_keypair, load_private_key, load_public_key
from estate_graph.sources.cisco import (
    parse_cisco_catalyst_inventory,
    parse_cisco_sna_flows,
)
from estate_graph.sources.cloud_flows import (
    parse_azure_nsg_flow_logs,
    parse_gcp_vpc_flow_logs,
)
from estate_graph.sources.netflow import (
    build_ipfix_packet,
    build_netflow_v9_packet,
    parse_netflow_packets,
)
from estate_graph.sources.servicenow import parse_servicenow_cmdb
from estate_graph.sources.sflow import build_sflow_v5_datagram, parse_sflow_datagrams
from estate_graph.verify import BadSignature, ExpiredGraph, verify_envelope

NOW = 1795716000


# --- Item 1: Contract, IdentityResolver, CheckpointStore, Skeleton -------


def test_identity_resolver_provenance_and_honest_unknowns():
    res = IdentityResolver()
    res.register("10.0.0.1", "checkout-api", "declared")
    res.register("10.0.0.2", "payments-api", "k8s-api")
    assert res.resolve("10.0.0.1") == ("checkout-api", "declared")
    assert res.resolve("203.0.113.66") == ("ip:203.0.113.66", None)
    nodes = {n.id: n for n in res.provenance_nodes()}
    assert nodes["checkout-api"].labels["identity_sources"] == ["declared"]
    assert nodes["payments-api"].labels["identity_sources"] == ["k8s-api"]


def test_checkpoint_store_roundtrip_and_skeleton(tmp_path):
    store = CheckpointStore(tmp_path / "ckpt.json")
    resolver = IdentityResolver()
    resolver.register("10.0.0.1", "svc-a", "declared")
    resolver.register("10.0.0.2", "svc-b", "declared")

    records = [
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 443, "protocol": "TCP", "action": "ACCEPT", "timestamp": NOW},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 443, "protocol": "TCP", "action": "REJECT", "timestamp": NOW},
        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.1", "dst_port": 443, "protocol": "TCP", "action": "ACCEPT", "timestamp": NOW},
        "not-a-dict",
    ]
    col = SkeletonCollector(
        lambda cur: (records if cur == 0 else [], 1),
        resolver=resolver,
        checkpoint_store=store,
    )
    res1 = col.collect()
    assert len(res1.observations) == 1
    assert res1.stats.records_dropped == 3
    # Reload from disk: cursor=1 prevents duplicate reads
    store2 = CheckpointStore(tmp_path / "ckpt.json")
    assert store2.get("skeleton-example")["cursor"] == 1


# --- Item 2: NetFlow v9 / IPFIX & sFlow v5 -------------------------------


def test_netflow_v9_and_ipfix_pure_parsers_and_drop_handling():
    resolver = IdentityResolver()
    resolver.register("10.0.1.10", "checkout-api", "declared")
    resolver.register("10.0.1.20", "payments-api", "declared")

    # 0x40 = forwarded, 0x80 = dropped (must not become an edge)
    ipfix_pkt = build_ipfix_packet(
        [
            ("10.0.1.10", "10.0.1.20", 8443, 6, 0x40),
            ("10.0.1.10", "203.0.113.66", 443, 6, 0x40),
            ("10.0.1.10", "198.51.100.9", 22, 6, 0x80),  # dropped!
        ],
        export_ts=NOW,
    )
    nf9_pkt = build_netflow_v9_packet(
        [("10.0.1.20", "10.0.1.10", 443, 6, 0x40)],
        export_ts=NOW + 10,
    )
    stats = CollectorStats(origin="ipfix")
    obs = parse_netflow_packets(
        [ipfix_pkt, nf9_pkt, b"short", b"\x00\x05" + b"\x00" * 20],
        resolver,
        stats=stats,
    )
    pairs = {(o.source, o.target, o.port, o.origin) for o in obs}
    assert ("checkout-api", "payments-api", 8443, "ipfix") in pairs
    assert ("checkout-api", "ip:203.0.113.66", 443, "ipfix") in pairs
    assert ("payments-api", "checkout-api", 443, "netflow-v9") in pairs
    assert all(o.target != "ip:198.51.100.9" for o in obs)
    assert stats.drop_reasons["dropped_forwarding_status"] == 1
    assert stats.drop_reasons["truncated_header"] == 1
    assert stats.drop_reasons["unsupported_version"] == 1


def test_sflow_v5_records_sampling_rate_on_evidence_and_edge():
    resolver = IdentityResolver()
    resolver.register("10.0.2.1", "edge-gw", "dns")
    resolver.register("10.0.2.2", "auth-svc", "dns")

    dgram = build_sflow_v5_datagram(
        [
            ("10.0.2.1", "10.0.2.2", 443, 6, 1000),
            ("10.0.2.1", "10.0.2.2", 443, 6, 1000),
        ]
    )
    stats = CollectorStats(origin="sflow")
    obs = parse_sflow_datagrams([dgram, b"bad"], resolver, observed_at=NOW, stats=stats)
    assert len(obs) == 1
    assert obs[0].count == 2
    assert obs[0].labels == {"sampling_rate": 1000, "sampled": True}
    assert stats.drop_reasons["truncated_sflow_header"] == 1

    graph = aggregate(obs, issued_at=NOW)
    assert graph.edges[0].labels["sampling_rate"] == 1000
    assert graph.edges[0].labels["sampled"] is True


# --- Item 3: Cloud live pulls & OpenLineage HTTP -------------------------


def test_aws_s3_and_cloudwatch_collectors_checkpoint_and_dedupe(tmp_path):
    vpc_log = (
        "version account-id interface-id srcaddr dstaddr srcport dstport "
        "protocol packets bytes start end action log-status\n"
        f"2 111111111111 eni-1 10.0.0.1 10.0.0.2 50000 443 6 5 400 {NOW} {NOW+30} ACCEPT OK\n"
    )
    gz_bytes = gzip.compress(vpc_log.encode("utf-8"))

    class FakeS3:
        def list_objects_v2(self, Bucket, Prefix):
            return {"Contents": [{"Key": "AWSLogs/flow1.log.gz"}]}

        def get_object(self, Bucket, Key):
            return {"Body": io.BytesIO(gz_bytes)}

    store = CheckpointStore(tmp_path / "aws_ckpt.json")
    s3_col = AWSVPCFlowS3Collector("bucket", "AWSLogs/", s3_client=FakeS3(), checkpoint_store=store)
    r1 = s3_col.collect()
    assert len(r1.observations) == 1
    r2 = s3_col.collect()
    assert len(r2.observations) == 0  # deduplicated via checkpoint!
    assert r2.stats.drop_reasons["already_checkpointed"] == 1

    class FakeCW:
        def filter_log_events(self, logGroupName, startTime):
            return {
                "events": [
                    {
                        "eventId": "ev-1",
                        "timestamp": NOW * 1000,
                        "message": f"2 111 eni-1 10.0.0.1 10.0.0.2 50000 443 6 5 400 {NOW} {NOW+30} ACCEPT OK",
                    }
                ]
            }

    cw_col = AWSVPCFlowCloudWatchCollector("/vpc/flows", logs_client=FakeCW(), checkpoint_store=store)
    c1 = cw_col.collect()
    assert len(c1.observations) == 1
    c2 = cw_col.collect()
    assert len(c2.observations) == 0
    assert c2.stats.drop_reasons["duplicate_event_id"] == 1


def test_azure_nsg_and_gcp_vpc_and_hubble_collectors(tmp_path):
    store = CheckpointStore(tmp_path / "cloud_ckpt.json")
    azure_doc = json.dumps(
        {
            "records": [
                {
                    "properties": {
                        "flows": [
                            {
                                "flows": [
                                    {
                                        "flowTuples": [
                                            f"{NOW},10.1.0.1,10.1.0.2,51000,443,T,O,A,B,1,60,1,60",
                                            f"{NOW},10.1.0.1,10.1.0.9,51001,22,T,O,D,B,1,60,0,0",
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                }
            ]
        }
    )

    class FakeBlobClient:
        def list_blobs(self):
            return [{"name": "nsg-01.json", "etag": "e1", "generation": "1"}]

        def download_blob(self, name):
            return azure_doc.encode("utf-8")

    az = AzureNSGFlowCollector("nsg-logs", container_client=FakeBlobClient(), checkpoint_store=store)
    az_r1 = az.collect()
    assert len(az_r1.observations) == 1
    assert az_r1.stats.drop_reasons["denied_flow"] == 1
    assert len(az.collect().observations) == 0

    gcp_doc = json.dumps(
        [
            {
                "jsonPayload": {
                    "connection": {"src_ip": "10.2.0.1", "dest_ip": "10.2.0.2", "dest_port": 5432, "protocol": 6},
                    "start_time": "2026-11-26T18:00:00Z",
                    "end_time": "2026-11-26T18:01:00Z",
                }
            }
        ]
    )

    class FakeGCS:
        def list_blobs(self):
            return [{"name": "gcp-01.json", "generation": "42"}]

        def download_blob(self, name):
            return gcp_doc.encode("utf-8")

    gcp = GCPVPCFlowCollector("gcp-flows", bucket_client=FakeGCS(), checkpoint_store=store)
    assert len(gcp.collect().observations) == 1
    assert len(gcp.collect().observations) == 0

    hubble_lines = [
        json.dumps(
            {
                "time": "2026-11-26T18:00:00Z",
                "flow": {
                    "verdict": "FORWARDED",
                    "source": {"labels": ["k8s:app=checkout-api"]},
                    "destination": {"pod_name": "payments-api-7d9f8c5b4-x2abc"},
                    "l4": {"TCP": {"destination_port": 8443}},
                },
            }
        )
    ]
    hub = HubbleLiveCollector(
        lambda cur: (hubble_lines if cur is None else [], "tok-1"),
        checkpoint_store=store,
    )
    h1 = hub.collect()
    assert len(h1.observations) == 1
    assert (h1.observations[0].source, h1.observations[0].target) == ("checkout-api", "payments-api")
    assert len(hub.collect().observations) == 0


# --- Items 4 & 5: Cisco & ServiceNow -------------------------------------


def test_cisco_catalyst_inventory_and_sna_flows():
    inv = {
        "response": [
            {"id": "dev-1", "hostname": "core-sw-01", "managementIpAddress": "10.9.0.1", "role": "CORE", "platformId": "C9500"}
        ]
    }
    sna = {
        "data": {
            "flows": [
                {
                    "subject": {"ipAddress": "10.9.0.1"},
                    "peer": {"ipAddress": "203.0.113.50", "portProtocol": "443/tcp"},
                    "statistics": {"firstActiveTime": NOW, "lastActiveTime": NOW + 60, "flowCount": 5},
                    "action": "ALLOW",
                },
                {
                    "subject": {"ipAddress": "10.9.0.1"},
                    "peer": {"ipAddress": "198.51.100.2", "portProtocol": "23/tcp"},
                    "action": "DENY",
                },
            ]
        }
    }

    def fake_get(url, headers):
        return json.dumps(inv if "network-device" in url else sna)

    col = CiscoCollector(
        catalyst_url="https://dnac.local",
        sna_flows_url="https://sna.local/flows",
        http_get=fake_get,
    )
    res = col.collect()
    assert len(res.extra_nodes) == 1
    assert res.extra_nodes[0].id == "core-sw-01"
    assert len(res.observations) == 1
    assert res.observations[0].source == "core-sw-01"
    assert res.observations[0].target == "ip:203.0.113.50"
    assert res.observations[0].count == 5
    assert res.stats.drop_reasons["denied_flow"] == 1


def test_servicenow_cmdb_declared_model_and_reconcile():
    cis = {
        "result": [
            {"sys_id": "ci-1", "name": "checkout-api", "ip_address": "10.0.0.1", "sys_class_name": "cmdb_ci_service"},
            {"sys_id": "ci-2", "name": "payments-api", "ip_address": "10.0.0.2", "sys_class_name": "cmdb_ci_service"},
        ]
    }
    rels = {"result": [{"parent": {"value": "ci-1"}, "child": {"value": "ci-2"}}]}

    def fake_get(url, headers):
        return json.dumps(cis if "cmdb_ci?" in url else rels)

    sn = ServiceNowCMDBCollector("https://example.service-now.com", http_get=fake_get)
    declared = sn.load_declared()
    nodes = {n.id: n for n in declared.nodes}
    assert nodes["checkout-api"].labels["servicenow_sys_id"] == "ci-1"
    assert ("checkout-api", "payments-api") in declared.pairs
    assert declared.ip_to_service["10.0.0.1"] == "checkout-api"


# --- Item 6: Continuous runner, failure isolation, live 3-source proof ---


def test_runner_enforces_reissue_shorter_than_ttl_and_isolates_failures(tmp_path):
    priv_path, pub_path = generate_keypair(tmp_path / "keys")
    priv = load_private_key(priv_path)
    pub = load_public_key(pub_path)
    store = CheckpointStore(tmp_path / "ckpt.json")

    with pytest.raises(ValueError, match="strictly shorter"):
        IngestRunner(
            [],
            private_key=priv,
            out_envelope=tmp_path / "env.json",
            checkpoint_store=store,
            ttl_seconds=60,
            reissue_interval_seconds=60,
        )

    class DeadCollector:
        origin = "dead-source"

        def collect(self):
            raise ConnectionError("endpoint unreachable")

    class GarbageCollector:
        origin = "garbage-source"

        def collect(self):
            return "not-a-collector-result"

    good = SkeletonCollector(
        lambda _cur: (
            [{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 443, "protocol": "TCP", "action": "ACCEPT", "timestamp": NOW}],
            1,
        )
    )

    runner = IngestRunner(
        [DeadCollector(), GarbageCollector(), good],
        private_key=priv,
        out_envelope=tmp_path / "env.json",
        checkpoint_store=store,
        ttl_seconds=3600,
        reissue_interval_seconds=60,
    )
    rep = runner.run_cycle(now=NOW)
    assert rep["sequence"] == 1
    assert len(rep["failed_sources"]) == 2
    assert {f["origin"] for f in rep["failed_sources"]} == {"dead-source", "garbage-source"}
    assert rep["edges"] == 1

    env = json.loads((tmp_path / "env.json").read_text(encoding="utf-8"))
    verified = verify_envelope(env, pub, now=NOW + 10)
    assert verified.sequence == 1


def test_live_continuous_runner_multi_source_end_to_end(tmp_path):
    """Acceptance #3: live runner across 3 real local endpoints (NetFlow UDP,
    sFlow UDP, OpenLineage HTTP) issuing 2 successive signed graphs with
    increasing sequence, each verified fail-closed + tamper & expiry checks.
    """
    priv_path, pub_path = generate_keypair(tmp_path / "keys")
    priv = load_private_key(priv_path)
    pub = load_public_key(pub_path)
    store = CheckpointStore(tmp_path / "ckpt.json")
    resolver = IdentityResolver()
    resolver.register("10.0.1.10", "checkout-api", "declared")
    resolver.register("10.0.1.20", "payments-api", "declared")

    nf_col = NetFlowUDPCollector("127.0.0.1", 0, resolver=resolver)
    sf_col = SFlowUDPCollector("127.0.0.1", 0, resolver=resolver)
    ol_col = OpenLineageHTTPCollector("127.0.0.1", 0)
    nf_port = nf_col.start()
    sf_port = sf_col.start()
    ol_port = ol_col.start()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Cycle 1: send real IPFIX UDP + sFlow UDP + OpenLineage HTTP POST
        sock.sendto(
            build_ipfix_packet([("10.0.1.10", "10.0.1.20", 8443, 6, 0x40)], export_ts=NOW),
            ("127.0.0.1", nf_port),
        )
        sock.sendto(
            build_sflow_v5_datagram([("10.0.1.20", "203.0.113.66", 443, 6, 512)]),
            ("127.0.0.1", sf_port),
        )
        req = urllib.request.Request(
            f"http://127.0.0.1:{ol_port}/api/v1/lineage",
            data=json.dumps(
                {
                    "eventTime": "2026-11-26T18:00:00Z",
                    "inputs": [{"namespace": "s3", "name": "raw-orders"}],
                    "outputs": [{"namespace": "pg", "name": "ledger"}],
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 202

        time.sleep(0.15)  # allow UDP receiver threads to drain
        runner = IngestRunner(
            [nf_col, sf_col, ol_col],
            private_key=priv,
            out_envelope=tmp_path / "estate.envelope.json",
            checkpoint_store=store,
            resolver=resolver,
            ttl_seconds=3600,
            reissue_interval_seconds=60,
        )

        r1 = runner.run_cycle(now=NOW)
        assert r1["sequence"] == 1
        env1 = json.loads((tmp_path / "estate.envelope.json").read_text(encoding="utf-8"))
        g1 = verify_envelope(env1, pub, now=NOW + 10)
        assert g1.sequence == 1
        assert len(g1.network_edges()) == 2
        assert len(g1.edges_on_layer("lineage")) == 1

        # Cycle 2: send another IPFIX flow and re-issue -> sequence bumps to 2
        sock.sendto(
            build_ipfix_packet([("10.0.1.10", "10.0.1.20", 8443, 6, 0x40)], export_ts=NOW + 30),
            ("127.0.0.1", nf_port),
        )
        sock.close()
        time.sleep(0.15)

        r2 = runner.run_cycle(now=NOW + 60)
        assert r2["sequence"] == 2
        env2 = json.loads((tmp_path / "estate.envelope.json").read_text(encoding="utf-8"))
        g2 = verify_envelope(env2, pub, now=NOW + 120)
        assert g2.sequence == 2

        # Verify fail-closed on expiry
        with pytest.raises(ExpiredGraph):
            verify_envelope(env2, pub, now=NOW + 60 + 3600)

        # Verify fail-closed on tamper
        payload = json.loads(base64.b64decode(env2["payload"]))
        payload["producer"] = "mallory"
        tampered = dict(
            env2,
            payload=base64.b64encode(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).decode(),
        )
        with pytest.raises(BadSignature):
            verify_envelope(tampered, pub, now=NOW + 120)
    finally:
        nf_col.stop()
        sf_col.stop()
        ol_col.stop()


def test_gui_ingest_config_and_run_once_endpoints(tmp_path):
    import threading

    from estate_graph.serve import serve_views

    server = serve_views(
        tmp_path / "views",
        host="127.0.0.1",
        port=0,
        keys_dir=tmp_path / "keys",
        require_auth=False,
    )
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ingest/config") as resp:
            cfg_res = json.loads(resp.read())
            assert cfg_res["ok"] is True
            assert "env_status" in cfg_res

        save_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/ingest/config",
            data=json.dumps(
                {
                    "graph_id": "gui-estate",
                    "ttl_seconds": 3600,
                    "reissue_interval_seconds": 300,
                    "sources": [
                        {"id": "nf-1", "type": "netflow", "host": "127.0.0.1", "port": 0}
                    ],
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(save_req) as resp:
            saved = json.loads(resp.read())
            assert saved["ok"] is True
            assert len(saved["config"]["sources"]) == 1

        run_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/ingest/run-once",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(run_req) as resp:
            run_res = json.loads(resp.read())
            assert run_res["ok"] is True
            assert run_res["view"] == "gui-estate_ingested_view.html"
            assert run_res["report"]["sequence"] == 1
    finally:
        server.shutdown()
        server.server_close()

