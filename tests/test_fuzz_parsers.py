"""Deterministic fuzzing & adversarial input tests for G1-Manifest parsers.

Throws thousands of random, truncated, bit-flipped, and type-confused inputs at:
- NetFlow v9 / IPFIX binary parser (`sources/netflow.py`)
- sFlow v5 binary parser (`sources/sflow.py`)
- Azure NSG & GCP VPC parsers (`sources/cloud_flows.py`)
- Cisco Catalyst & SNA parsers (`sources/cisco.py`)
- ServiceNow CMDB parser (`sources/servicenow.py`)
- Skeleton parser (`ingestors/skeleton.py`)

Invariants:
1. No unhandled exceptions on any malformed, truncated, or hostile input.
2. Bounded execution time (no infinite loops or billion-iteration DoS).
3. Every emitted FlowObservation obeys contract invariants.
"""

from __future__ import annotations

import random
import struct
import time

from estate_graph.ingestors.contract import CollectorStats
from estate_graph.ingestors.skeleton import parse_skeleton_records
from estate_graph.sources.cisco import (
    parse_cisco_catalyst_inventory,
    parse_cisco_sna_flows,
)
from estate_graph.sources.cloud_flows import (
    parse_azure_nsg_flow_logs,
    parse_gcp_vpc_flow_logs,
)
from estate_graph.sources.netflow import (
    TemplateCache,
    build_ipfix_packet,
    build_netflow_v9_packet,
    parse_netflow_packets,
)
from estate_graph.sources.servicenow import parse_servicenow_cmdb
from estate_graph.sources.sflow import build_sflow_v5_datagram, parse_sflow_datagrams

NOW = 1795716000


def _mutate_bytes(rng: random.Random, seed: bytes) -> bytes:
    buf = bytearray(seed)
    mode = rng.randrange(4)
    if mode == 0 and buf:  # truncate
        return bytes(buf[: rng.randrange(len(buf))])
    if mode == 1 and buf:  # flip 1..4 random bytes
        for _ in range(rng.randint(1, 4)):
            buf[rng.randrange(len(buf))] = rng.randrange(256)
        return bytes(buf)
    if mode == 2 and len(buf) >= 4:  # inject extreme 16/32-bit ints
        pos = rng.randrange(len(buf) - 3)
        buf[pos : pos + 4] = rng.choice(
            [b"\x00\x00\x00\x00", b"\xff\xff\xff\xff", b"\x7f\xff\xff\xff", b"\x80\x00\x00\x00"]
        )
        return bytes(buf)
    # append garbage
    return bytes(buf) + rng.randbytes(rng.randint(1, 64))


def test_fuzz_netflow_v9_and_ipfix_binary_parser():
    rng = random.Random(20261127)
    seed_ipfix = build_ipfix_packet(
        [("10.0.0.1", "10.0.0.2", 443, 6, 0x40)], export_ts=NOW
    )
    seed_nf9 = build_netflow_v9_packet(
        [("10.0.0.1", "10.0.0.2", 8443, 6, 0x40)], export_ts=NOW
    )

    corpus: list[bytes] = [
        b"",
        b"\x00",
        b"\x00\x09" + b"\x00" * 30,
        b"\x00\x0a" + b"\x00" * 30,
        # Craft huge field_count / zero set_len / enterprise bit on short buffer
        struct.pack("!HHIIIHHHH", 10, 24, NOW, 1, 1, 2, 8, 256, 0xFFFF),
        struct.pack("!HHIIIIHHHH", 9, 1, 0, NOW, 1, 1, 0, 8, 256, 0xFFFF),
    ]
    for _ in range(1500):
        corpus.append(rng.randbytes(rng.randint(0, 256)))
    for _ in range(750):
        corpus.append(_mutate_bytes(rng, seed_ipfix))
        corpus.append(_mutate_bytes(rng, seed_nf9))

    t0 = time.perf_counter()
    cache = TemplateCache()
    stats = CollectorStats(origin="netflow-fuzz")
    obs = parse_netflow_packets(corpus, template_cache=cache, stats=stats)
    elapsed = time.perf_counter() - t0

    assert elapsed < 5.0, f"NetFlow fuzzing took too long ({elapsed:.2f}s) — possible DoS loop"
    for o in obs:
        assert o.source and o.target and o.source != o.target
        assert o.count > 0
        assert o.first_seen >= 0 and o.last_seen >= 0


def test_fuzz_sflow_v5_binary_parser():
    rng = random.Random(20261128)
    seed_sf = build_sflow_v5_datagram(
        [("10.0.0.1", "10.0.0.2", 443, 6, 1000)]
    )

    corpus: list[bytes] = [
        b"",
        b"\x00\x00\x00\x05" + b"\x00" * 40,
        # Craft num_samples = 0xFFFFFFFF with minimal datagram
        struct.pack("!IIIIIII", 5, 1, 0x0A000001, 0, 1, 100, 0xFFFFFFFF),
        # Craft addr_type = 2 (IPv6) truncated
        struct.pack("!II", 5, 2) + b"\x00" * 16,
    ]
    for _ in range(1500):
        corpus.append(rng.randbytes(rng.randint(0, 256)))
    for _ in range(1000):
        corpus.append(_mutate_bytes(rng, seed_sf))

    t0 = time.perf_counter()
    stats = CollectorStats(origin="sflow-fuzz")
    obs = parse_sflow_datagrams(corpus, observed_at=NOW, stats=stats)
    elapsed = time.perf_counter() - t0

    assert elapsed < 5.0, f"sFlow fuzzing took too long ({elapsed:.2f}s) — possible DoS loop"
    for o in obs:
        assert o.source and o.target and o.source != o.target
        assert o.count > 0
        assert o.labels.get("sampled") is True
        assert int(o.labels.get("sampling_rate", 0)) >= 1


def test_fuzz_json_and_vendor_parsers_adversarial_inputs():
    hostile_inputs = [
        "",
        "{",
        "[]",
        "null",
        "12345",
        '{"records": "not-a-list"}',
        '{"records": [null, 123, {"properties": null}, {"properties": {"flows": [null, {"flows": [{"flowTuples": [null, "a,b,c", "bad,1,2,3,4,5,6,A"]}]}]}}]}',
        '{"jsonPayload": null}',
        '{"jsonPayload": {"connection": "bad"}}',
        '{"jsonPayload": {"connection": {"src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "dest_port": "nan", "protocol": null}, "start_time": "not-a-ts"}}',
        '{"response": [null, 42, {"hostname": 123, "managementIpAddress": null}]}',
        '{"data": "not-a-dict"}',
        '{"data": {"flows": [null, {"subject": null, "peer": {"ipAddress": "1.1.1.1", "portProtocol": "bad/tcp"}, "statistics": "bad"}]}}',
        '{"result": [null, 99, {"sys_id": null, "name": ""}]}',
    ]

    for raw in hostile_inputs:
        parse_azure_nsg_flow_logs(raw, stats=CollectorStats(origin="az"))
        parse_gcp_vpc_flow_logs(raw, stats=CollectorStats(origin="gcp"))
        parse_cisco_sna_flows(raw, stats=CollectorStats(origin="sna"))
        parse_cisco_catalyst_inventory(raw)
        parse_servicenow_cmdb(raw, raw)

    # Also fuzz skeleton parser with type-confused dicts
    parse_skeleton_records(
        [
            None,
            123,
            {},
            {"action": "ACCEPT", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "dst_port": "oops", "timestamp": "bad"},
            {"action": "ACCEPT", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "dst_port": 443, "timestamp": -999999999999},
        ],
        stats=CollectorStats(origin="skel"),
    )
