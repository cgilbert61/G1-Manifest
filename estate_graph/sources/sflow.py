"""Pure RFC 3176 sFlow v5 binary datagram parser.

Decodes sFlow v5 Flow Samples (format 1 & expanded format 3) containing
Ethernet + IPv4/IPv6 + TCP/UDP/ICMP raw packet headers into deterministic
``FlowObservation`` objects. Every emitted observation carries
``labels={"sampling_rate": <rate>, "sampled": True}`` so sampled counts are
never misread as exact flow counts.
"""

from __future__ import annotations

import ipaddress
import struct

from ..ingestors.contract import CollectorStats, IdentityResolver, validate_observations
from ..model import FlowObservation

ORIGIN = "sflow"
_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMP"}


def _parse_raw_ethernet_ip(header_bytes: bytes) -> tuple[str, str, int | None, str] | None:
    """Extract (src_ip, dst_ip, dst_port, proto) from an Ethernet frame header."""
    if len(header_bytes) < 14:
        return None
    ethertype = struct.unpack_from("!H", header_bytes, 12)[0]
    offset = 14
    # Single 802.1Q VLAN tag
    if ethertype == 0x8100:
        if len(header_bytes) < 18:
            return None
        ethertype = struct.unpack_from("!H", header_bytes, 16)[0]
        offset = 18

    if ethertype == 0x0800:  # IPv4
        if len(header_bytes) < offset + 20:
            return None
        ver_ihl = header_bytes[offset]
        ihl = (ver_ihl & 0x0F) * 4
        if (ver_ihl >> 4) != 4 or ihl < 20 or len(header_bytes) < offset + ihl:
            return None
        proto_num = header_bytes[offset + 9]
        src_ip = str(ipaddress.IPv4Address(header_bytes[offset + 12 : offset + 16]))
        dst_ip = str(ipaddress.IPv4Address(header_bytes[offset + 16 : offset + 20]))
        l4_off = offset + ihl
    elif ethertype == 0x86DD:  # IPv6
        if len(header_bytes) < offset + 40:
            return None
        proto_num = header_bytes[offset + 6]
        src_ip = str(ipaddress.IPv6Address(header_bytes[offset + 8 : offset + 24]))
        dst_ip = str(ipaddress.IPv6Address(header_bytes[offset + 24 : offset + 40]))
        l4_off = offset + 40
    else:
        return None

    proto = _PROTOCOLS.get(proto_num, str(proto_num))
    dst_port: int | None = None
    if proto in ("TCP", "UDP"):
        if len(header_bytes) >= l4_off + 4:
            _src_port, dst_port = struct.unpack_from("!HH", header_bytes, l4_off)
    return src_ip, dst_ip, dst_port, proto


def parse_sflow_datagrams(
    datagrams: list[bytes],
    resolver: IdentityResolver | None = None,
    *,
    observed_at: int = 0,
    stats: CollectorStats | None = None,
) -> list[FlowObservation]:
    """Decode sFlow v5 binary datagrams into sampled FlowObservations."""
    agg: dict[tuple, FlowObservation] = {}

    for dgram in datagrams:
        if not isinstance(dgram, (bytes, bytearray)) or len(dgram) < 28:
            if stats:
                stats.records_in += 1
                stats.record_drop("truncated_sflow_header")
            continue
        ver, addr_type = struct.unpack_from("!II", dgram, 0)
        if ver != 5:
            if stats:
                stats.records_in += 1
                stats.record_drop("unsupported_sflow_version")
            continue
        if addr_type == 1:
            addr_len = 4
        elif addr_type == 2:
            addr_len = 16
        else:
            if stats:
                stats.records_in += 1
                stats.record_drop("invalid_agent_addr_type")
            continue
        hdr_end = 8 + addr_len + 16
        if len(dgram) < hdr_end:
            if stats:
                stats.records_in += 1
                stats.record_drop("truncated_sflow_header")
            continue
        _sub_agent, _seq, _uptime, num_samples = struct.unpack_from(
            "!IIII", dgram, 8 + addr_len
        )
        offset = hdr_end

        for _ in range(num_samples):
            if offset + 8 > len(dgram):
                if stats:
                    stats.records_in += 1
                    stats.record_drop("truncated_sample")
                break
            sample_type, sample_len = struct.unpack_from("!II", dgram, offset)
            offset += 8
            if offset + sample_len > len(dgram):
                if stats:
                    stats.records_in += 1
                    stats.record_drop("invalid_sample_length")
                break
            sample_body = dgram[offset : offset + sample_len]
            offset += sample_len

            enterprise = sample_type >> 12
            fmt = sample_type & 0xFFF
            if enterprise != 0 or fmt not in (1, 3):
                continue  # counter sample or enterprise extension

            if fmt == 1:
                if len(sample_body) < 32:
                    if stats:
                        stats.records_in += 1
                        stats.record_drop("truncated_flow_sample")
                    continue
                (
                    _s_seq,
                    _src_id,
                    sampling_rate,
                    _pool,
                    _drops,
                    _in_if,
                    _out_if,
                    num_records,
                ) = struct.unpack_from("!IIIIIIII", sample_body, 0)
                rec_off = 32
            else:  # expanded flow sample (format 3)
                if len(sample_body) < 44:
                    if stats:
                        stats.records_in += 1
                        stats.record_drop("truncated_expanded_flow_sample")
                    continue
                (
                    _s_seq,
                    _src_t,
                    _src_idx,
                    sampling_rate,
                    _pool,
                    _drops,
                    _in_f,
                    _in_v,
                    _out_f,
                    _out_v,
                    num_records,
                ) = struct.unpack_from("!IIIIIIIIIII", sample_body, 0)
                rec_off = 44

            for _r in range(num_records):
                if rec_off + 8 > len(sample_body):
                    break
                rec_type, rec_len = struct.unpack_from("!II", sample_body, rec_off)
                rec_off += 8
                if rec_off + rec_len > len(sample_body):
                    if stats:
                        stats.records_in += 1
                        stats.record_drop("truncated_flow_record")
                    break
                rec_body = sample_body[rec_off : rec_off + rec_len]
                rec_off += rec_len

                if (rec_type >> 12) != 0 or (rec_type & 0xFFF) != 1:
                    continue  # not raw packet header
                if stats:
                    stats.records_in += 1
                if len(rec_body) < 16:
                    if stats:
                        stats.record_drop("truncated_raw_header")
                    continue
                hdr_proto, _frame_len, _stripped, hdr_len = struct.unpack_from(
                    "!IIII", rec_body, 0
                )
                if hdr_proto != 1 or 16 + hdr_len > len(rec_body):
                    if stats:
                        stats.record_drop("unsupported_header_protocol")
                    continue
                parsed = _parse_raw_ethernet_ip(rec_body[16 : 16 + hdr_len])
                if not parsed:
                    if stats:
                        stats.record_drop("non_ip_frame")
                    continue
                src_ip, dst_ip, dst_port, proto = parsed
                src = resolver.resolve(src_ip)[0] if resolver else f"ip:{src_ip}"
                dst = resolver.resolve(dst_ip)[0] if resolver else f"ip:{dst_ip}"
                if src == dst:
                    if stats:
                        stats.record_drop("self_traffic")
                    continue

                rate = max(1, int(sampling_rate))
                key = (src, dst, dst_port, proto)
                obs = agg.get(key)
                if obs is None:
                    agg[key] = FlowObservation(
                        source=src,
                        target=dst,
                        port=dst_port,
                        protocol=proto,
                        count=1,
                        first_seen=observed_at,
                        last_seen=observed_at,
                        origin=ORIGIN,
                        labels={"sampling_rate": rate, "sampled": True},
                    )
                else:
                    obs.count += 1
                    obs.labels["sampling_rate"] = max(
                        int(obs.labels.get("sampling_rate", 1)), rate
                    )

    observations = validate_observations(list(agg.values()), stats=stats)
    if stats:
        stats.observations_out = len(observations)
    return observations


def build_sflow_v5_datagram(
    samples: list[tuple[str, str, int, int, int]],
    *,
    agent_ip: str = "10.0.0.254",
    seq: int = 1,
) -> bytes:
    """Build a valid RFC 3176 sFlow v5 datagram with Ethernet+IPv4+TCP/UDP headers.

    Each tuple is ``(src_ipv4, dst_ipv4, dst_port, proto_num, sampling_rate)``.
    """
    sample_chunks: list[bytes] = []
    for idx, (src_ip, dst_ip, dst_port, proto_num, rate) in enumerate(samples, start=1):
        eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ipv4 = (
            struct.pack("!BBHHHBBH", 0x45, 0, 40, 0, 0, 64, proto_num, 0)
            + ipaddress.IPv4Address(src_ip).packed
            + ipaddress.IPv4Address(dst_ip).packed
        )
        l4 = struct.pack("!HH", 50000 + idx, dst_port) + b"\x00" * 16
        frame = eth + ipv4 + l4
        pad = (-len(frame)) % 4
        raw_hdr = struct.pack("!IIII", 1, len(frame), 4, len(frame)) + frame + b"\x00" * pad
        flow_rec = struct.pack("!II", 1, len(raw_hdr)) + raw_hdr
        flow_sample_body = (
            struct.pack("!IIIIIIII", idx, 1, rate, rate, 0, 1, 2, 1) + flow_rec
        )
        sample_chunks.append(
            struct.pack("!II", 1, len(flow_sample_body)) + flow_sample_body
        )

    header = (
        struct.pack("!II", 5, 1)
        + ipaddress.IPv4Address(agent_ip).packed
        + struct.pack("!IIII", 0, seq, 1000, len(sample_chunks))
    )
    return header + b"".join(sample_chunks)
