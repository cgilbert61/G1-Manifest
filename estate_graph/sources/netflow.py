"""Pure RFC 3954 (NetFlow v9) and RFC 7011 (IPFIX / v10) binary flow parser.

Decodes template sets and data sets into deterministic ``FlowObservation``
records with zero third-party dependencies. Malformed, truncated, or
unknown-template datagrams are cleanly dropped and counted via ``CollectorStats``.
"""

from __future__ import annotations

import ipaddress
import struct

from ..ingestors.contract import CollectorStats, IdentityResolver, validate_observations
from ..model import FlowObservation

ORIGIN_NETFLOW_V9 = "netflow-v9"
ORIGIN_IPFIX = "ipfix"

_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMP"}

# Standard NetFlow v9 / IPFIX Information Element IDs
IE_IN_BYTES = 1
IE_IN_PKTS = 2
IE_PROTOCOL = 4
IE_L4_SRC_PORT = 7
IE_IPV4_SRC_ADDR = 8
IE_L4_DST_PORT = 11
IE_IPV4_DST_ADDR = 12
IE_IPV6_SRC_ADDR = 27
IE_IPV6_DST_ADDR = 28
IE_FORWARDING_STATUS = 89
IE_FLOW_START_SEC = 150
IE_FLOW_END_SEC = 151
IE_FLOW_START_MS = 152
IE_FLOW_END_MS = 153


class TemplateCache:
    """In-memory cache mapping (version, domain_id, template_id) -> field specs."""

    def __init__(self) -> None:
        self._templates: dict[tuple[int, int, int], list[tuple[int, int]]] = {}

    def put(
        self, version: int, domain_id: int, template_id: int, fields: list[tuple[int, int]]
    ) -> None:
        self._templates[(version, domain_id, template_id)] = list(fields)

    def get(
        self, version: int, domain_id: int, template_id: int
    ) -> list[tuple[int, int]] | None:
        return self._templates.get((version, domain_id, template_id))


def _decode_uint(raw: bytes) -> int:
    return int.from_bytes(raw, "big", signed=False)


def _decode_ip(raw: bytes) -> str | None:
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw))
    if len(raw) == 16:
        return str(ipaddress.IPv6Address(raw))
    return None


def _parse_template_set(
    version: int,
    domain_id: int,
    body: bytes,
    cache: TemplateCache,
    stats: CollectorStats | None,
) -> None:
    offset = 0
    while offset + 4 <= len(body):
        template_id, field_count = struct.unpack_from("!HH", body, offset)
        offset += 4
        if template_id < 256 or field_count == 0:
            break  # padding or invalid template
        fields: list[tuple[int, int]] = []
        ok = True
        for _ in range(field_count):
            if offset + 4 > len(body):
                ok = False
                if stats:
                    stats.record_drop("truncated_template")
                break
            ftype, flen = struct.unpack_from("!HH", body, offset)
            offset += 4
            # IPFIX enterprise bit (RFC 7011 §3.2): high bit set -> 4B enterprise num follows
            if version == 10 and (ftype & 0x8000):
                if offset + 4 > len(body):
                    ok = False
                    if stats:
                        stats.record_drop("truncated_enterprise_field")
                    break
                offset += 4
                ftype = ftype & 0x7FFF
            if flen == 0 or flen == 0xFFFF:
                ok = False
                if stats:
                    stats.record_drop("unsupported_variable_length_field")
                break
            fields.append((ftype, flen))
        if ok and fields:
            cache.put(version, domain_id, template_id, fields)


def parse_netflow_packets(
    packets: list[bytes],
    resolver: IdentityResolver | None = None,
    *,
    template_cache: TemplateCache | None = None,
    stats: CollectorStats | None = None,
) -> list[FlowObservation]:
    """Decode NetFlow v9 (ver=9) and IPFIX (ver=10) binary datagrams."""
    cache = template_cache if template_cache is not None else TemplateCache()
    agg: dict[tuple, FlowObservation] = {}

    for pkt in packets:
        if not isinstance(pkt, (bytes, bytearray)) or len(pkt) < 16:
            if stats:
                stats.records_in += 1
                stats.record_drop("truncated_header")
            continue

        version = struct.unpack_from("!H", pkt, 0)[0]
        if version == 9:
            if len(pkt) < 20:
                if stats:
                    stats.records_in += 1
                    stats.record_drop("truncated_v9_header")
                continue
            _ver, _count, _uptime, export_ts, _seq, domain_id = struct.unpack_from(
                "!HHIIII", pkt, 0
            )
            offset = 20
            end_offset = len(pkt)
            template_set_id = 0
            origin = ORIGIN_NETFLOW_V9
        elif version == 10:
            _ver, msg_len, export_ts, _seq, domain_id = struct.unpack_from(
                "!HHIII", pkt, 0
            )
            if msg_len < 16 or msg_len > len(pkt):
                if stats:
                    stats.records_in += 1
                    stats.record_drop("invalid_ipfix_length")
                continue
            offset = 16
            end_offset = msg_len
            template_set_id = 2
            origin = ORIGIN_IPFIX
        else:
            if stats:
                stats.records_in += 1
                stats.record_drop("unsupported_version")
            continue

        while offset + 4 <= end_offset:
            set_id, set_len = struct.unpack_from("!HH", pkt, offset)
            if set_len < 4 or offset + set_len > end_offset:
                if stats:
                    stats.records_in += 1
                    stats.record_drop("invalid_set_length")
                break
            body = pkt[offset + 4 : offset + set_len]
            offset += set_len

            if set_id == template_set_id:
                _parse_template_set(version, domain_id, body, cache, stats)
                continue
            if set_id < 256:
                continue  # options template or reserved set

            fields = cache.get(version, domain_id, set_id)
            if not fields:
                if stats:
                    stats.records_in += 1
                    stats.record_drop("unknown_template")
                continue

            rec_size = sum(flen for _ft, flen in fields)
            rec_off = 0
            while rec_off + rec_size <= len(body):
                if stats:
                    stats.records_in += 1
                src_ip: str | None = None
                dst_ip: str | None = None
                dst_port: int | None = None
                proto_num: int | None = None
                first_ts = export_ts
                last_ts = export_ts
                dropped_status = False

                pos = rec_off
                for ftype, flen in fields:
                    raw = body[pos : pos + flen]
                    pos += flen
                    if ftype in (IE_IPV4_SRC_ADDR, IE_IPV6_SRC_ADDR):
                        src_ip = _decode_ip(raw)
                    elif ftype in (IE_IPV4_DST_ADDR, IE_IPV6_DST_ADDR):
                        dst_ip = _decode_ip(raw)
                    elif ftype == IE_L4_DST_PORT:
                        dst_port = _decode_uint(raw)
                    elif ftype == IE_PROTOCOL:
                        proto_num = _decode_uint(raw)
                    elif ftype == IE_FLOW_START_SEC:
                        first_ts = _decode_uint(raw)
                    elif ftype == IE_FLOW_END_SEC:
                        last_ts = _decode_uint(raw)
                    elif ftype == IE_FLOW_START_MS:
                        first_ts = _decode_uint(raw) // 1000
                    elif ftype == IE_FLOW_END_MS:
                        last_ts = _decode_uint(raw) // 1000
                    elif ftype == IE_FORWARDING_STATUS and flen >= 1:
                        # Top 2 bits: 01=forwarded, 10=dropped, 11=consumed
                        status_class = (raw[0] >> 6) & 0x03
                        if status_class == 2:
                            dropped_status = True
                rec_off += rec_size

                if dropped_status:
                    if stats:
                        stats.record_drop("dropped_forwarding_status")
                    continue
                if not src_ip or not dst_ip:
                    if stats:
                        stats.record_drop("missing_ip")
                    continue

                src = resolver.resolve(src_ip)[0] if resolver else f"ip:{src_ip}"
                dst = resolver.resolve(dst_ip)[0] if resolver else f"ip:{dst_ip}"
                if src == dst:
                    if stats:
                        stats.record_drop("self_traffic")
                    continue
                proto = (
                    _PROTOCOLS.get(proto_num, str(proto_num))
                    if proto_num is not None
                    else None
                )
                port = None if proto == "ICMP" else dst_port
                key = (src, dst, port, proto, origin)
                obs = agg.get(key)
                if obs is None:
                    agg[key] = FlowObservation(
                        source=src,
                        target=dst,
                        port=port,
                        protocol=proto,
                        count=1,
                        first_seen=first_ts,
                        last_seen=last_ts,
                        origin=origin,
                    )
                else:
                    obs.count += 1
                    if first_ts:
                        obs.first_seen = (
                            min(obs.first_seen, first_ts) if obs.first_seen else first_ts
                        )
                    obs.last_seen = max(obs.last_seen, last_ts)

    observations = validate_observations(list(agg.values()), stats=stats)
    if stats:
        stats.observations_out = len(observations)
    return observations


def build_ipfix_packet(
    flows: list[tuple[str, str, int, int, int]],
    *,
    export_ts: int,
    domain_id: int = 1,
    template_id: int = 256,
    seq: int = 1,
) -> bytes:
    """Build a valid RFC 7011 IPFIX datagram containing a template + data set.

    Each flow tuple is ``(src_ipv4, dst_ipv4, dst_port, proto_num, fwd_status)``.
    """
    fields = [
        (IE_IPV4_SRC_ADDR, 4),
        (IE_IPV4_DST_ADDR, 4),
        (IE_L4_DST_PORT, 2),
        (IE_PROTOCOL, 1),
        (IE_FORWARDING_STATUS, 1),
    ]
    tmpl_body = struct.pack("!HH", template_id, len(fields)) + b"".join(
        struct.pack("!HH", ft, fl) for ft, fl in fields
    )
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl_body)) + tmpl_body

    data_body = b"".join(
        ipaddress.IPv4Address(s).packed
        + ipaddress.IPv4Address(d).packed
        + struct.pack("!HBB", port, proto, fwd)
        for s, d, port, proto, fwd in flows
    )
    data_set = struct.pack("!HH", template_id, 4 + len(data_body)) + data_body
    total_len = 16 + len(tmpl_set) + len(data_set)
    header = struct.pack("!HHIII", 10, total_len, export_ts, seq, domain_id)
    return header + tmpl_set + data_set


def build_netflow_v9_packet(
    flows: list[tuple[str, str, int, int, int]],
    *,
    export_ts: int,
    source_id: int = 1,
    template_id: int = 256,
    seq: int = 1,
) -> bytes:
    """Build a valid RFC 3954 NetFlow v9 datagram containing template + data set."""
    fields = [
        (IE_IPV4_SRC_ADDR, 4),
        (IE_IPV4_DST_ADDR, 4),
        (IE_L4_DST_PORT, 2),
        (IE_PROTOCOL, 1),
        (IE_FORWARDING_STATUS, 1),
    ]
    tmpl_body = struct.pack("!HH", template_id, len(fields)) + b"".join(
        struct.pack("!HH", ft, fl) for ft, fl in fields
    )
    tmpl_set = struct.pack("!HH", 0, 4 + len(tmpl_body)) + tmpl_body

    data_body = b"".join(
        ipaddress.IPv4Address(s).packed
        + ipaddress.IPv4Address(d).packed
        + struct.pack("!HBB", port, proto, fwd)
        for s, d, port, proto, fwd in flows
    )
    data_set = struct.pack("!HH", template_id, 4 + len(data_body)) + data_body
    header = struct.pack("!HHIIII", 9, 1 + len(flows), 1000, export_ts, seq, source_id)
    return header + tmpl_set + data_set
