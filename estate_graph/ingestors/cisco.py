"""Read-only Cisco Catalyst Center & SNA REST collector (stdlib only, no vendor SDK)."""

from __future__ import annotations

import os
import time
import urllib.request

from ..sources.cisco import (
    ORIGIN_CATALYST,
    ORIGIN_SNA,
    parse_cisco_catalyst_inventory,
    parse_cisco_sna_flows,
)
from .contract import CollectorResult, CollectorStats, IdentityResolver


def _default_get(url: str, headers: dict[str, str], timeout: float = 15.0) -> str:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


class CiscoCollector:
    """Read-only REST collector for Cisco Catalyst Center inventory + SNA flows."""

    origin = ORIGIN_SNA

    def __init__(
        self,
        *,
        catalyst_url: str | None = None,
        sna_flows_url: str | None = None,
        token_env: str = "CISCO_API_TOKEN",
        resolver: IdentityResolver | None = None,
        http_get=None,
        live: bool = False,
    ) -> None:
        self.catalyst_url = catalyst_url
        self.sna_flows_url = sna_flows_url
        self.token_env = token_env
        self._resolver = resolver or IdentityResolver()
        self._http_get = http_get or _default_get
        self._live = live

    def _headers(self) -> dict[str, str]:
        token = os.environ.get(self.token_env, "").strip()
        hdrs = {"Accept": "application/json"}
        if token:
            hdrs["X-Auth-Token"] = token
        return hdrs

    def collect(self) -> CollectorResult:
        t0 = time.perf_counter()
        stats = CollectorStats(origin=self.origin, live=self._live)
        hdrs = self._headers()
        extra_nodes = []

        if self.catalyst_url:
            inv_raw = self._http_get(
                self.catalyst_url.rstrip("/") + "/dna/intent/api/v1/network-device",
                hdrs,
            )
            ip_map, nodes = parse_cisco_catalyst_inventory(inv_raw)
            self._resolver.register_bulk(ip_map, ORIGIN_CATALYST)
            extra_nodes.extend(nodes)

        observations = []
        if self.sna_flows_url:
            flows_raw = self._http_get(self.sna_flows_url, hdrs)
            observations = parse_cisco_sna_flows(
                flows_raw, self._resolver, stats=stats
            )

        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return CollectorResult(
            origin=self.origin,
            observations=observations,
            extra_nodes=extra_nodes,
            stats=stats,
        )
