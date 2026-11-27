"""Live UDP flow collectors for NetFlow v9 / IPFIX and sFlow v5 (stdlib only)."""

from __future__ import annotations

import socket
import threading
import time

from ..sources.netflow import ORIGIN_IPFIX, TemplateCache, parse_netflow_packets
from ..sources.sflow import ORIGIN as ORIGIN_SFLOW, parse_sflow_datagrams
from .contract import CollectorResult, CollectorStats, IdentityResolver


class _BaseUDPCollector:
    origin: str = "udp-flow"

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        resolver: IdentityResolver | None = None,
        max_datagrams_per_cycle: int = 100_000,
    ) -> None:
        self.host = host
        self.port = port
        self._resolver = resolver
        self._max_datagrams = max_datagrams_per_cycle
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._buffer: list[bytes] = []

    def start(self) -> int:
        if self._sock is not None:
            return self.bound_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.1)
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._thread.start()
        return self.bound_port

    @property
    def bound_port(self) -> int:
        if self._sock is None:
            return self.port
        return int(self._sock.getsockname()[1])

    def _recv_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, _addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                if len(self._buffer) < self._max_datagrams:
                    self._buffer.append(data)

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    def _drain(self) -> list[bytes]:
        with self._lock:
            pkts = self._buffer
            self._buffer = []
        return pkts


class NetFlowUDPCollector(_BaseUDPCollector):
    """Live UDP collector for NetFlow v9 and IPFIX (default port 2055)."""

    origin = ORIGIN_IPFIX

    def __init__(self, host: str = "127.0.0.1", port: int = 2055, **kwargs) -> None:
        super().__init__(host=host, port=port, **kwargs)
        self._templates = TemplateCache()

    def collect(self) -> CollectorResult:
        t0 = time.perf_counter()
        stats = CollectorStats(origin=self.origin, live=self._sock is not None)
        packets = self._drain()
        observations = parse_netflow_packets(
            packets,
            self._resolver,
            template_cache=self._templates,
            stats=stats,
        )
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return CollectorResult(
            origin=self.origin, observations=observations, stats=stats
        )


class SFlowUDPCollector(_BaseUDPCollector):
    """Live UDP collector for sFlow v5 (default port 6343)."""

    origin = ORIGIN_SFLOW

    def __init__(self, host: str = "127.0.0.1", port: int = 6343, **kwargs) -> None:
        super().__init__(host=host, port=port, **kwargs)

    def collect(self) -> CollectorResult:
        t0 = time.perf_counter()
        stats = CollectorStats(origin=self.origin, live=self._sock is not None)
        datagrams = self._drain()
        observations = parse_sflow_datagrams(
            datagrams,
            self._resolver,
            observed_at=int(time.time()),
            stats=stats,
        )
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return CollectorResult(
            origin=self.origin, observations=observations, stats=stats
        )
