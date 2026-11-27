"""Standalone OpenLineage HTTP intake collector (stdlib only).

Accepts POSTed OpenLineage RunEvent JSON payloads at ``POST /api/v1/lineage``
and feeds them into the exact same ``parse_lineage()`` parser the file loader
uses. Lineage edges stay on ``layer="lineage"`` and never enter network
reconciliation.
"""

from __future__ import annotations

import json
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..sources.lineage import ORIGIN, parse_lineage
from .contract import CollectorResult, CollectorStats

MAX_BODY_BYTES = 10 * 1024 * 1024


class OpenLineageHTTPCollector:
    """Live HTTP intake endpoint for OpenLineage RunEvents."""

    origin = ORIGIN

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        max_events_per_cycle: int = 10_000,
    ) -> None:
        self.host = host
        self.port = port
        self._max_events = max_events_per_cycle
        self._lock = threading.Lock()
        self._buffer: list[dict] = []
        self._dropped: dict[str, int] = {}
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def bound_port(self) -> int:
        if self._server is None:
            return self.port
        return int(self._server.server_address[1])

    def start(self) -> int:
        if self._server is not None:
            return self.bound_port
        collector = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, status: int, body: dict) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:  # noqa: N802
                if self.path == "/health":
                    self._reply(HTTPStatus.OK, {"status": "ok", "origin": ORIGIN})
                    return
                self._reply(HTTPStatus.NOT_FOUND, {"error": "not_found"})

            def do_POST(self) -> None:  # noqa: N802
                if self.path not in ("/api/v1/lineage", "/lineage"):
                    self._reply(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length <= 0 or length > MAX_BODY_BYTES:
                    with collector._lock:
                        collector._dropped["invalid_content_length"] = (
                            collector._dropped.get("invalid_content_length", 0) + 1
                        )
                    self._reply(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
                    return
                raw = self.rfile.read(length)
                try:
                    data = json.loads(raw.decode("utf-8"))
                except Exception:
                    with collector._lock:
                        collector._dropped["invalid_json"] = (
                            collector._dropped.get("invalid_json", 0) + 1
                        )
                    self._reply(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
                    return
                events = (
                    data["events"]
                    if isinstance(data, dict) and isinstance(data.get("events"), list)
                    else (data if isinstance(data, list) else [data])
                )
                accepted = 0
                with collector._lock:
                    for ev in events:
                        if not isinstance(ev, dict):
                            collector._dropped["non_dict_event"] = (
                                collector._dropped.get("non_dict_event", 0) + 1
                            )
                            continue
                        if len(collector._buffer) < collector._max_events:
                            collector._buffer.append(ev)
                            accepted += 1
                        else:
                            collector._dropped["buffer_full"] = (
                                collector._dropped.get("buffer_full", 0) + 1
                            )
                self._reply(HTTPStatus.ACCEPTED, {"accepted": accepted})

            def log_message(self, format: str, *args) -> None:  # noqa: A002
                return

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.bound_port

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    def collect(self) -> CollectorResult:
        t0 = time.perf_counter()
        stats = CollectorStats(origin=self.origin, live=self._server is not None)
        with self._lock:
            events = self._buffer
            self._buffer = []
            dropped = self._dropped
            self._dropped = {}
        for reason, cnt in dropped.items():
            stats.record_drop(reason, cnt)
        stats.records_in = len(events) + sum(dropped.values())
        edges, nodes = parse_lineage(events) if events else ([], [])
        stats.observations_out = len(edges)
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return CollectorResult(
            origin=self.origin,
            extra_edges=edges,
            extra_nodes=nodes,
            stats=stats,
        )
