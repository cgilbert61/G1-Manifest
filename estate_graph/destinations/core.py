"""Single shared export path for G1-Manifest downstream destinations.

Every downstream adapter plugs into ``ExportEngine``:
1. Verifies the DSSEv1 Ed25519 envelope fail-closed via ``verify_envelope`` —
   an expired or unverified graph is NEVER exported as current.
2. Computes a stable ``envelope_id`` and attaches ``envelope_id`` +
   ``expires_at`` to every exported node, edge, and finding.
3. Supports three send modes: ``full``, ``delta`` (since last successful send
   to that destination), and ``findings_only``.
4. Isolates failures per destination so one failing downstream system never
   blocks or corrupts exports to others.
5. Persists per-destination configuration (credential references only, never
   raw secrets) and logs every configuration change as an audited record.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..model import DependencyGraph, Edge, ServiceNode, iso_utc
from ..reconcile import reconcile
from ..sources.declared import DeclaredModel
from ..verify import VerificationError, verify_envelope

VALID_SEND_MODES = ("full", "delta", "findings_only")


def envelope_id_for(envelope: dict, graph: DependencyGraph) -> str:
    """Stable trace identifier binding downstream records to the signed envelope."""
    digest = hashlib.sha256(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:12]
    return f"{graph.graph_id}:seq{graph.sequence}:{digest}"


@dataclass
class ExportBundle:
    """Normalized, verified payload handed by ExportEngine to every adapter."""

    envelope_id: str
    graph_id: str
    sequence: int
    producer: str
    issued_at: int
    expires_at: int
    mode: str  # full | delta | findings_only
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    reconcile_summary: dict | None = None

    def to_dict(self) -> dict:
        return {
            "envelope_id": self.envelope_id,
            "graph_id": self.graph_id,
            "sequence": self.sequence,
            "producer": self.producer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "expires_utc": iso_utc(self.expires_at),
            "mode": self.mode,
            "nodes": self.nodes,
            "edges": self.edges,
            "findings": self.findings,
            "reconcile_summary": self.reconcile_summary,
        }


@dataclass
class ExportResult:
    """Per-destination delivery accounting."""

    destination_id: str
    system: str
    mode: str
    envelope_id: str
    expires_at: int
    ok: bool
    accepted: int = 0
    rejected: int = 0
    unsupported: int = 0
    elapsed_ms: float = 0.0
    error: str | None = None
    live: bool = False
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "destination_id": self.destination_id,
            "system": self.system,
            "mode": self.mode,
            "envelope_id": self.envelope_id,
            "expires_at": self.expires_at,
            "ok": self.ok,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "unsupported": self.unsupported,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "error": self.error,
            "live": self.live,
            "details": self.details,
        }


def default_http_post(
    url: str,
    payload: bytes,
    headers: dict[str, str],
    *,
    method: str = "POST",
    timeout: float = 15.0,
) -> tuple[int, str]:
    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return int(resp.status), resp.read().decode("utf-8", errors="replace")


class BaseDestinationAdapter:
    """Base contract for every downstream destination adapter."""

    system: str = "generic"
    group: str = "graph-and-catalog"
    default_target_view: str = "API endpoint"

    def __init__(self, config: dict, *, http_send=None) -> None:
        self.config = dict(config)
        self.destination_id = str(config.get("id") or self.system)
        self.endpoint = str(config.get("endpoint") or "").strip()
        self.credential_ref = str(config.get("credential_ref") or "").strip()
        self._http_send = http_send or default_http_post
        self._is_live = http_send is None

    def _resolve_credential(self) -> str:
        """Read secret strictly from the referenced env var; never store raw."""
        if not self.credential_ref:
            return ""
        return os.environ.get(self.credential_ref, "").strip()

    def build_payloads(self, bundle: ExportBundle) -> list[tuple[str, dict, dict[str, str]]]:
        """Return list of (url, json_body_dict, headers) requests to send."""
        raise NotImplementedError

    def send(self, bundle: ExportBundle) -> ExportResult:
        t0 = time.perf_counter()
        if not self.endpoint:
            return ExportResult(
                destination_id=self.destination_id,
                system=self.system,
                mode=bundle.mode,
                envelope_id=bundle.envelope_id,
                expires_at=bundle.expires_at,
                ok=False,
                error="destination endpoint is not configured",
                live=self._is_live,
            )
        requests = self.build_payloads(bundle)
        accepted = 0
        rejected = 0
        unsupported = 0
        errors: list[str] = []

        for url, body, headers in requests:
            if body.get("_unsupported"):
                unsupported += int(body.get("_count", 1))
                continue
            raw = json.dumps(body, sort_keys=True).encode("utf-8")
            try:
                status, _resp_text = self._http_send(url, raw, headers)
                if 200 <= status < 300:
                    accepted += int(body.get("_record_count", 1))
                else:
                    rejected += int(body.get("_record_count", 1))
                    errors.append(f"HTTP {status} from {url}")
            except Exception as exc:
                rejected += int(body.get("_record_count", 1))
                errors.append(f"{type(exc).__name__}: {exc}")

        return ExportResult(
            destination_id=self.destination_id,
            system=self.system,
            mode=bundle.mode,
            envelope_id=bundle.envelope_id,
            expires_at=bundle.expires_at,
            ok=(rejected == 0 and not errors),
            accepted=accepted,
            rejected=rejected,
            unsupported=unsupported,
            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            error="; ".join(errors) if errors else None,
            live=self._is_live,
        )


def _node_record(node: ServiceNode, envelope_id: str, expires_at: int) -> dict:
    return {
        "id": node.id,
        "kind": node.kind,
        "substrate": node.substrate,
        "labels": dict(node.labels),
        "envelope_id": envelope_id,
        "expires_at": expires_at,
    }


def _edge_record(edge: Edge, envelope_id: str, expires_at: int) -> dict:
    return {
        "source": edge.source,
        "target": edge.target,
        "port": edge.port,
        "protocol": edge.protocol,
        "layer": edge.layer,
        "low_frequency": edge.low_frequency,
        "labels": dict(edge.labels),
        "evidence": edge.evidence.to_dict(),
        "envelope_id": envelope_id,
        "expires_at": expires_at,
    }


def _finding_records(report: dict | None, envelope_id: str, expires_at: int) -> list[dict]:
    if not report:
        return []
    out: list[dict] = []
    for item in report.get("observed_undeclared", []):
        rec = dict(item)
        rec["bucket"] = "observed_undeclared"
        rec["envelope_id"] = envelope_id
        rec["expires_at"] = expires_at
        out.append(rec)
    for item in report.get("declared_unobserved", []):
        rec = dict(item)
        rec["bucket"] = "declared_unobserved"
        rec["envelope_id"] = envelope_id
        rec["expires_at"] = expires_at
        out.append(rec)
    return out


class DestinationStateStore:
    """Tracks per-destination last-sent hashes for deterministic delta mode."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._state: dict[str, dict] = {}
        if self.path.is_file():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._state = data
            except Exception:
                self._state = {}

    def get(self, dest_id: str) -> dict:
        return dict(self._state.get(dest_id, {}))

    def record_success(
        self, dest_id: str, *, envelope_id: str, node_keys: list[str], edge_keys: list[str], finding_keys: list[str]
    ) -> None:
        self._state[dest_id] = {
            "last_envelope_id": envelope_id,
            "node_keys": sorted(set(node_keys)),
            "edge_keys": sorted(set(edge_keys)),
            "finding_keys": sorted(set(finding_keys)),
            "updated_at": int(time.time()),
        }
        self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._state, indent=2, sort_keys=True) + "\n"
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".dstate-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, self.path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


class DestinationConfigStore:
    """Persists destination configs (credential refs only) + audited change log."""

    def __init__(self, config_path: str | Path, audit_path: str | Path | None = None) -> None:
        self.config_path = Path(config_path)
        self.audit_path = (
            Path(audit_path)
            if audit_path is not None
            else self.config_path.parent / "destination_audit.jsonl"
        )

    def list_destinations(self) -> list[dict]:
        if not self.config_path.is_file():
            return []
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("destinations"), list):
                return list(data["destinations"])
        except Exception:
            pass
        return []

    def _save_all(self, dests: list[dict]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"destinations": dests}, indent=2, sort_keys=True) + "\n"
        fd, tmp = tempfile.mkstemp(dir=str(self.config_path.parent), prefix=".dcfg-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, self.config_path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _append_audit(self, actor: str, action: str, dest_id: str, summary: dict) -> dict:
        entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "actor": actor,
            "action": action,
            "destination_id": dest_id,
            "summary": summary,
        }
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def upsert(self, dest: dict, *, actor: str = "operator") -> tuple[dict, dict]:
        from .registry import SUPPORTED_SYSTEMS

        system = str(dest.get("system") or "").strip().lower()
        if system not in SUPPORTED_SYSTEMS:
            raise ValueError(f"unsupported downstream system: {system!r}")
        mode = str(dest.get("send_mode") or "full").strip().lower()
        if mode not in VALID_SEND_MODES:
            raise ValueError(f"send_mode must be one of {VALID_SEND_MODES}")
        endpoint = str(dest.get("endpoint") or "").strip()
        if not endpoint:
            raise ValueError("endpoint is required")
        # Reject obvious raw secret fields — credential_ref is a pointer only.
        for forbidden in ("password", "secret", "api_key", "token", "raw_secret"):
            if dest.get(forbidden):
                raise ValueError(
                    f"raw credential field {forbidden!r} is forbidden; "
                    "supply 'credential_ref' (environment variable name) only"
                )
        dest_id = str(dest.get("id") or f"{system}-{int(time.time())}").strip()
        clean = {
            "id": dest_id,
            "name": str(dest.get("name") or dest_id).strip(),
            "system": system,
            "endpoint": endpoint,
            "credential_ref": str(dest.get("credential_ref") or "").strip(),
            "send_mode": mode,
            "schedule": str(dest.get("schedule") or "manual").strip(),
            "enabled": bool(dest.get("enabled", True)),
            "target_view": str(dest.get("target_view") or "").strip(),
            "extra": dict(dest.get("extra") or {}),
        }
        dests = self.list_destinations()
        action = "create"
        updated: list[dict] = []
        for existing in dests:
            if existing.get("id") == dest_id:
                action = "update"
                updated.append(clean)
            else:
                updated.append(existing)
        if action == "create":
            updated.append(clean)
        self._save_all(updated)
        audit = self._append_audit(
            actor,
            action,
            dest_id,
            {
                "system": system,
                "endpoint": endpoint,
                "credential_ref": clean["credential_ref"],
                "send_mode": mode,
                "schedule": clean["schedule"],
                "enabled": clean["enabled"],
                "target_view": clean["target_view"],
            },
        )
        return clean, audit

    def delete(self, dest_id: str, *, actor: str = "operator") -> bool:
        dests = self.list_destinations()
        remaining = [d for d in dests if d.get("id") != dest_id]
        if len(remaining) == len(dests):
            return False
        self._save_all(remaining)
        self._append_audit(actor, "delete", dest_id, {"deleted": True})
        return True

    def read_audit_log(self, limit: int = 50) -> list[dict]:
        if not self.audit_path.is_file():
            return []
        lines = [
            ln for ln in self.audit_path.read_text(encoding="utf-8").splitlines() if ln.strip()
        ]
        out = []
        for ln in lines[-limit:]:
            try:
                out.append(json.loads(ln))
            except Exception:
                continue
        return list(reversed(out))


class ExportEngine:
    """Single verified export path shared by all downstream destination adapters."""

    def __init__(self, state_store: DestinationStateStore | None = None) -> None:
        self.state_store = state_store

    def export_envelope(
        self,
        envelope: dict,
        public_key,
        adapters: list[BaseDestinationAdapter],
        *,
        declared: DeclaredModel | None = None,
        now: int | None = None,
    ) -> dict:
        """Verify envelope fail-closed, then export to every enabled adapter.

        Raises VerificationError (including ExpiredGraph / BadSignature) BEFORE
        contacting any downstream system.
        """
        # 1. Fail-closed verification — expired or forged graphs never export.
        graph = verify_envelope(envelope, public_key, now=now)
        env_id = envelope_id_for(envelope, graph)
        rec_report = reconcile(graph, declared) if declared is not None else None

        all_nodes = [_node_record(n, env_id, graph.expires_at) for n in graph.nodes]
        all_edges = [_edge_record(e, env_id, graph.expires_at) for e in graph.edges]
        all_findings = _finding_records(rec_report, env_id, graph.expires_at)

        node_key_map = {n["id"]: n for n in all_nodes}
        edge_key_map = {
            f"{e['source']}|{e['target']}|{e['port']}|{e['protocol']}|{e['layer']}|{e['evidence']['flow_count']}": e
            for e in all_edges
        }
        finding_key_map = {
            f"{f['bucket']}|{f['source']}|{f['target']}": f for f in all_findings
        }

        results: list[ExportResult] = []
        for adapter in adapters:
            if not adapter.config.get("enabled", True):
                continue
            mode = str(adapter.config.get("send_mode") or "full").lower()
            if mode not in VALID_SEND_MODES:
                mode = "full"

            if mode == "findings_only":
                nodes, edges, findings = [], [], all_findings
            elif mode == "delta" and self.state_store is not None:
                prev = self.state_store.get(adapter.destination_id)
                prev_n = set(prev.get("node_keys", []))
                prev_e = set(prev.get("edge_keys", []))
                prev_f = set(prev.get("finding_keys", []))
                nodes = [v for k, v in node_key_map.items() if k not in prev_n]
                edges = [v for k, v in edge_key_map.items() if k not in prev_e]
                findings = [v for k, v in finding_key_map.items() if k not in prev_f]
            else:
                nodes, edges, findings = all_nodes, all_edges, all_findings

            bundle = ExportBundle(
                envelope_id=env_id,
                graph_id=graph.graph_id,
                sequence=graph.sequence,
                producer=graph.producer,
                issued_at=graph.issued_at,
                expires_at=graph.expires_at,
                mode=mode,
                nodes=nodes,
                edges=edges,
                findings=findings,
                reconcile_summary=rec_report["summary"] if rec_report else None,
            )

            # Per-destination failure isolation
            try:
                res = adapter.send(bundle)
            except Exception as exc:
                res = ExportResult(
                    destination_id=adapter.destination_id,
                    system=adapter.system,
                    mode=mode,
                    envelope_id=env_id,
                    expires_at=graph.expires_at,
                    ok=False,
                    error=f"{type(exc).__name__}: {exc}",
                    live=adapter._is_live,
                )

            if res.ok and self.state_store is not None:
                self.state_store.record_success(
                    adapter.destination_id,
                    envelope_id=env_id,
                    node_keys=list(node_key_map.keys()),
                    edge_keys=list(edge_key_map.keys()),
                    finding_keys=list(finding_key_map.keys()),
                )
            results.append(res)

        return {
            "ok": all(r.ok for r in results) if results else True,
            "envelope_id": env_id,
            "graph_id": graph.graph_id,
            "sequence": graph.sequence,
            "expires_at": graph.expires_at,
            "expires_utc": iso_utc(graph.expires_at),
            "results": [r.to_dict() for r in results],
        }
