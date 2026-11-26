"""Importer for a declared estate model, in Warrant's shape.

The declared model is what a human (or an estate loader transcribing one)
says the dependencies are: a list of services, each with ``service_id`` and
``allowed_egress_services``. This is the *claim*. Everything else in this
package exists to check the claim against evidence.

Accepted input: either a bare list of service objects, or an object with
``services`` plus an optional top-level ``endpoints`` map (ip -> service_id).
A service may also carry ``addresses``/``ips`` (merged into the ip map) and
``substrate``/``kind``/``labels`` metadata for its node.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..model import ServiceNode


@dataclass
class DeclaredModel:
    nodes: list[ServiceNode] = field(default_factory=list)
    # Declared egress as (source, target) pairs — Warrant's lists carry no
    # ports, so reconciliation compares at pair level (see reconcile.py).
    pairs: set[tuple[str, str]] = field(default_factory=set)
    ip_to_service: dict[str, str] = field(default_factory=dict)

    def targets_of(self, service_id: str) -> set[str]:
        return {t for (s, t) in self.pairs if s == service_id}


def parse_declared(data) -> DeclaredModel:
    if isinstance(data, list):
        services, endpoints = data, {}
    else:
        services = data.get("services", [])
        endpoints = data.get("endpoints", {}) or {}
    model = DeclaredModel()
    model.ip_to_service.update(endpoints)
    for svc in services:
        sid = svc["service_id"]
        model.nodes.append(
            ServiceNode(
                id=sid,
                kind=svc.get("kind", "service"),
                substrate=svc.get("substrate", "declared"),
                labels=dict(svc.get("labels", {})),
            )
        )
        for ip in svc.get("addresses", []) + svc.get("ips", []):
            model.ip_to_service[ip] = sid
        for peer in svc.get("allowed_egress_services", []):
            target = peer["service_id"] if isinstance(peer, dict) else peer
            if target != sid:
                model.pairs.add((sid, target))
    return model


def load_declared(path: str) -> DeclaredModel:
    with open(path, encoding="utf-8") as fh:
        return parse_declared(json.load(fh))
