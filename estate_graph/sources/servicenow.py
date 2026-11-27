"""Pure parser for ServiceNow CMDB (``cmdb_ci`` + ``cmdb_rel_ci``) -> DeclaredModel.

Read-only ingest direction: converts what the CMDB *believes* about CIs and
their dependency relationships into Manifest's ``DeclaredModel`` so network
reconciliation can diff observed reality against CMDB declarations. Every
imported node retains its ServiceNow ``sys_id`` in ``labels`` so any drift
finding can be traced directly back to the CI that caused it.
"""

from __future__ import annotations

import json

from ..model import ServiceNode
from .declared import DeclaredModel

ORIGIN = "servicenow-cmdb"


def _extract_ref(val) -> str:
    if isinstance(val, dict):
        return str(val.get("value") or val.get("display_value") or "").strip()
    return str(val or "").strip()


def parse_servicenow_cmdb(
    cis_data: str | dict | list,
    rels_data: str | dict | list | None = None,
) -> DeclaredModel:
    """Convert ServiceNow Table API ``cmdb_ci`` + ``cmdb_rel_ci`` JSON into DeclaredModel."""
    if isinstance(cis_data, str):
        cis_obj = json.loads(cis_data)
    else:
        cis_obj = cis_data
    cis = (
        cis_obj.get("result", [])
        if isinstance(cis_obj, dict)
        else (cis_obj if isinstance(cis_obj, list) else [])
    )

    if rels_data is None:
        rels = []
    else:
        rels_obj = json.loads(rels_data) if isinstance(rels_data, str) else rels_data
        rels = (
            rels_obj.get("result", [])
            if isinstance(rels_obj, dict)
            else (rels_obj if isinstance(rels_obj, list) else [])
        )

    model = DeclaredModel()
    sys_id_to_name: dict[str, str] = {}
    seen_nodes: dict[str, ServiceNode] = {}

    for ci in cis:
        if not isinstance(ci, dict):
            continue
        sys_id = str(ci.get("sys_id") or "").strip()
        name = str(ci.get("name") or "").strip()
        if not sys_id or not name:
            continue
        sys_id_to_name[sys_id] = name
        ip = str(ci.get("ip_address") or "").strip()
        if ip:
            model.ip_to_service[ip] = name
        seen_nodes[name] = ServiceNode(
            id=name,
            kind="service",
            substrate=ORIGIN,
            labels={
                "source": ORIGIN,
                "identity_sources": [ORIGIN],
                "servicenow_sys_id": sys_id,
                "sys_class_name": str(ci.get("sys_class_name") or "cmdb_ci"),
            },
        )

    for rel in rels:
        if not isinstance(rel, dict):
            continue
        parent_id = _extract_ref(rel.get("parent"))
        child_id = _extract_ref(rel.get("child"))
        src = sys_id_to_name.get(parent_id)
        dst = sys_id_to_name.get(child_id)
        if src and dst and src != dst:
            model.pairs.add((src, dst))

    model.nodes = sorted(seen_nodes.values(), key=lambda n: n.id)
    return model
