"""Graph & catalog downstream destination adapters (3 systems, pure stdlib).

Systems:
- Neo4j (Cypher HTTP Transactional API /db/neo4j/tx/commit; preserves all evidence properties)
- Backstage service catalog (backstage.io/v1alpha1 Component/Resource entities + dependsOn)
- Generic REST / webhook (full graph, delta, or findings JSON)
"""

from __future__ import annotations

import base64

from .core import BaseDestinationAdapter, ExportBundle


class Neo4jAdapter(BaseDestinationAdapter):
    """Export nodes, edges, and findings to Neo4j via parameterized Cypher statements."""

    system = "neo4j"
    group = "graph-and-catalog"
    default_target_view = "Neo4j Browser -> MATCH (n:G1Node)-[r:G1_DEPENDS_ON]->(m) RETURN n,r,m"

    def build_payloads(self, bundle: ExportBundle):
        db = self.config.get("extra", {}).get("database", "neo4j")
        url = self.endpoint.rstrip("/") + f"/db/{db}/tx/commit"
        cred = self._resolve_credential()
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if cred:
            if ":" in cred:
                b64 = base64.b64encode(cred.encode("utf-8")).decode("ascii")
                hdrs["Authorization"] = f"Basic {b64}"
            else:
                hdrs["Authorization"] = f"Bearer {cred}"

        statements = []
        if bundle.nodes:
            statements.append(
                {
                    "statement": (
                        "UNWIND $nodes AS n "
                        "MERGE (x:G1Node {id: n.id}) "
                        "SET x.kind = n.kind, x.substrate = n.substrate, "
                        "x.envelope_id = n.envelope_id, x.expires_at = n.expires_at"
                    ),
                    "parameters": {"nodes": bundle.nodes},
                }
            )
        if bundle.edges:
            edge_params = [
                {
                    "source": e["source"],
                    "target": e["target"],
                    "port": e["port"] if e["port"] is not None else -1,
                    "protocol": e["protocol"] or "",
                    "layer": e["layer"],
                    "flow_count": e["evidence"]["flow_count"],
                    "first_seen": e["evidence"]["first_seen"],
                    "last_seen": e["evidence"]["last_seen"],
                    "sources": e["evidence"]["sources"],
                    "low_frequency": e["low_frequency"],
                    "envelope_id": e["envelope_id"],
                    "expires_at": e["expires_at"],
                }
                for e in bundle.edges
            ]
            statements.append(
                {
                    "statement": (
                        "UNWIND $edges AS e "
                        "MERGE (s:G1Node {id: e.source}) "
                        "MERGE (t:G1Node {id: e.target}) "
                        "MERGE (s)-[r:G1_DEPENDS_ON {layer: e.layer, port: e.port, protocol: e.protocol}]->(t) "
                        "SET r.flow_count = e.flow_count, r.first_seen = e.first_seen, "
                        "r.last_seen = e.last_seen, r.sources = e.sources, "
                        "r.low_frequency = e.low_frequency, "
                        "r.envelope_id = e.envelope_id, r.expires_at = e.expires_at"
                    ),
                    "parameters": {"edges": edge_params},
                }
            )
        if bundle.findings:
            statements.append(
                {
                    "statement": (
                        "UNWIND $findings AS f "
                        "MERGE (x:G1Finding {bucket: f.bucket, source: f.source, target: f.target}) "
                        "SET x.severity = f.severity, x.envelope_id = f.envelope_id, "
                        "x.expires_at = f.expires_at"
                    ),
                    "parameters": {"findings": bundle.findings},
                }
            )
        return [
            (
                url,
                {
                    "statements": statements,
                    "envelope_id": bundle.envelope_id,
                    "expires_at": bundle.expires_at,
                    "_record_count": len(bundle.nodes) + len(bundle.edges) + len(bundle.findings),
                },
                hdrs,
            )
        ]


class BackstageAdapter(BaseDestinationAdapter):
    """Export Backstage Service Catalog entities (backstage.io/v1alpha1)."""

    system = "backstage"
    group = "graph-and-catalog"
    default_target_view = "Backstage -> Software Catalog -> Components & Relations"

    def build_payloads(self, bundle: ExportBundle):
        url = self.endpoint.rstrip("/") + "/api/catalog/entities/g1-manifest"
        token = self._resolve_credential()
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            hdrs["Authorization"] = f"Bearer {token}"

        deps_by_src: dict[str, list[str]] = {}
        for e in bundle.edges:
            if e["layer"] == "network":
                deps_by_src.setdefault(e["source"], []).append(
                    f"component:default/{e['target']}"
                )

        entities = []
        for n in bundle.nodes:
            kind = "Component" if n["kind"] == "service" else "Resource"
            entities.append(
                {
                    "apiVersion": "backstage.io/v1alpha1",
                    "kind": kind,
                    "metadata": {
                        "name": n["id"].replace(":", "-").replace("/", "-"),
                        "title": n["id"],
                        "annotations": {
                            "g1163rt.ai/envelope-id": n["envelope_id"],
                            "g1163rt.ai/expires-at": str(n["expires_at"]),
                            "g1163rt.ai/substrate": n["substrate"],
                        },
                    },
                    "spec": {
                        "type": n["kind"],
                        "lifecycle": "production",
                        "owner": "g1-manifest",
                        "dependsOn": sorted(set(deps_by_src.get(n["id"], []))),
                    },
                }
            )
        return [
            (
                url,
                {
                    "entities": entities,
                    "findings": bundle.findings,
                    "envelope_id": bundle.envelope_id,
                    "expires_at": bundle.expires_at,
                    "_record_count": len(entities) + len(bundle.findings),
                },
                hdrs,
            )
        ]


class GenericWebhookAdapter(BaseDestinationAdapter):
    """Export full graph, delta, or findings JSON to any configured REST/webhook endpoint."""

    system = "webhook"
    group = "graph-and-catalog"
    default_target_view = "Custom REST / Webhook Receiver"

    def build_payloads(self, bundle: ExportBundle):
        token = self._resolve_credential()
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        payload = bundle.to_dict()
        payload["_record_count"] = (
            len(bundle.nodes) + len(bundle.edges) + len(bundle.findings)
        )
        return [(self.endpoint, payload, hdrs)]
