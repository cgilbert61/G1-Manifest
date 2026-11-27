"""Network & observability map downstream destination adapters (4 systems, stdlib).

Systems:
- Cisco Catalyst Center (/dna/intent/api/v1/topology/custom-topology)
- Datadog (/api/v2/services/definitions & /api/v1/events)
- Dynatrace (/api/v2/entities/custom & /api/v2/events/ingest)
- SolarWinds NPM (/SolarWinds/InformationService/v3/Json/Invoke/...)
"""

from __future__ import annotations

from .core import BaseDestinationAdapter, ExportBundle


class CiscoCatalystAdapter(BaseDestinationAdapter):
    """Export topology and device relationships to Cisco Catalyst Center."""

    system = "cisco-catalyst"
    group = "network-observability"
    default_target_view = "Cisco Catalyst Center -> Topology -> Custom Dependencies"

    def build_payloads(self, bundle: ExportBundle):
        url = self.endpoint.rstrip("/") + "/dna/intent/api/v1/topology/custom-topology"
        token = self._resolve_credential()
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            hdrs["X-Auth-Token"] = token
        return [
            (
                url,
                {
                    "response": {
                        "nodes": [
                            {
                                "id": n["id"],
                                "nodeType": n["kind"],
                                "envelope_id": n["envelope_id"],
                                "expires_at": n["expires_at"],
                            }
                            for n in bundle.nodes
                        ],
                        "links": [
                            {
                                "source": e["source"],
                                "target": e["target"],
                                "port": e["port"],
                                "protocol": e["protocol"],
                                "flow_count": e["evidence"]["flow_count"],
                                "envelope_id": e["envelope_id"],
                                "expires_at": e["expires_at"],
                            }
                            for e in bundle.edges
                        ],
                    },
                    "findings": bundle.findings,
                    "envelope_id": bundle.envelope_id,
                    "expires_at": bundle.expires_at,
                    "_record_count": len(bundle.nodes) + len(bundle.edges) + len(bundle.findings),
                },
                hdrs,
            )
        ]


class DatadogAdapter(BaseDestinationAdapter):
    """Export service definitions and reconciliation findings to Datadog API."""

    system = "datadog"
    group = "network-observability"
    default_target_view = "Datadog -> Service Catalog & Events Explorer"

    def build_payloads(self, bundle: ExportBundle):
        base = self.endpoint.rstrip("/")
        api_key = self._resolve_credential()
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if api_key:
            hdrs["DD-API-KEY"] = api_key
        reqs = []
        if bundle.nodes or bundle.edges:
            deps_by_src: dict[str, list[str]] = {}
            for e in bundle.edges:
                deps_by_src.setdefault(e["source"], []).append(e["target"])
            defs = [
                {
                    "schema-version": "v2.2",
                    "dd-service": n["id"],
                    "tags": [
                        f"g1_envelope_id:{n['envelope_id']}",
                        f"g1_expires_at:{n['expires_at']}",
                        f"substrate:{n['substrate']}",
                    ],
                    "extensions": {
                        "g1.manifest": {
                            "envelope_id": n["envelope_id"],
                            "expires_at": n["expires_at"],
                            "depends_on": sorted(set(deps_by_src.get(n["id"], []))),
                        }
                    },
                }
                for n in bundle.nodes
            ]
            reqs.append(
                (
                    f"{base}/api/v2/services/definitions",
                    {
                        "services": defs,
                        "envelope_id": bundle.envelope_id,
                        "expires_at": bundle.expires_at,
                        "_record_count": len(defs),
                    },
                    hdrs,
                )
            )
        if bundle.findings:
            events = [
                {
                    "title": f"G1-Manifest [{f['bucket']}]: {f['source']} -> {f['target']}",
                    "text": f"Envelope {f['envelope_id']} (expires {f['expires_at']})",
                    "alert_type": "error" if f.get("severity") == "high" else "warning",
                    "tags": [
                        f"g1_envelope_id:{f['envelope_id']}",
                        f"g1_expires_at:{f['expires_at']}",
                        f"bucket:{f['bucket']}",
                    ],
                }
                for f in bundle.findings
            ]
            reqs.append(
                (
                    f"{base}/api/v1/events",
                    {
                        "events": events,
                        "envelope_id": bundle.envelope_id,
                        "expires_at": bundle.expires_at,
                        "_record_count": len(events),
                    },
                    hdrs,
                )
            )
        return reqs


class DynatraceAdapter(BaseDestinationAdapter):
    """Export custom entities, relationships, and findings to Dynatrace API v2."""

    system = "dynatrace"
    group = "network-observability"
    default_target_view = "Dynatrace -> Smartscape / Custom Topology & Events"

    def build_payloads(self, bundle: ExportBundle):
        base = self.endpoint.rstrip("/")
        token = self._resolve_credential()
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            hdrs["Authorization"] = f"Api-Token {token}"
        reqs = []
        if bundle.nodes or bundle.edges:
            reqs.append(
                (
                    f"{base}/api/v2/entities/custom",
                    {
                        "entities": [
                            {
                                "entityId": f"G1_SERVICE-{n['id']}",
                                "displayName": n["id"],
                                "properties": {
                                    "kind": n["kind"],
                                    "substrate": n["substrate"],
                                    "g1_envelope_id": n["envelope_id"],
                                    "g1_expires_at": n["expires_at"],
                                },
                            }
                            for n in bundle.nodes
                        ],
                        "relationships": [
                            {
                                "from": f"G1_SERVICE-{e['source']}",
                                "to": f"G1_SERVICE-{e['target']}",
                                "type": "CALLS",
                                "evidence": e["evidence"],
                                "g1_envelope_id": e["envelope_id"],
                                "g1_expires_at": e["expires_at"],
                            }
                            for e in bundle.edges
                        ],
                        "envelope_id": bundle.envelope_id,
                        "expires_at": bundle.expires_at,
                        "_record_count": len(bundle.nodes) + len(bundle.edges),
                    },
                    hdrs,
                )
            )
        if bundle.findings:
            reqs.append(
                (
                    f"{base}/api/v2/events/ingest",
                    {
                        "eventType": "CUSTOM_ALERT",
                        "title": f"G1-Manifest Reconciliation Findings ({bundle.envelope_id})",
                        "properties": {
                            "g1_envelope_id": bundle.envelope_id,
                            "g1_expires_at": str(bundle.expires_at),
                        },
                        "envelope_id": bundle.envelope_id,
                        "expires_at": bundle.expires_at,
                        "findings": bundle.findings,
                        "_record_count": len(bundle.findings),
                    },
                    hdrs,
                )
            )
        return reqs


class SolarWindsNPMAdapter(BaseDestinationAdapter):
    """Export nodes, topology, and findings to SolarWinds Orion / NPM SWIS REST API."""

    system = "solarwinds-npm"
    group = "network-observability"
    default_target_view = "SolarWinds NPM -> Orion Maps -> G1-Manifest Topology"

    def build_payloads(self, bundle: ExportBundle):
        url = (
            self.endpoint.rstrip("/")
            + "/SolarWinds/InformationService/v3/Json/Invoke/Orion.Topology/ImportManifest"
        )
        token = self._resolve_credential()
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        return [
            (
                url,
                {
                    "Nodes": [
                        {
                            "Caption": n["id"],
                            "Kind": n["kind"],
                            "G1EnvelopeId": n["envelope_id"],
                            "G1ExpiresAt": n["expires_at"],
                        }
                        for n in bundle.nodes
                    ],
                    "Connections": [
                        {
                            "SrcNode": e["source"],
                            "DestNode": e["target"],
                            "Port": e["port"],
                            "Protocol": e["protocol"],
                            "FlowCount": e["evidence"]["flow_count"],
                            "G1EnvelopeId": e["envelope_id"],
                            "G1ExpiresAt": e["expires_at"],
                        }
                        for e in bundle.edges
                    ],
                    "Findings": bundle.findings,
                    "envelope_id": bundle.envelope_id,
                    "expires_at": bundle.expires_at,
                    "_record_count": len(bundle.nodes) + len(bundle.edges) + len(bundle.findings),
                },
                hdrs,
            )
        ]
