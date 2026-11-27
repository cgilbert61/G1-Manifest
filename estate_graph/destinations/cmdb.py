"""CMDB / ITSM downstream destination adapters (6 systems, pure stdlib).

Systems:
- ServiceNow CMDB (IRE / CSDM via /api/now/identifyreconcile)
- BMC Helix CMDB (/api/cmdb/v1.0/instances)
- Jira Service Management Assets (/gateway/api/jsm/assets/.../object/create)
- Ivanti Neurons for ITSM (/api/odata/businessobject/CIs)
- Device42 (/api/1.0/devices/ & /api/2.0/service_communications/)
- Freshservice (/api/v2/assets & /api/v2/relationships)
"""

from __future__ import annotations

from .core import BaseDestinationAdapter, ExportBundle


def _bearer_headers(token: str) -> dict[str, str]:
    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    return hdrs


class ServiceNowCMDBAdapter(BaseDestinationAdapter):
    """Export via ServiceNow Identification and Reconciliation Engine (IRE) mapped to CSDM."""

    system = "servicenow"
    group = "cmdb-itsm"
    default_target_view = "CMDB -> Service Graph Connector -> CSDM Services"

    def build_payloads(self, bundle: ExportBundle):
        url = self.endpoint.rstrip("/") + "/api/now/identifyreconcile"
        hdrs = _bearer_headers(self._resolve_credential())
        hdrs["X-ServiceNow-Discovery-Source"] = "G1-Manifest"

        items = []
        idx_by_id: dict[str, int] = {}
        for idx, n in enumerate(bundle.nodes):
            idx_by_id[n["id"]] = idx
            items.append(
                {
                    "className": "cmdb_ci_service_discovered"
                    if n["kind"] == "service"
                    else "cmdb_ci_endpoint",
                    "values": {
                        "name": n["id"],
                        "discovery_source": "G1-Manifest",
                        "u_g1_envelope_id": n["envelope_id"],
                        "u_g1_expires_at": n["expires_at"],
                        "u_substrate": n["substrate"],
                    },
                }
            )
        relations = []
        for e in bundle.edges:
            if e["source"] in idx_by_id and e["target"] in idx_by_id:
                relations.append(
                    {
                        "parent": idx_by_id[e["source"]],
                        "child": idx_by_id[e["target"]],
                        "type": "Depends on::Used by",
                        "u_g1_envelope_id": e["envelope_id"],
                        "u_g1_expires_at": e["expires_at"],
                        "u_flow_count": e["evidence"]["flow_count"],
                    }
                )
        body = {
            "items": items,
            "relations": relations,
            "findings": bundle.findings,
            "envelope_id": bundle.envelope_id,
            "expires_at": bundle.expires_at,
            "_record_count": len(items) + len(relations) + len(bundle.findings),
        }
        return [(url, body, hdrs)]


class BMCHelixCMDBAdapter(BaseDestinationAdapter):
    """Export CIs and relationships to BMC Helix CMDB REST API."""

    system = "bmc-helix"
    group = "cmdb-itsm"
    default_target_view = "Helix CMDB -> BMC.ASSET -> Application Services"

    def build_payloads(self, bundle: ExportBundle):
        url = self.endpoint.rstrip("/") + "/api/cmdb/v1.0/instances"
        hdrs = _bearer_headers(self._resolve_credential())
        instances = [
            {
                "class_name": "BMC_ApplicationService",
                "dataset_id": self.config.get("extra", {}).get("dataset_id", "BMC.G1.MANIFEST"),
                "attributes": {
                    "Name": n["id"],
                    "TokenId": n["id"],
                    "Description": f"envelope={n['envelope_id']} expires_at={n['expires_at']}",
                    "g1_envelope_id": n["envelope_id"],
                    "g1_expires_at": n["expires_at"],
                },
            }
            for n in bundle.nodes
        ]
        relationships = [
            {
                "class_name": "BMC_Dependency",
                "source_token_id": e["source"],
                "destination_token_id": e["target"],
                "attributes": {
                    "flow_count": e["evidence"]["flow_count"],
                    "first_seen": e["evidence"]["first_seen"],
                    "last_seen": e["evidence"]["last_seen"],
                    "g1_envelope_id": e["envelope_id"],
                    "g1_expires_at": e["expires_at"],
                },
            }
            for e in bundle.edges
        ]
        return [
            (
                url,
                {
                    "instances": instances,
                    "relationships": relationships,
                    "findings": bundle.findings,
                    "envelope_id": bundle.envelope_id,
                    "expires_at": bundle.expires_at,
                    "_record_count": len(instances) + len(relationships) + len(bundle.findings),
                },
                hdrs,
            )
        ]


class JSMAssetsAdapter(BaseDestinationAdapter):
    """Export objects and attributes to Jira Service Management Assets REST API."""

    system = "jsm-assets"
    group = "cmdb-itsm"
    default_target_view = "JSM Assets -> Object Schema -> Services & Dependencies"

    def build_payloads(self, bundle: ExportBundle):
        ws = self.config.get("extra", {}).get("workspace_id", "default")
        url = (
            self.endpoint.rstrip("/")
            + f"/gateway/api/jsm/assets/workspace/{ws}/v1/object/create"
        )
        hdrs = _bearer_headers(self._resolve_credential())
        objects = [
            {
                "objectTypeId": self.config.get("extra", {}).get("object_type_id", "1"),
                "attributes": [
                    {"objectTypeAttributeId": "Name", "objectAttributeValues": [{"value": n["id"]}]},
                    {"objectTypeAttributeId": "Kind", "objectAttributeValues": [{"value": n["kind"]}]},
                    {"objectTypeAttributeId": "EnvelopeId", "objectAttributeValues": [{"value": n["envelope_id"]}]},
                    {"objectTypeAttributeId": "ExpiresAt", "objectAttributeValues": [{"value": str(n["expires_at"])}]},
                ],
            }
            for n in bundle.nodes
        ]
        return [
            (
                url,
                {
                    "objects": objects,
                    "edges": bundle.edges,
                    "findings": bundle.findings,
                    "envelope_id": bundle.envelope_id,
                    "expires_at": bundle.expires_at,
                    "_record_count": len(objects) + len(bundle.edges) + len(bundle.findings),
                },
                hdrs,
            )
        ]


class IvantiITSMAdapter(BaseDestinationAdapter):
    """Export CIs and relationships to Ivanti Neurons for ITSM OData API."""

    system = "ivanti-itsm"
    group = "cmdb-itsm"
    default_target_view = "Ivanti Neurons -> Configuration Items -> CI#Service"

    def build_payloads(self, bundle: ExportBundle):
        url = self.endpoint.rstrip("/") + "/api/odata/businessobject/CIs"
        token = self._resolve_credential()
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
        if token:
            hdrs["Authorization"] = f"rest_api_key={token}"
        cis = [
            {
                "CIType": "Service",
                "Name": n["id"],
                "Status": "Production",
                "G1EnvelopeId": n["envelope_id"],
                "G1ExpiresAt": n["expires_at"],
            }
            for n in bundle.nodes
        ]
        return [
            (
                url,
                {
                    "value": cis,
                    "relationships": bundle.edges,
                    "findings": bundle.findings,
                    "envelope_id": bundle.envelope_id,
                    "expires_at": bundle.expires_at,
                    "_record_count": len(cis) + len(bundle.edges) + len(bundle.findings),
                },
                hdrs,
            )
        ]


class Device42Adapter(BaseDestinationAdapter):
    """Export devices, services, and dependencies to Device42 REST API."""

    system = "device42"
    group = "cmdb-itsm"
    default_target_view = "Device42 -> Applications -> Service Communications"

    def build_payloads(self, bundle: ExportBundle):
        base = self.endpoint.rstrip("/")
        hdrs = _bearer_headers(self._resolve_credential())
        reqs = []
        if bundle.nodes:
            reqs.append(
                (
                    f"{base}/api/1.0/devices/",
                    {
                        "devices": [
                            {
                                "name": n["id"],
                                "type": n["kind"],
                                "custom_fields": {
                                    "g1_envelope_id": n["envelope_id"],
                                    "g1_expires_at": n["expires_at"],
                                },
                            }
                            for n in bundle.nodes
                        ],
                        "envelope_id": bundle.envelope_id,
                        "expires_at": bundle.expires_at,
                        "_record_count": len(bundle.nodes),
                    },
                    hdrs,
                )
            )
        if bundle.edges or bundle.findings:
            reqs.append(
                (
                    f"{base}/api/2.0/service_communications/",
                    {
                        "communications": [
                            {
                                "client": e["source"],
                                "server": e["target"],
                                "port": e["port"],
                                "protocol": e["protocol"],
                                "flow_count": e["evidence"]["flow_count"],
                                "envelope_id": e["envelope_id"],
                                "expires_at": e["expires_at"],
                            }
                            for e in bundle.edges
                        ],
                        "findings": bundle.findings,
                        "envelope_id": bundle.envelope_id,
                        "expires_at": bundle.expires_at,
                        "_record_count": len(bundle.edges) + len(bundle.findings),
                    },
                    hdrs,
                )
            )
        return reqs


class FreshserviceAdapter(BaseDestinationAdapter):
    """Export assets and relationships to Freshservice v2 REST API."""

    system = "freshservice"
    group = "cmdb-itsm"
    default_target_view = "Freshservice -> Assets -> CMDB & Relationships"

    def build_payloads(self, bundle: ExportBundle):
        base = self.endpoint.rstrip("/")
        hdrs = _bearer_headers(self._resolve_credential())
        reqs = []
        if bundle.nodes:
            reqs.append(
                (
                    f"{base}/api/v2/assets",
                    {
                        "assets": [
                            {
                                "name": n["id"],
                                "asset_type_id": 1,
                                "type_fields": {
                                    "g1_envelope_id": n["envelope_id"],
                                    "g1_expires_at": n["expires_at"],
                                },
                            }
                            for n in bundle.nodes
                        ],
                        "envelope_id": bundle.envelope_id,
                        "expires_at": bundle.expires_at,
                        "_record_count": len(bundle.nodes),
                    },
                    hdrs,
                )
            )
        if bundle.edges or bundle.findings:
            reqs.append(
                (
                    f"{base}/api/v2/relationships",
                    {
                        "relationships": [
                            {
                                "primary_id": e["source"],
                                "secondary_id": e["target"],
                                "relationship_type": "Depends On",
                                "envelope_id": e["envelope_id"],
                                "expires_at": e["expires_at"],
                            }
                            for e in bundle.edges
                        ],
                        "findings": bundle.findings,
                        "envelope_id": bundle.envelope_id,
                        "expires_at": bundle.expires_at,
                        "_record_count": len(bundle.edges) + len(bundle.findings),
                    },
                    hdrs,
                )
            )
        return reqs
