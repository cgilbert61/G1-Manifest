"""Adapter registry for all 13 G1-Manifest downstream destinations."""

from __future__ import annotations

from .cmdb import (
    BMCHelixCMDBAdapter,
    Device42Adapter,
    FreshserviceAdapter,
    IvantiITSMAdapter,
    JSMAssetsAdapter,
    ServiceNowCMDBAdapter,
)
from .core import BaseDestinationAdapter
from .graph_catalog import BackstageAdapter, GenericWebhookAdapter, Neo4jAdapter
from .observability import (
    CiscoCatalystAdapter,
    DatadogAdapter,
    DynatraceAdapter,
    SolarWindsNPMAdapter,
)

ADAPTER_CLASSES: dict[str, type[BaseDestinationAdapter]] = {
    "servicenow": ServiceNowCMDBAdapter,
    "bmc-helix": BMCHelixCMDBAdapter,
    "jsm-assets": JSMAssetsAdapter,
    "ivanti-itsm": IvantiITSMAdapter,
    "device42": Device42Adapter,
    "freshservice": FreshserviceAdapter,
    "cisco-catalyst": CiscoCatalystAdapter,
    "datadog": DatadogAdapter,
    "dynatrace": DynatraceAdapter,
    "solarwinds-npm": SolarWindsNPMAdapter,
    "neo4j": Neo4jAdapter,
    "backstage": BackstageAdapter,
    "webhook": GenericWebhookAdapter,
}

SUPPORTED_SYSTEMS: dict[str, dict] = {
    key: {
        "system": key,
        "group": cls.group,
        "default_target_view": cls.default_target_view,
    }
    for key, cls in ADAPTER_CLASSES.items()
}


def create_adapter(config: dict, *, http_send=None) -> BaseDestinationAdapter:
    system = str(config.get("system") or "").strip().lower()
    cls = ADAPTER_CLASSES.get(system)
    if cls is None:
        raise ValueError(f"unsupported downstream system: {system!r}")
    return cls(config, http_send=http_send)
