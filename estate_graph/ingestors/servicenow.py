"""Read-only ServiceNow CMDB Table API collector (stdlib only).

Reads ``/api/now/table/cmdb_ci`` and ``/api/now/table/cmdb_rel_ci`` using
read-only credentials from environment variables. Never writes back to
ServiceNow.
"""

from __future__ import annotations

import base64
import os
import urllib.request

from ..sources.declared import DeclaredModel
from ..sources.servicenow import ORIGIN, parse_servicenow_cmdb


def _default_get(url: str, headers: dict[str, str], timeout: float = 15.0) -> str:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


class ServiceNowCMDBCollector:
    """Read-only collector pulling DeclaredModel from ServiceNow Table API."""

    origin = ORIGIN

    def __init__(
        self,
        instance_url: str,
        *,
        user_env: str = "SERVICENOW_USER",
        password_env: str = "SERVICENOW_PASSWORD",
        token_env: str = "SERVICENOW_BEARER_TOKEN",
        ci_query: str = "install_status=1",
        http_get=None,
    ) -> None:
        self.instance_url = instance_url.rstrip("/")
        self.user_env = user_env
        self.password_env = password_env
        self.token_env = token_env
        self.ci_query = ci_query
        self._http_get = http_get or _default_get

    def _headers(self) -> dict[str, str]:
        hdrs = {"Accept": "application/json"}
        token = os.environ.get(self.token_env, "").strip()
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
            return hdrs
        user = os.environ.get(self.user_env, "").strip()
        pwd = os.environ.get(self.password_env, "").strip()
        if user and pwd:
            creds = base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")
            hdrs["Authorization"] = f"Basic {creds}"
        return hdrs

    def load_declared(self) -> DeclaredModel:
        hdrs = self._headers()
        cis_url = (
            f"{self.instance_url}/api/now/table/cmdb_ci"
            f"?sysparm_fields=sys_id,name,ip_address,sys_class_name"
            f"&sysparm_query={self.ci_query}"
        )
        rels_url = (
            f"{self.instance_url}/api/now/table/cmdb_rel_ci"
            "?sysparm_fields=parent,child,type"
        )
        cis_raw = self._http_get(cis_url, hdrs)
        rels_raw = self._http_get(rels_url, hdrs)
        return parse_servicenow_cmdb(cis_raw, rels_raw)
