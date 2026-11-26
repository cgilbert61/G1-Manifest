"""Verify a running G1-Manifest Docker stack (including MFA Login Portal) over HTTP."""

from __future__ import annotations

import http.cookiejar
import json
import sys
import urllib.request

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8088"


def main() -> int:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def get(path: str) -> bytes:
        url = BASE_URL.rstrip("/") + path
        with opener.open(url, timeout=5) as resp:
            assert resp.status == 200, f"{url} returned {resp.status}"
            return resp.read()

    health = json.loads(get("/health"))
    assert health.get("status") == "ok", f"unhealthy: {health}"

    portal = get("/").decode("utf-8")
    assert "G1-MANIFEST" in portal or "G1-Manifest" in portal
    assert "G1163RT Security Labs" in portal

    # Authenticate via PBKDF2 + TOTP demo account if MFA gate is active
    auth_status = json.loads(get("/api/auth/status"))
    if not auth_status.get("authenticated"):
        login_req = urllib.request.Request(
            BASE_URL.rstrip("/") + "/api/auth/login",
            data=json.dumps(
                {
                    "email": "ops@g1163rt.ai",
                    "password": "G1ManifestDemo2026!",
                    "mfa_code": "482910",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with opener.open(login_req, timeout=5) as resp:
            login_res = json.loads(resp.read())
            assert login_res.get("authenticated") is True

    dashboard = get("/").decode("utf-8")
    assert "Available Witness Pages" in dashboard
    demo = get("/demo_view.html").decode("utf-8")
    assert "VERIFIED" in demo
    pub = get("/api/keys/public.pem").decode("utf-8")
    assert "BEGIN PUBLIC KEY" in pub
    print(f"OK: G1-Manifest Docker stack & MFA Login verified at {BASE_URL} (views={health['views']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
