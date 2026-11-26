"""Verify a running G1-Manifest Docker stack over HTTP."""

from __future__ import annotations

import json
import sys
import urllib.request

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8088"


def check(path: str) -> bytes:
    url = BASE_URL.rstrip("/") + path
    with urllib.request.urlopen(url, timeout=5) as resp:
        assert resp.status == 200, f"{url} returned {resp.status}"
        return resp.read()


def main() -> int:
    health = json.loads(check("/health"))
    assert health.get("status") == "ok", f"unhealthy: {health}"
    index = check("/").decode("utf-8")
    assert "G1-Manifest" in index and "G1163RT Security Labs" in index
    demo = check("/demo_view.html").decode("utf-8")
    assert "VERIFIED" in demo
    pub = check("/api/keys/public.pem").decode("utf-8")
    assert "BEGIN PUBLIC KEY" in pub
    print(f"OK: G1-Manifest Docker stack verified at {BASE_URL} (views={health['views']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
